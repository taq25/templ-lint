// Package lint は a-h/templ の .templ ファイルを parser/v2 で直接解析し、
// htmx / Alpine.js 利用時に XSS へつながる危険な記述を検出する。
//
// 背景: templ は属性値を HTML エスケープするが、Alpine の x-init / @click や
// htmx の hx-on:* は属性値の文字列をそのまま JavaScript として評価するため、
// 動的な値を渡すとエスケープでは XSS を防げない。
package lint

import (
	"cmp"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	parser "github.com/a-h/templ/parser/v2"
	"github.com/a-h/templ/parser/v2/visitor"
	"github.com/m-mizutani/goerr/v2"
)

// Linter は .templ ファイルの検査器。
type Linter struct {
	// AllowedSanitizers は templ.Raw 等の引数として許可するサニタイズ関数
	// ("pkg.Func" 形式、例: "sanitize.HTML")。
	// bluemonday.XxxPolicy().Sanitize(x) チェーンは常に許可される。
	AllowedSanitizers []string
}

// LintPaths はファイルまたはディレクトリ (再帰的に *.templ を収集) を検査する。
func (l *Linter) LintPaths(paths []string) ([]Finding, error) {
	files, err := collectTemplFiles(paths)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, f := range files {
		fs, err := l.LintFile(f)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fs...)
	}
	slices.SortFunc(findings, func(a, b Finding) int {
		if c := cmp.Compare(a.File, b.File); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Line, b.Line); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Col, b.Col); c != 0 {
			return c
		}
		return cmp.Compare(a.Rule, b.Rule)
	})
	return findings, nil
}

// LintFile は 1 つの .templ ファイルを検査する。
func (l *Linter) LintFile(path string) ([]Finding, error) {
	tf, err := parser.Parse(path)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to parse templ file", goerr.V("path", path))
	}
	var findings []Finding

	v := visitor.New()

	// 動的な属性値: <div x-init={ expr }> など
	prevExprAttr := v.ExpressionAttribute
	v.ExpressionAttribute = func(n *parser.ExpressionAttribute) error {
		l.checkAttribute(path, n, &findings)
		return prevExprAttr(n)
	}

	// 動的な属性名: <div { name }={ value }> は名前ごと攻撃者が選べる
	prevBoolExprAttr := v.BoolExpressionAttribute
	v.BoolExpressionAttribute = func(n *parser.BoolExpressionAttribute) error {
		if _, ok := n.Key.(parser.ExpressionAttributeKey); ok {
			findings = append(findings, Finding{
				File: path, Line: n.Range.From.Line + 1, Col: n.Range.From.Col + 1,
				Rule: RuleDynAttrName, Severity: SeverityError,
				Message: "dynamic attribute name: an attacker-controlled name can become an event handler or Alpine directive",
			})
		}
		return prevBoolExprAttr(n)
	}

	// スプレッド属性: <div { attrs... }> は属性名も値も動的
	prevSpread := v.SpreadAttributes
	v.SpreadAttributes = func(n *parser.SpreadAttributes) error {
		findings = append(findings, Finding{
			File: path, Line: n.Expression.Range.From.Line + 1, Col: n.Expression.Range.From.Col + 1,
			Rule: RuleSpreadAttr, Severity: SeverityWarning,
			Message: "spread attributes: attribute names are dynamic; ensure the map cannot contain event/Alpine/htmx attributes",
		})
		return prevSpread(n)
	}

	// .templ 内の Go 式/コード片に含まれる templ.Raw 等
	prevTemplElem := v.TemplElementExpression
	v.TemplElementExpression = func(n *parser.TemplElementExpression) error {
		l.checkGoSnippet(path, n.Expression, &findings)
		return prevTemplElem(n)
	}
	prevCallTempl := v.CallTemplateExpression
	v.CallTemplateExpression = func(n *parser.CallTemplateExpression) error {
		l.checkGoSnippet(path, n.Expression, &findings)
		return prevCallTempl(n)
	}
	prevGoCode := v.GoCode
	v.GoCode = func(n *parser.GoCode) error {
		l.checkGoSnippet(path, n.Expression, &findings)
		return prevGoCode(n)
	}
	prevStringExpr := v.StringExpression
	v.StringExpression = func(n *parser.StringExpression) error {
		l.checkGoSnippet(path, n.Expression, &findings)
		return prevStringExpr(n)
	}

	if err := tf.Visit(v); err != nil {
		return nil, goerr.Wrap(err, "failed to visit templ AST", goerr.V("path", path))
	}
	return findings, nil
}

func (l *Linter) checkAttribute(path string, n *parser.ExpressionAttribute, findings *[]Finding) {
	// 属性名が動的 ({ name }={ value }) な場合は名前ごと危険
	if _, ok := n.Key.(parser.ExpressionAttributeKey); ok {
		*findings = append(*findings, Finding{
			File: path, Line: n.Range.From.Line + 1, Col: n.Range.From.Col + 1,
			Rule: RuleDynAttrName, Severity: SeverityError,
			Message: "dynamic attribute name: an attacker-controlled name can become an event handler or Alpine directive",
		})
		return
	}
	name := n.Key.String()
	switch {
	case jsEvalAttrPattern.MatchString(name):
		*findings = append(*findings, Finding{
			File: path, Line: n.Range.From.Line + 1, Col: n.Range.From.Col + 1,
			Rule: RuleJSEvalAttr, Severity: SeverityError,
			Message: fmt.Sprintf(
				"dynamic value in %q: Alpine.js/htmx evaluate this attribute as JavaScript, so HTML escaping does not prevent XSS; use a static expression, or pass data via templ.JSONString into a data-* attribute",
				name),
		})
	case urlAttrPattern.MatchString(name):
		*findings = append(*findings, Finding{
			File: path, Line: n.Range.From.Line + 1, Col: n.Range.From.Col + 1,
			Rule: RuleURLAttr, Severity: SeverityWarning,
			Message: fmt.Sprintf(
				"dynamic URL in %q: htmx will send a request to this URL; validate it against an allowlist server-side",
				name),
		})
	}
	// 属性値の Go 式内の templ.SafeURL(x) 等も検査する
	l.checkGoSnippet(path, n.Expression, findings)
}

func collectTemplFiles(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		matches, err := filepath.Glob(p)
		if err != nil || len(matches) == 0 {
			matches = []string{p}
		}
		for _, m := range matches {
			if err := filepath.WalkDir(m, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return goerr.Wrap(err, "failed to walk directory", goerr.V("path", path))
				}
				if !d.IsDir() && strings.HasSuffix(path, ".templ") {
					files = append(files, path)
				}
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}
	if len(files) == 0 {
		return nil, goerr.New("no .templ files found", goerr.V("paths", paths))
	}
	return files, nil
}
