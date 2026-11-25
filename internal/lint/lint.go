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
	// HTMXPrefixes は hx- と同じ意味を持つ追加の属性接頭辞 (htmx.config.prefix)。
	// "data-hx-" は常に有効。
	HTMXPrefixes []string
	// AlpinePrefixes は x- と同じ意味を持つ追加の属性接頭辞 (Alpine.prefix)。
	AlpinePrefixes []string
	// HTMXVersion は対象の htmx のメジャーバージョン (2 または 4)。0 なら未指定で、
	// バージョンによって意味が変わる検査 (hx-disable / hx-ignore, hx-confirm) は
	// 安全側に倒すか行わない。
	HTMXVersion int
	// CSP は前提とする Content-Security-Policy。CSPStrict ("strict") なら、script-src に
	// 'unsafe-inline' も 'unsafe-eval' も付けない CSP の下で動かない書き方を警告する。
	// セキュリティの検査は CSP の有無で変えない。
	CSP string
}

func (l *Linter) normalizer() AttrNormalizer {
	return AttrNormalizer{HTMXPrefixes: l.HTMXPrefixes, AlpinePrefixes: l.AlpinePrefixes}
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
	var ignores []*ignoreDirective
	tn := collectTemplNames(tf)

	// 属性の検査には要素名が要る (templ が URL をサニタイズするかは要素と属性の組で決まる)。
	// visitor は要素の属性を子要素より先に訪れるので、要素に入った時点の名前を覚えておけば
	// その要素の属性 (条件付き属性の中身を含む) を訪れる間は正しい要素名になる。
	var element string

	v := visitor.New()

	// 抑制ディレクティブ: // templ-lint:ignore <rule> <理由> または <!-- 同 -->
	// コメントと同じ行、およびその直後の行の該当ルールを抑制する。
	prevGoComment := v.GoComment
	v.GoComment = func(n *parser.GoComment) error {
		collectIgnore(path, n.Contents, n.Range, &ignores, &findings)
		return prevGoComment(n)
	}
	prevHTMLComment := v.HTMLComment
	v.HTMLComment = func(n *parser.HTMLComment) error {
		collectIgnore(path, n.Contents, n.Range, &ignores, &findings)
		return prevHTMLComment(n)
	}

	// 要素レベルの規則: reverse tabnabbing, SRI 欠如
	prevElement := v.Element
	v.Element = func(n *parser.Element) error {
		element = strings.ToLower(n.Name)
		l.checkElement(path, n, &findings)
		l.checkHTMXElement(path, tn, n, &findings)
		l.checkCSPElement(path, tn, n.Attributes, &findings)
		return prevElement(n)
	}
	prevScriptElement := v.ScriptElement
	v.ScriptElement = func(n *parser.ScriptElement) error {
		element = "script"
		l.checkScript(path, n, &findings)
		l.checkCSPElement(path, tn, n.Attributes, &findings)
		l.checkCSPScript(path, n, &findings)
		return prevScriptElement(n)
	}
	prevRawElement := v.RawElement
	v.RawElement = func(n *parser.RawElement) error {
		element = strings.ToLower(n.Name)
		l.checkCSPElement(path, tn, n.Attributes, &findings)
		return prevRawElement(n)
	}

	// 動的な属性値: <div x-init={ expr }> など
	prevExprAttr := v.ExpressionAttribute
	v.ExpressionAttribute = func(n *parser.ExpressionAttribute) error {
		l.checkAttribute(path, element, tn, n, &findings)
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
		l.checkGoSnippet(path, tn, n.Expression, &findings)
		return prevTemplElem(n)
	}
	prevCallTempl := v.CallTemplateExpression
	v.CallTemplateExpression = func(n *parser.CallTemplateExpression) error {
		l.checkGoSnippet(path, tn, n.Expression, &findings)
		return prevCallTempl(n)
	}
	prevGoCode := v.GoCode
	v.GoCode = func(n *parser.GoCode) error {
		l.checkGoSnippet(path, tn, n.Expression, &findings)
		return prevGoCode(n)
	}
	prevStringExpr := v.StringExpression
	v.StringExpression = func(n *parser.StringExpression) error {
		l.checkGoSnippet(path, tn, n.Expression, &findings)
		return prevStringExpr(n)
	}

	// テンプレートの外に書いた Go コード (ヘルパー関数など) の templ.Raw 等
	prevGoExpr := v.TemplateFileGoExpression
	v.TemplateFileGoExpression = func(n *parser.TemplateFileGoExpression) error {
		l.checkGoSnippet(path, tn, n.Expression, &findings)
		return prevGoExpr(n)
	}

	if err := tf.Visit(v); err != nil {
		return nil, goerr.Wrap(err, "failed to visit templ AST", goerr.V("path", path))
	}
	return l.applyIgnores(path, findings, ignores), nil
}

// ignoreDirective は理由付き抑制コメント 1 件。
// fromLine〜toLine (コメント自身) と toLine+1 (直後の行) の検出を抑制する。
type ignoreDirective struct {
	fromLine uint32 // 1 始まり
	toLine   uint32
	col      uint32
	rules    []string        // 書かれた順 (未使用の報告を安定させるため)
	used     map[string]bool // 実際に検出を抑制したルール
}

func collectIgnore(path, contents string, r parser.Range, ignores *[]*ignoreDirective, findings *[]Finding) {
	collectIgnoreAt(path, contents, r.From.Line+1, r.To.Line+1, r.From.Col+1, ignores, findings)
}

// collectIgnoreAt は 1 始まりの行・列で抑制ディレクティブを登録する。
func collectIgnoreAt(path, contents string, fromLine, toLine, col uint32, ignores *[]*ignoreDirective, findings *[]Finding) {
	m := ignoreDirectivePattern.FindStringSubmatch(contents)
	if m == nil {
		return
	}
	add := func(msg string) {
		*findings = append(*findings, Finding{
			File: path, Line: fromLine, Col: col,
			Rule: RuleInvalidIgnore, Severity: SeverityWarning, Message: msg,
		})
	}
	reason := strings.TrimSpace(m[2])
	if reason == "" {
		// 理由のない抑制は無効化し、それ自体を報告する
		add("templ-lint:ignore requires a reason (templ-lint:ignore <rule> <why it is safe>); directive is ineffective without one")
		return
	}
	d := &ignoreDirective{fromLine: fromLine, toLine: toLine, col: col, used: map[string]bool{}}
	for _, id := range strings.Split(m[1], ",") {
		id = strings.TrimSpace(id)
		if !IsKnownRule(id) {
			// 綴り間違いの抑制は黙って何もしないので、それ自体を報告する
			add(fmt.Sprintf("templ-lint:ignore names unknown rule %q; it suppresses nothing", id))
			continue
		}
		if !slices.Contains(d.rules, id) {
			d.rules = append(d.rules, id)
		}
	}
	if len(d.rules) > 0 {
		*ignores = append(*ignores, d)
	}
}

// applyIgnores は抑制された検出を取り除き、何も抑制しなかったディレクティブを報告する。
func (l *Linter) applyIgnores(path string, findings []Finding, ignores []*ignoreDirective) []Finding {
	if len(ignores) == 0 {
		return findings
	}
	kept := findings[:0]
	for _, f := range findings {
		if !suppressed(f, ignores) {
			kept = append(kept, f)
		}
	}
	for _, d := range ignores {
		for _, id := range d.rules {
			if d.used[id] || !l.ruleActive(id) {
				continue
			}
			kept = append(kept, Finding{
				File: path, Line: d.fromLine, Col: d.col,
				Rule: RuleUnusedIgnore, Severity: SeverityWarning,
				Message: fmt.Sprintf("templ-lint:ignore %s suppresses nothing on this or the next line; remove it", id),
			})
		}
	}
	return kept
}

func suppressed(f Finding, ignores []*ignoreDirective) bool {
	hit := false
	for _, d := range ignores {
		if slices.Contains(d.rules, f.Rule) && f.Line >= d.fromLine && f.Line <= d.toLine+1 {
			d.used[f.Rule] = true
			hit = true
		}
	}
	return hit
}

// ruleActive は現在の設定でルールが検出を出し得るかを返す。
// 設定次第で出ないルール (-csp strict 専用など) の抑制は、未使用として報告しない。
func (l *Linter) ruleActive(id string) bool {
	switch id {
	case RuleCSPInlineHandler, RuleCSPEvalAttr, RuleCSPInlineScript:
		return l.CSP == CSPStrict
	case RuleHTMXDisableSemantics:
		return l.HTMXVersion != htmxVersionUnknown
	case RuleInvalidIgnore, RuleUnusedIgnore:
		// ディレクティブ自体の検出は抑制の対象にならない
		return false
	}
	return true
}

func (l *Linter) checkAttribute(path, element string, tn templNames, n *parser.ExpressionAttribute, findings *[]Finding) {
	// 属性名が動的 ({ name }={ value }) な場合は名前ごと危険
	if _, ok := n.Key.(parser.ExpressionAttributeKey); ok {
		*findings = append(*findings, Finding{
			File: path, Line: n.Range.From.Line + 1, Col: n.Range.From.Col + 1,
			Rule: RuleDynAttrName, Severity: SeverityError,
			Message: "dynamic attribute name: an attacker-controlled name can become an event handler or Alpine directive",
		})
		return
	}
	raw := n.Key.String()
	add := func(rule string, sev Severity, msg string) {
		*findings = append(*findings, Finding{
			File: path, Line: n.Range.From.Line + 1, Col: n.Range.From.Col + 1,
			Rule: rule, Severity: sev, Message: msg,
		})
	}

	// { "..." } のように文字列リテラルだけでできた値は、開発者がテンプレートに書いた
	// 静的な値なので属性値の規則の対象外 (属性値の Go 式内の templ.Raw 等は下で検査する)。
	if !isConstantStringSrc(n.Expression.Value) {
		value := n.Expression
		normalized := l.normalizer().Normalize(raw)
		class := classifyAttr(normalized)
		if (class == attrJSEval || class == attrJSEvalPrefixed) && isSafeScriptValue(tn, raw, normalized, value.Value) {
			class = attrSafe
		}
		// htmx 2 の hx-confirm は確認ダイアログの文言で、js: を評価するのは htmx 4 から
		if normalized == "hx-confirm" && l.HTMXVersion == htmxVersion2 {
			class = attrSafe
		}
		switch class {
		case attrJSEval:
			add(RuleJSEvalAttr, SeverityError, fmt.Sprintf(
				"dynamic value in %q: Alpine.js/htmx evaluate this attribute as JavaScript, so HTML escaping does not prevent XSS; use a static expression, or pass data via templ.JSONString into a data-* attribute",
				raw))
		case attrJSEvalPrefixed:
			// 先頭が js: になり得ない ("Delete " + name など) なら評価されない
			if !hasNonScriptLiteralPrefix(value) {
				add(RuleJSEvalAttr, SeverityError, fmt.Sprintf(
					"dynamic value in %q: htmx evaluates this attribute as JavaScript when the value starts with \"js:\" or \"javascript:\"; start the value with a static literal, or pass data via templ.JSONString",
					raw))
			}
		case attrRequestURL:
			// 相対パス (自オリジン確定) は外部送信の心配がないので除外する。
			if !isSameOriginRelativeURL(value) {
				add(RuleURLAttr, SeverityWarning, fmt.Sprintf(
					"dynamic URL in %q: htmx will send a request to this URL; validate it against an allowlist server-side",
					raw))
			}
		case attrUnvetted:
			add(RuleUnvettedAttr, SeverityWarning, fmt.Sprintf(
				"dynamic value in %q: templ-lint does not know whether htmx evaluates this attribute; check the htmx docs and use a static value or suppress with a reason",
				raw))
		}

		lower := strings.ToLower(raw)
		if isUnsanitizedURLAttr(element, lower) &&
			!isSameOriginRelativeURL(value) &&
			!isTemplCall(tn, value.Value, "URL") &&
			// templ.SafeURL(x) は escape-bypass で報告するので二重に出さない
			!isTemplCall(tn, value.Value, "SafeURL") {
			add(RuleUnsafeURLAttr, SeverityError, fmt.Sprintf(
				"dynamic URL in <%s %s>: templ does not sanitize URLs in this attribute, so a javascript: URL or an attacker-chosen script runs; wrap the value in templ.URL(...) or use a same-origin relative path",
				element, raw))
		}
		if lower == "srcdoc" && !l.isAllowedHTMLSrc(tn, value.Value) {
			add(RuleSrcdocAttr, SeverityError, fmt.Sprintf(
				"dynamic value in <%s srcdoc>: the browser parses this attribute as an HTML document, so HTML escaping does not prevent XSS; sanitize with an allowed sanitizer",
				element))
		}
	}
	// 属性値の Go 式内の templ.SafeURL(x) 等も検査する
	l.checkGoSnippet(path, tn, n.Expression, findings)
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
