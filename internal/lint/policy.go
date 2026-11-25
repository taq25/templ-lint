package lint

import (
	"fmt"
	goast "go/ast"
	goparser "go/parser"
	"go/token"
	"strings"

	"github.com/m-mizutani/goerr/v2"
)

// checkSanitizerPolicy は bluemonday のポリシー設定のうち、サニタイズ後の HTML に
// htmx / Alpine / イベントハンドラの属性を残してしまうものを検出する (sanitizer-policy)。
//
// templ-lint は bluemonday.XxxPolicy().Sanitize(x) を templ.Raw の引数として許可するが、
// ポリシーの中身次第ではサニタイズ後も攻撃者の属性が生きる:
//
//   - AllowDataAttributes(): data-* をすべて通す。htmx は data-hx-* を hx-* と同じに扱うので
//     data-hx-get / data-hx-trigger でリクエストを発行させられる
//   - AllowAttrs("onclick", "x-data", "hx-get", "@click", ...): JS として評価される属性や
//     htmx の属性を名指しで通す
//   - AllowUnsafe(true): <script> / <style> の許可を有効にする
//
// 型情報は使わないので、bluemonday を import しているファイルの中で上のメソッド名の
// 呼び出しを探す。report には位置とメッセージを渡す。
func (l *Linter) checkSanitizerPolicy(root goast.Node, report func(pos token.Pos, msg string)) {
	norm := l.normalizer()
	goast.Inspect(root, func(node goast.Node) bool {
		call, ok := node.(*goast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*goast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "AllowDataAttributes":
			report(sel.Sel.Pos(), "bluemonday AllowDataAttributes() lets every data-* attribute through, and htmx treats data-hx-* as hx-* (data-hx-get, data-hx-trigger, ...), so sanitized user HTML can still drive htmx; allow specific data-* names instead, and wrap the output in hx-ignore (htmx 2: hx-disable)")
		case "AllowAttrs":
			for _, arg := range call.Args {
				name, ok := constantStringValue(exprSource(arg))
				if !ok {
					continue
				}
				if classifyAttr(norm.Normalize(name)) == attrOther {
					continue
				}
				report(arg.Pos(), fmt.Sprintf(
					"bluemonday AllowAttrs(%q) keeps an attribute that the browser, htmx or Alpine.js acts on, so sanitized user HTML can still run code or send requests; do not allow it in user content",
					name))
			}
		case "AllowUnsafe":
			if len(call.Args) == 1 {
				if id, ok := call.Args[0].(*goast.Ident); ok && id.Name == "false" {
					return true
				}
			}
			report(sel.Sel.Pos(), "bluemonday AllowUnsafe(true) permits <script> and <style> when they are allowed, which defeats sanitizing user HTML; remove it")
		}
		return true
	})
}

// exprSource は文字列リテラル (とその連結) の式を Go のソースに戻す。
// constantStringValue に渡すためだけに使うので、それ以外の式は空文字列になる。
func exprSource(e goast.Expr) string {
	switch e := unparen(e).(type) {
	case *goast.BasicLit:
		return e.Value
	case *goast.BinaryExpr:
		if e.Op == token.ADD {
			return exprSource(e.X) + " + " + exprSource(e.Y)
		}
	}
	return ""
}

// importsBluemonday はファイルが bluemonday を import しているか判定する。
func importsBluemonday(imports []*goast.ImportSpec) bool {
	for _, imp := range imports {
		if strings.Trim(imp.Path.Value, "`\"") == bluemondayImportPath {
			return true
		}
	}
	return false
}

// LintGoFile は .go ファイル (templ の生成コードとテストを除く) の bluemonday ポリシーを検査する。
// ポリシーは .templ ではなく .go で組み立てることが多いので、ディレクトリを検査するときは
// .go ファイルも対象にする。bluemonday を import していないファイルは読み飛ばす。
func (l *Linter) LintGoFile(path string) ([]Finding, error) {
	fset := token.NewFileSet()
	f, err := goparser.ParseFile(fset, path, nil, goparser.ImportsOnly)
	if err != nil {
		// 構文エラーの .go はコンパイルで気付くので、ここでは検査しない
		return nil, nil
	}
	if !importsBluemonday(f.Imports) {
		return nil, nil
	}
	f, err = goparser.ParseFile(fset, path, nil, goparser.ParseComments)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to parse go file", goerr.V("path", path))
	}
	var findings []Finding
	var ignores []*ignoreDirective
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			from, to := fset.Position(c.Pos()), fset.Position(c.End())
			collectIgnoreAt(path, c.Text, uint32(from.Line), uint32(to.Line), uint32(from.Column), &ignores, &findings)
		}
	}
	l.checkSanitizerPolicy(f, func(pos token.Pos, msg string) {
		p := fset.Position(pos)
		findings = append(findings, Finding{
			File: path, Line: uint32(p.Line), Col: uint32(p.Column),
			Rule: RuleSanitizerPolicy, Severity: SeverityWarning, Message: msg,
		})
	})
	return l.applyIgnores(path, findings, ignores), nil
}

// isLintableGoFile は検査対象の .go ファイルか判定する (templ の生成コードとテストは除く)。
func isLintableGoFile(path string) bool {
	return strings.HasSuffix(path, ".go") &&
		!strings.HasSuffix(path, "_templ.go") &&
		!strings.HasSuffix(path, "_test.go")
}
