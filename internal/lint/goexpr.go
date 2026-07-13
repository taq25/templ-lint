package lint

import (
	"fmt"
	goast "go/ast"
	goparser "go/parser"
	"go/token"
	"strings"

	parser "github.com/a-h/templ/parser/v2"
)

// checkGoSnippet は .templ 内の Go 式/コード片を go/parser で解析し、
// templ.Raw / templ.SafeURL 等への非リテラル引数を検出する。
func (l *Linter) checkGoSnippet(path string, expr parser.Expression, findings *[]Finding) {
	root, ok := parseGoSnippet(expr.Value)
	if !ok {
		return
	}
	goast.Inspect(root, func(node goast.Node) bool {
		call, ok := node.(*goast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*goast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*goast.Ident)
		if !ok || pkg.Name != "templ" || !escapeBypassFuncs[sel.Sel.Name] {
			return true
		}
		if len(call.Args) > 0 && l.isAllowedArg(call.Args[0]) {
			return true
		}
		*findings = append(*findings, Finding{
			File:     path,
			Line:     expr.Range.From.Line + 1,
			Col:      expr.Range.From.Col + 1,
			Rule:     RuleEscapeBypass,
			Severity: SeverityError,
			Message: fmt.Sprintf(
				"templ.%s bypasses escaping; passing a non-literal value risks XSS — sanitize with an allowed sanitizer or use a static literal",
				sel.Sel.Name),
		})
		return true
	})
}

// parseGoSnippet は式として、だめなら関数本体として Go コード片をパースする。
// (GoCode ノードは `x := f()` のような文を含み得るため)
func parseGoSnippet(src string) (goast.Node, bool) {
	if expr, err := goparser.ParseExpr(src); err == nil {
		return expr, true
	}
	wrapped := "package p\nfunc _() {\n" + src + "\n}"
	file, err := goparser.ParseFile(token.NewFileSet(), "snippet.go", wrapped, 0)
	if err != nil {
		return nil, false
	}
	return file, true
}

// isAllowedArg はエスケープバイパス関数の引数として許可される形かを判定する。
func (l *Linter) isAllowedArg(arg goast.Expr) bool {
	// 静的な文字列リテラルは開発者が書いたものなので許可
	if lit, ok := arg.(*goast.BasicLit); ok {
		return lit.Kind == token.STRING
	}
	call, ok := arg.(*goast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*goast.SelectorExpr)
	if !ok {
		return false
	}
	// bluemonday.XxxPolicy().Sanitize(x) チェーンは AST で由来を検証できるので許可。
	// 変数に格納したポリシー (p.Sanitize(x)) は由来を検証できないため許可しない。
	if sel.Sel.Name == "Sanitize" {
		if inner, ok := sel.X.(*goast.CallExpr); ok {
			if innerSel, ok := inner.Fun.(*goast.SelectorExpr); ok {
				if pkg, ok := innerSel.X.(*goast.Ident); ok && pkg.Name == "bluemonday" {
					return true
				}
			}
		}
	}
	// 設定された許可リスト ("pkg.Func" 形式のサニタイズラッパー)
	if pkg, ok := sel.X.(*goast.Ident); ok {
		qualified := pkg.Name + "." + sel.Sel.Name
		for _, allowed := range l.AllowedSanitizers {
			if strings.TrimSpace(allowed) == qualified {
				return true
			}
		}
	}
	return false
}
