package lint

import (
	"fmt"
	goast "go/ast"
	goparser "go/parser"
	"go/token"
	"strconv"
	"strings"

	parser "github.com/a-h/templ/parser/v2"
)

// isSameOriginRelativeURL は、属性値の Go 式が「自オリジンの相対 URL」だと
// 静的に確定できるかを判定する。確定できる場合だけ true。
//
// 相対パス (先頭が "/") は必ず同一オリジンを指すので、動的に組み立てていても
// htmx が外部へリクエストを送る心配はない。ただし "//host" や "/\host" は
// プロトコル相対 URL として別オリジンへ飛ぶため、先頭 "/" の次の文字が
// "/" でも "\" でもないことまで確認する。
//
// 判定できるのは、式が文字列リテラル、または + 連結の最左要素が
// そのような文字列リテラルである場合に限る (例: "/posts/" + strconv.Itoa(id))。
// 変数由来 (baseURL + path など) は中身が見えないので false = 検知を維持する。
func isSameOriginRelativeURL(expr parser.Expression) bool {
	e, err := goparser.ParseExpr(expr.Value)
	if err != nil {
		return false
	}
	// + 連結の最左要素まで降りる ("a" + b + c は ((a+b)+c) と左結合)
	for {
		bin, ok := e.(*goast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			break
		}
		e = bin.X
	}
	lit, ok := e.(*goast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return false
	}
	// "/x..." の形 (先頭 "/" かつ次が "/"・"\" 以外) だけを同一オリジンと見なす。
	// "/" 単独や "//"・"/\" はプロトコル相対で別オリジンになり得るため除外しない。
	if len(s) < 2 || s[0] != '/' {
		return false
	}
	return s[1] != '/' && s[1] != '\\'
}

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
