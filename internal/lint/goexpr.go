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

const templImportPath = "github.com/a-h/templ"

// templNames は .templ ファイル内で templ パッケージを指す識別子の集合。
// 生成コードが常に templ を import するので "templ" は必ず含まれ、
// import t "github.com/a-h/templ" のような別名もここに加わる。
// dot import (import . "github.com/a-h/templ") の場合は dot が true になる。
type templNames struct {
	names map[string]bool
	dot   bool
}

func defaultTemplNames() templNames {
	return templNames{names: map[string]bool{"templ": true}}
}

// collectTemplNames は .templ ファイル内の Go コード (import 文) から templ の別名を集める。
func collectTemplNames(tf *parser.TemplateFile) templNames {
	tn := defaultTemplNames()
	var srcs []string
	for _, h := range tf.Header {
		srcs = append(srcs, h.Expression.Value)
	}
	for _, n := range tf.Nodes {
		if g, ok := n.(*parser.TemplateFileGoExpression); ok {
			srcs = append(srcs, g.Expression.Value)
		}
	}
	for _, src := range srcs {
		f, err := goparser.ParseFile(token.NewFileSet(), "", "package p\n"+src, goparser.ImportsOnly)
		if err != nil {
			continue
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || path != templImportPath || imp.Name == nil {
				continue
			}
			switch imp.Name.Name {
			case ".":
				tn.dot = true
			case "_":
			default:
				tn.names[imp.Name.Name] = true
			}
		}
	}
	return tn
}

// templFunc は式が templ パッケージの関数 (templ.X / 別名.X / dot import の X) なら X を返す。
func (tn templNames) templFunc(e goast.Expr) (string, bool) {
	switch e := e.(type) {
	case *goast.SelectorExpr:
		if pkg, ok := e.X.(*goast.Ident); ok && tn.names[pkg.Name] {
			return e.Sel.Name, true
		}
	case *goast.Ident:
		if tn.dot {
			return e.Name, true
		}
	}
	return "", false
}

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
	s, ok := leftmostStringLiteral(expr.Value)
	if !ok {
		return false
	}
	// "/x..." の形 (先頭 "/" かつ次が "/"・"\" 以外) だけを同一オリジンと見なす。
	// "/" 単独や "//"・"/\" はプロトコル相対で別オリジンになり得るため除外しない。
	if len(s) < 2 || s[0] != '/' {
		return false
	}
	return s[1] != '/' && s[1] != '\\'
}

// hasNonScriptLiteralPrefix は、値の先頭が "js:" / "javascript:" になり得ないと
// 静的に確定できるかを判定する (hx-vals, hx-confirm など js: 接頭辞で評価される属性用)。
// + 連結の最左要素が、空白を除いて空でなく js: で始まらない文字列リテラルなら true。
func hasNonScriptLiteralPrefix(expr parser.Expression) bool {
	s, ok := leftmostStringLiteral(expr.Value)
	if !ok {
		return false
	}
	s = strings.ToLower(strings.TrimLeft(s, " \t\r\n\f"))
	if s == "" {
		return false
	}
	// 先頭が "j", "js", "javascr" のように途中で切れていると、続く動的部分で js: になり得る
	for _, p := range []string{"js:", "javascript:"} {
		if strings.HasPrefix(s, p) || strings.HasPrefix(p, s) {
			return false
		}
	}
	return true
}

// leftmostStringLiteral は + 連結の最左要素が文字列リテラルならその値を返す。
func leftmostStringLiteral(src string) (string, bool) {
	e, err := goparser.ParseExpr(src)
	if err != nil {
		return "", false
	}
	// "a" + b + c は ((a+b)+c) と左結合
	for {
		bin, ok := e.(*goast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			break
		}
		e = bin.X
	}
	e = unparen(e)
	lit, ok := e.(*goast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// isConstantString は式が文字列リテラル (またはその + 連結) だけでできているかを判定する。
// 開発者がテンプレートに直接書いた値なので、属性値の規則の対象外にする。
func isConstantString(e goast.Expr) bool {
	switch e := unparen(e).(type) {
	case *goast.BasicLit:
		return e.Kind == token.STRING
	case *goast.BinaryExpr:
		return e.Op == token.ADD && isConstantString(e.X) && isConstantString(e.Y)
	}
	return false
}

func isConstantStringSrc(src string) bool {
	e, err := goparser.ParseExpr(src)
	return err == nil && isConstantString(e)
}

func unparen(e goast.Expr) goast.Expr {
	for {
		p, ok := e.(*goast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// goSnippet は .templ 内の Go コード片を解析した結果。
// lineOffset は解析用に前置したラッパーの行数で、位置を .templ 上に戻すのに使う。
type goSnippet struct {
	root       goast.Node
	fset       *token.FileSet
	lineOffset int
}

// parseGoSnippet は Go コード片を、式 → ファイル (関数宣言などのトップレベル) → 関数本体
// (`x := f()` のような文) の順に試してパースする。
func parseGoSnippet(src string) (goSnippet, bool) {
	fset := token.NewFileSet()
	if expr, err := goparser.ParseExprFrom(fset, "snippet.go", src, 0); err == nil {
		return goSnippet{root: expr, fset: fset}, true
	}
	for _, w := range []struct {
		prefix, suffix string
		lines          int
	}{
		{"package p\n", "", 1},
		{"package p\nfunc _() {\n", "\n}", 2},
	} {
		fset := token.NewFileSet()
		file, err := goparser.ParseFile(fset, "snippet.go", w.prefix+src+w.suffix, 0)
		if err == nil {
			return goSnippet{root: file, fset: fset, lineOffset: w.lines}, true
		}
	}
	return goSnippet{}, false
}

// position はコード片内の位置を .templ ファイル上の 1 始まりの行・列に変換する。
func (s goSnippet) position(base parser.Range, pos token.Pos) (uint32, uint32) {
	p := s.fset.Position(pos)
	line := p.Line - s.lineOffset // コード片内の 1 始まりの行
	if !p.IsValid() || line < 1 {
		return base.From.Line + 1, base.From.Col + 1
	}
	if line == 1 {
		return base.From.Line + 1, base.From.Col + uint32(p.Column)
	}
	return base.From.Line + uint32(line), uint32(p.Column)
}

// checkGoSnippet は .templ 内の Go 式/コード片を go/parser で解析し、
// templ.Raw / templ.SafeURL 等への非リテラル引数を検出する。
// 関数を呼ばずに値として扱う形 (f := templ.Raw) も、引数の検査を素通りするので検出する。
func (l *Linter) checkGoSnippet(path string, tn templNames, expr parser.Expression, findings *[]Finding) {
	snip, ok := parseGoSnippet(expr.Value)
	if !ok {
		return
	}
	report := func(pos token.Pos, msg string) {
		line, col := snip.position(expr.Range, pos)
		*findings = append(*findings, Finding{
			File: path, Line: line, Col: col,
			Rule: RuleEscapeBypass, Severity: SeverityError,
			Message: msg,
		})
	}
	called := map[goast.Expr]bool{}
	goast.Inspect(snip.root, func(node goast.Node) bool {
		switch n := node.(type) {
		case *goast.CallExpr:
			name, ok := tn.templFunc(n.Fun)
			if !ok || !escapeBypassFuncs[name] {
				return true
			}
			called[n.Fun] = true
			if len(n.Args) > 0 && l.isAllowedArg(n.Args[0]) {
				return true
			}
			report(n.Pos(), fmt.Sprintf(
				"templ.%s bypasses escaping; passing a non-literal value risks XSS — sanitize with an allowed sanitizer or use a static literal",
				name))
		case *goast.SelectorExpr:
			// dot import 時の素の識別子 (f := Raw) は、宣言や別パッケージのセレクタの一部
			// としても現れて区別できないため、値としての使用は templ.X / 別名.X の形だけを見る。
			if called[n] {
				return true
			}
			name, ok := tn.templFunc(n)
			if !ok || !escapeBypassFuncs[name] {
				return true
			}
			report(n.Pos(), fmt.Sprintf(
				"templ.%s is used as a value: calls through it skip the argument check; call templ.%s directly",
				name, name))
			return false
		}
		return true
	})
}

// isAllowedArg はエスケープバイパス関数の引数として許可される形かを判定する。
func (l *Linter) isAllowedArg(arg goast.Expr) bool {
	// 静的な文字列リテラル (とその連結) は開発者が書いたものなので許可
	if isConstantString(arg) {
		return true
	}
	call, ok := unparen(arg).(*goast.CallExpr)
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

// isTemplCall は式が templ の指定関数の呼び出しか判定する。
func isTemplCall(tn templNames, src, fn string) bool {
	e, err := goparser.ParseExpr(src)
	if err != nil {
		return false
	}
	call, ok := unparen(e).(*goast.CallExpr)
	if !ok {
		return false
	}
	name, ok := tn.templFunc(call.Fun)
	return ok && name == fn
}

// isAllowedHTMLSrc は式が許可されたサニタイザ呼び出し (srcdoc に入れてよい HTML) か判定する。
func (l *Linter) isAllowedHTMLSrc(src string) bool {
	e, err := goparser.ParseExpr(src)
	return err == nil && l.isAllowedArg(e)
}
