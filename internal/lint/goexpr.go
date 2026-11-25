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
// imports はファイル内の import の「ローカル名 → import パス」(-allow-sanitizer の
// import パス指定と bluemonday の由来の確認に使う)。
type templNames struct {
	names   map[string]bool
	dot     bool
	imports map[string]string
}

func defaultTemplNames() templNames {
	return templNames{names: map[string]bool{"templ": true}, imports: map[string]string{}}
}

// collectTemplNames は .templ ファイル内の Go コード (import 文) から templ の別名と
// import の一覧を集める。
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
		tn.addImports(f.Imports)
	}
	return tn
}

func (tn templNames) addImports(imports []*goast.ImportSpec) {
	for _, imp := range imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		local := defaultPackageName(path)
		if imp.Name != nil {
			local = imp.Name.Name
		}
		switch local {
		case ".":
			if path == templImportPath {
				tn.dot = true
			}
			continue
		case "_":
			continue
		}
		tn.imports[local] = path
		if path == templImportPath {
			tn.names[local] = true
		}
	}
}

// defaultPackageName は別名なしの import で使われるパッケージ名を import パスから推定する。
// 型情報なしでは正確には分からないので、Go の慣習 (最後の要素、/v2 などの
// メジャーバージョンと gopkg.in の .v3 は除く) に従う。外れた場合は許可されない側
// (検知を維持する側) に倒れるので、別名を付けた import で回避できる。
func defaultPackageName(path string) string {
	parts := strings.Split(path, "/")
	name := parts[len(parts)-1]
	if len(parts) > 1 && isMajorVersion(name) {
		name = parts[len(parts)-2]
	}
	if i := strings.Index(name, ".v"); i > 0 && isMajorVersion(name[i+1:]) {
		name = name[:i]
	}
	return name
}

func isMajorVersion(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// importsPath はファイルが指定の import パスを import しているかを返す。
func (tn templNames) importsPath(path string) bool {
	for _, p := range tn.imports {
		if p == path {
			return true
		}
	}
	return false
}

// importedFrom は識別子が指定の import パスのパッケージを指すかを返す。
// import の一覧にない識別子は判定できないので known=false を返す。
func (tn templNames) importedFrom(name, path string) (match, known bool) {
	p, ok := tn.imports[name]
	if !ok {
		return false, false
	}
	return p == path, true
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
	if tn.importsPath(bluemondayImportPath) {
		l.checkSanitizerPolicy(snip.root, func(pos token.Pos, msg string) {
			line, col := snip.position(expr.Range, pos)
			*findings = append(*findings, Finding{
				File: path, Line: line, Col: col,
				Rule: RuleSanitizerPolicy, Severity: SeverityWarning, Message: msg,
			})
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
			if len(n.Args) > 0 && l.isAllowedArg(tn, n.Args[0]) {
				return true
			}
			report(n.Pos(), fmt.Sprintf(
				"templ.%s bypasses escaping; passing a non-literal value risks XSS — sanitize with an allowed sanitizer or use a static literal",
				name))
		case *goast.CompositeLit:
			// templ.ComponentScript{Call: x} は templ.JSUnsafeFuncCall(x) と同じく
			// on* / hx-on:* に任意の JS を出力する
			name, ok := tn.templFunc(n.Type)
			if !ok || name != "ComponentScript" || componentScriptIsConstant(n) {
				return true
			}
			report(n.Pos(), "templ.ComponentScript literal with a non-literal Call: the value is output as JavaScript as-is; use templ.JSFuncCall with a static function name")
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

const bluemondayImportPath = "github.com/microcosm-cc/bluemonday"

// isAllowedArg はエスケープバイパス関数の引数として許可される形かを判定する。
func (l *Linter) isAllowedArg(tn templNames, arg goast.Expr) bool {
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
				if pkg, ok := innerSel.X.(*goast.Ident); ok && tn.isBluemonday(pkg.Name) {
					return true
				}
			}
		}
	}
	// 設定された許可リスト ("pkg.Func" または "import/path.Func" 形式のサニタイズラッパー)
	pkg, ok := sel.X.(*goast.Ident)
	if !ok {
		return false
	}
	for _, allowed := range l.AllowedSanitizers {
		path, fn, ok := splitSanitizer(allowed)
		if !ok || fn != sel.Sel.Name {
			continue
		}
		if strings.Contains(path, "/") || strings.Contains(path, ".") {
			// import パス指定: ファイル内の import と突き合わせるので、同名の別パッケージを
			// 誤って許可しない
			if match, _ := tn.importedFrom(pkg.Name, path); match {
				return true
			}
			continue
		}
		if pkg.Name == path {
			return true
		}
	}
	return false
}

// isBluemonday は識別子が bluemonday パッケージを指すかを返す。import の一覧に
// ないときは (従来どおり) 名前で判断し、別のパッケージを指しているなら許可しない。
func (tn templNames) isBluemonday(name string) bool {
	if match, known := tn.importedFrom(name, bluemondayImportPath); known {
		return match
	}
	return name == "bluemonday"
}

// splitSanitizer は "pkg.Func" / "example.com/x/sanitize.Func" を
// パッケージ (名前または import パス) と関数名に分ける。
func splitSanitizer(s string) (pkg, fn string, ok bool) {
	s = strings.TrimSpace(s)
	slash := strings.LastIndex(s, "/")
	dot := strings.LastIndex(s, ".")
	if dot <= slash || dot <= 0 || dot == len(s)-1 {
		return "", "", false
	}
	return s[:dot], s[dot+1:], true
}

// componentScriptIsConstant は ComponentScript リテラルの JS を出力するフィールドが
// すべて文字列リテラルかを判定する。
func componentScriptIsConstant(lit *goast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*goast.KeyValueExpr)
		if !ok {
			// フィールド名なしの初期化は Call / CallInline の位置を特定しない
			if !isConstantString(elt) {
				return false
			}
			continue
		}
		key, ok := kv.Key.(*goast.Ident)
		if !ok {
			return false
		}
		switch key.Name {
		case "Call", "CallInline", "Function":
			if !isConstantString(kv.Value) {
				return false
			}
		}
	}
	return true
}

// isSafeScriptValue は、JS として評価される属性の値が、中身にかかわらずコードを
// 注入できない形かを判定する。
//
//   - templ.JSONString(v): JSON は JavaScript の式としてはデータでしかない
//     (ES2019 以降 JSON は JS の部分集合)。hx-vals / hx-headers の "js:" にもならない
//     (出力は { [ " 数字 true false null のどれかで始まる)。ただし hx-trigger は
//     JS ではなく独自の文法で、値の一部だけがフィルタとして評価されるので対象外。
//   - templ.JSFuncCall("name", args...): templ が on* / hx-on:* 属性に対して出力する
//     安全な関数呼び出し。引数は JSON エンコードされる。関数名は templ が識別子の形かを
//     検査するだけで eval なども通すので、関数名が文字列リテラルのときだけ許可する。
//     templ がこの特別扱いをするのは書かれた属性名が "on" か "hx-on:" で始まるときだけ
//     (generator.isScriptAttribute) なので、それ以外の属性 (@click など) では許可しない。
//   - templ.JSUnsafeFuncCall(x) / templ.JSExpression(x) / templ.ComponentScript{...}:
//     引数やフィールドがリテラルなら開発者が書いた JS、そうでなければ escape-bypass が
//     報告するので、ここでは二重に報告しない。
func isSafeScriptValue(tn templNames, rawName, normalized, src string) bool {
	e, err := goparser.ParseExpr(src)
	if err != nil {
		return false
	}
	switch e := unparen(e).(type) {
	case *goast.CompositeLit:
		name, ok := tn.templFunc(e.Type)
		return ok && name == "ComponentScript"
	case *goast.CallExpr:
		fn, ok := tn.templFunc(e.Fun)
		if !ok {
			return false
		}
		switch fn {
		case "JSONString":
			return normalized != "hx-trigger"
		case "JSFuncCall":
			return isTemplScriptAttr(rawName) && len(e.Args) > 0 && isConstantString(e.Args[0])
		case "JSUnsafeFuncCall", "JSExpression":
			return true
		}
	}
	return false
}

// isTemplScriptAttr は templ が値を templ.ComponentScript として扱う属性か判定する。
// templ の generator.isScriptAttribute と同じ (大文字小文字を区別する前方一致)。
func isTemplScriptAttr(rawName string) bool {
	return strings.HasPrefix(rawName, "on") || strings.HasPrefix(rawName, "hx-on:")
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
func (l *Linter) isAllowedHTMLSrc(tn templNames, src string) bool {
	e, err := goparser.ParseExpr(src)
	return err == nil && l.isAllowedArg(tn, e)
}
