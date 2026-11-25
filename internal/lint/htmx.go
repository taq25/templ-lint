package lint

import (
	"fmt"
	goast "go/ast"
	"strings"

	parser "github.com/a-h/templ/parser/v2"
	"github.com/a-h/templ/parser/v2/visitor"
)

// htmx のメジャーバージョン。0 は未指定 (バージョンに依存しない検査だけを行う)。
const (
	htmxVersionUnknown = 0
	htmxVersion2       = 2
	htmxVersion4       = 4
)

// checkHTMXElement は htmx の要素レベルの規則を検査する。
//
//   - htmx-config-meta: <meta name="htmx-config" content={ 動的 }>
//     htmx は 2 でも 4 でも、この meta タグからグローバル設定を読む。htmx 4 では
//     属性接頭辞 (prefix)、許可する拡張 (extensions)、fetch の mode まで設定できるので、
//     値を注入されるとページ全体の防御を外される。
//   - htmx-disable-semantics: htmx 2 と 4 で意味が入れ替わった hx-disable / hx-ignore
func (l *Linter) checkHTMXElement(path string, tn templNames, n *parser.Element, findings *[]Finding) {
	name := strings.ToLower(n.Name)
	if name == "meta" {
		l.checkHTMXConfigMeta(path, tn, n, findings)
	}
	l.checkDisableSemantics(path, tn, n, findings)
}

func (l *Linter) checkHTMXConfigMeta(path string, tn templNames, n *parser.Element, findings *[]Finding) {
	metaName, ok := constAttr(n.Attributes, "name")
	if !ok || !strings.EqualFold(strings.TrimSpace(metaName), "htmx-config") {
		return
	}
	forEachAttr(n.Attributes, func(a parser.Attribute) {
		ea, ok := a.(*parser.ExpressionAttribute)
		if !ok {
			return
		}
		key, ok := ea.Key.(parser.ConstantAttributeKey)
		if !ok || !strings.EqualFold(key.Name, "content") {
			return
		}
		v := ea.Expression.Value
		// templ.JSONString(cfg) は Go の型で JSON の構造が固定されるので許可する
		// (キーを注入されることはない。値の中身は呼び出し側の責任)。
		if isConstantStringSrc(v) || isTemplCall(tn, v, "JSONString") {
			return
		}
		*findings = append(*findings, Finding{
			File: path, Line: ea.Range.From.Line + 1, Col: ea.Range.From.Col + 1,
			Rule: RuleHTMXConfigMeta, Severity: SeverityError,
			Message: `dynamic content in <meta name="htmx-config">: htmx reads its global configuration (prefix, extensions, request mode, ...) from this tag, so an injected value can disable page-wide protections; use a static value or templ.JSONString of a Go struct`,
		})
	})
}

// checkDisableSemantics は htmx 2 と 4 で入れ替わった属性の取り違えを検査する。
//
//	htmx 2: hx-disable          … 子孫を htmx に処理させない (ユーザー HTML を囲う防御策)
//	htmx 4: hx-ignore           … 同上 (hx-disable から改名)
//	        hx-disable          … リクエスト中に要素を無効化する (htmx 2 の hx-disabled-elt)
//
// htmx 2 のつもりで hx-disable を書いたまま htmx 4 に上げると、子孫の hx-* 属性が
// 黙って有効になる。逆に htmx 2 で hx-ignore を書いても何も防がない。
func (l *Linter) checkDisableSemantics(path string, tn templNames, n *parser.Element, findings *[]Finding) {
	norm := l.normalizer()
	forEachAttr(n.Attributes, func(a parser.Attribute) {
		key, value, isBool, r, ok := staticAttr(a)
		if !ok {
			return
		}
		switch norm.Normalize(key) {
		case "hx-disable":
			if l.HTMXVersion != htmxVersion4 {
				return
			}
			// 値なし / 空 / "true" は htmx 2 の書き方。htmx 4 の hx-disable はセレクタを取る。
			v := strings.TrimSpace(strings.ToLower(value))
			legacyForm := isBool || v == "" || v == "true"
			if !legacyForm && !containsUntrustedHTML(tn, n.Children) {
				return
			}
			*findings = append(*findings, Finding{
				File: path, Line: r.From.Line + 1, Col: r.From.Col + 1,
				Rule: RuleHTMXDisableSemantics, Severity: SeverityError,
				Message: fmt.Sprintf(
					"%q is used as in htmx 2, but in htmx 4 it only disables elements during requests and no longer stops htmx from processing descendants; use hx-ignore to keep untrusted content inert",
					key),
			})
		case "hx-ignore":
			if l.HTMXVersion != htmxVersion2 {
				return
			}
			*findings = append(*findings, Finding{
				File: path, Line: r.From.Line + 1, Col: r.From.Col + 1,
				Rule: RuleHTMXDisableSemantics, Severity: SeverityError,
				Message: fmt.Sprintf(
					"%q does not exist in htmx 2, so descendants are still processed by htmx; use hx-disable in htmx 2 (hx-ignore is its htmx 4 name)",
					key),
			})
		}
	})
}

// staticAttr は属性が静的 (値が固定) ならキー・値・値の有無を返す。
func staticAttr(a parser.Attribute) (key, value string, isBool bool, r parser.Range, ok bool) {
	switch a := a.(type) {
	case *parser.ConstantAttribute:
		if k, ok := a.Key.(parser.ConstantAttributeKey); ok {
			return k.Name, a.Value, false, a.Range, true
		}
	case *parser.BoolConstantAttribute:
		if k, ok := a.Key.(parser.ConstantAttributeKey); ok {
			return k.Name, "", true, a.Range, true
		}
	}
	return "", "", false, parser.Range{}, false
}

// forEachAttr は条件付き属性 (if ... { attr }) の中も含めて属性を列挙する。
func forEachAttr(attrs []parser.Attribute, fn func(parser.Attribute)) {
	for _, a := range attrs {
		if ca, ok := a.(*parser.ConditionalAttribute); ok {
			forEachAttr(ca.Then, fn)
			forEachAttr(ca.Else, fn)
			continue
		}
		fn(a)
	}
}

// containsUntrustedHTML は子孫に、内容をテンプレートから見通せない HTML
// (templ.Raw / { children... }) があるかを判定する。
func containsUntrustedHTML(tn templNames, nodes []parser.Node) bool {
	found := false
	v := visitor.New()
	v.ChildrenExpression = func(*parser.ChildrenExpression) error {
		found = true
		return nil
	}
	prevTemplElem := v.TemplElementExpression
	v.TemplElementExpression = func(n *parser.TemplElementExpression) error {
		if callsTemplFunc(tn, n.Expression.Value, "Raw") {
			found = true
		}
		return prevTemplElem(n)
	}
	for _, n := range nodes {
		if err := n.Visit(v); err != nil {
			return true // 判定できないときは安全側に倒す
		}
		if found {
			return true
		}
	}
	return false
}

// callsTemplFunc は Go コード片に templ の指定関数の呼び出しが含まれるかを判定する。
func callsTemplFunc(tn templNames, src, fn string) bool {
	snip, ok := parseGoSnippet(src)
	if !ok {
		return false
	}
	found := false
	goast.Inspect(snip.root, func(node goast.Node) bool {
		if call, ok := node.(*goast.CallExpr); ok {
			if name, ok := tn.templFunc(call.Fun); ok && name == fn {
				found = true
			}
		}
		return !found
	})
	return found
}
