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

// CSP の前提。CSPNone は CSP を前提にしない (既定)。
const (
	CSPNone   = ""
	CSPStrict = "strict"
)

// checkCSPElement は strict CSP (script-src に 'unsafe-inline' も 'unsafe-eval' も付けない)
// の下で動かない書き方を検査する。
//
// セキュリティの検査 (js-eval-attr など) とは独立した互換性の検査で、CSP があるからといって
// セキュリティの検査を緩めることはしない。CSP は設定ミスやヘッダーの付け忘れがあり得る保険だからだ。
// 重大度は警告: 脆弱性ではなく「本番で黙って動かない」バグを見つけるための検査。
//
// 動的な値はセキュリティの検査が先に報告するので、ここでは静的な値と、セキュリティの検査が
// 安全と判断した値 (templ.JSFuncCall など) だけを扱う。
func (l *Linter) checkCSPElement(path string, tn templNames, attrs []parser.Attribute, findings *[]Finding) {
	if l.CSP != CSPStrict {
		return
	}
	norm := l.normalizer()
	forEachAttr(attrs, func(a parser.Attribute) {
		key, val, ok := cspAttrValue(a)
		if !ok {
			return
		}
		r := attrRange(a)
		add := func(rule, msg string) {
			*findings = append(*findings, Finding{
				File: path, Line: r.From.Line + 1, Col: r.From.Col + 1,
				Rule: rule, Severity: SeverityWarning, Message: msg,
			})
		}
		normalized := norm.Normalize(key)
		if val.dynamic {
			// 動的な値はセキュリティの検査が安全と判断したもの (JSFuncCall など) だけ見る
			if isEventHandlerAttr(normalized) && isSafeScriptValue(tn, key, normalized, val.src) {
				add(RuleCSPInlineHandler, fmt.Sprintf(
					"%q renders an inline event handler, which a strict CSP blocks (nonces do not apply to event handler attributes); attach the listener from an external script instead",
					key))
			}
			return
		}

		switch {
		case isEventHandlerAttr(normalized):
			add(RuleCSPInlineHandler, fmt.Sprintf(
				"%q is an inline event handler, which a strict CSP blocks (nonces do not apply to event handler attributes); attach the listener from an external script instead",
				key))
		case isJavaScriptURLAttr(normalized) && isJavaScriptURL(val.value):
			add(RuleCSPInlineHandler, fmt.Sprintf(
				"javascript: URL in %q is blocked by a strict CSP; use a <button> with a listener from an external script instead",
				key))
		case strings.HasPrefix(normalized, "hx-"):
			if msg := l.htmxEvalUnderCSP(normalized, val.value); msg != "" {
				add(RuleCSPEvalAttr, fmt.Sprintf("%q %s", key, msg))
			}
		}
	})
}

// htmxEvalUnderCSP は htmx が eval / new Function で評価する静的な値なら理由を返す。
func (l *Linter) htmxEvalUnderCSP(normalized, value string) string {
	const blocked = "; a strict CSP without 'unsafe-eval' blocks this, so it silently does nothing"
	switch classifyAttr(normalized) {
	case attrJSEval:
		if normalized == "hx-trigger" {
			// フィルタ click[ctrlKey] の中身だけが評価される
			if strings.Contains(value, "[") {
				return "contains an event filter ([...]), which htmx evaluates as JavaScript" + blocked
			}
			return ""
		}
		return "is evaluated as JavaScript by htmx" + blocked
	case attrJSEvalPrefixed:
		if normalized == "hx-confirm" && l.HTMXVersion == htmxVersion2 {
			return ""
		}
		v := strings.ToLower(strings.TrimSpace(value))
		if strings.HasPrefix(v, "js:") || strings.HasPrefix(v, "javascript:") {
			return "uses the js: prefix, which htmx evaluates as JavaScript" + blocked
		}
	}
	return ""
}

// checkCSPScript はインラインの <script> に nonce があるかを検査する。
//
// templ は普通の <script> に nonce を自動では付けない (付くのは script テンプレートと
// templ.JSONScript だけ) ので、nonce={ templ.GetNonce(ctx) } を書き忘れると strict CSP の
// 下では実行されない。静的な nonce は毎リクエスト変わらないので CSP の意味を失わせる。
func (l *Linter) checkCSPScript(path string, n *parser.ScriptElement, findings *[]Finding) {
	if l.CSP != CSPStrict {
		return
	}
	add := func(r parser.Range, msg string) {
		*findings = append(*findings, Finding{
			File: path, Line: r.From.Line + 1, Col: r.From.Col + 1,
			Rule: RuleCSPInlineScript, Severity: SeverityWarning, Message: msg,
		})
	}
	var (
		hasSrc, hasNonce bool
		scriptType       = ""
		dynamicType      bool
	)
	forEachAttr(n.Attributes, func(a parser.Attribute) {
		key, val, ok := cspAttrValue(a)
		if !ok {
			return
		}
		switch strings.ToLower(key) {
		case "src":
			hasSrc = true
		case "type":
			if val.dynamic {
				dynamicType = true
			} else {
				scriptType = val.value
			}
		case "nonce":
			hasNonce = true
			if !val.dynamic && !val.boolean {
				add(attrRange(a), "static nonce: a CSP nonce must be generated per response, otherwise an attacker can reuse it; use nonce={ templ.GetNonce(ctx) }")
			}
		}
	})
	if hasSrc || hasNonce || len(n.Contents) == 0 {
		return
	}
	if !dynamicType && !isJavaScriptMIME(scriptType) {
		// type="application/json" などのデータブロックは実行されないので CSP の対象外
		return
	}
	add(n.Range, "inline <script> without a nonce is blocked by a strict CSP; templ does not add nonces to plain <script> elements, so add nonce={ templ.GetNonce(ctx) } or move the code to an external file")
}

// cspValue は属性値の分類。
type cspValue struct {
	value   string // 静的な値
	src     string // 動的な値の Go 式
	dynamic bool
	boolean bool
}

// cspAttrValue は属性名が静的な属性のキーと値を返す。
// { "..." } のような文字列リテラルだけの式は静的な値として扱う。
func cspAttrValue(a parser.Attribute) (string, cspValue, bool) {
	switch a := a.(type) {
	case *parser.ConstantAttribute:
		if k, ok := a.Key.(parser.ConstantAttributeKey); ok {
			return k.Name, cspValue{value: a.Value}, true
		}
	case *parser.BoolConstantAttribute:
		if k, ok := a.Key.(parser.ConstantAttributeKey); ok {
			return k.Name, cspValue{boolean: true}, true
		}
	case *parser.ExpressionAttribute:
		if k, ok := a.Key.(parser.ConstantAttributeKey); ok {
			if s, ok := constantStringValue(a.Expression.Value); ok {
				return k.Name, cspValue{value: s}, true
			}
			return k.Name, cspValue{src: a.Expression.Value, dynamic: true}, true
		}
	case *parser.BoolExpressionAttribute:
		if k, ok := a.Key.(parser.ConstantAttributeKey); ok {
			return k.Name, cspValue{boolean: true}, true
		}
	}
	return "", cspValue{}, false
}

func attrRange(a parser.Attribute) parser.Range {
	switch a := a.(type) {
	case *parser.ConstantAttribute:
		return a.Range
	case *parser.BoolConstantAttribute:
		return a.Range
	case *parser.ExpressionAttribute:
		return a.Range
	case *parser.BoolExpressionAttribute:
		return a.Range
	}
	return parser.Range{}
}

// constantStringValue は文字列リテラル (とその + 連結) だけの式なら連結後の値を返す。
func constantStringValue(src string) (string, bool) {
	e, err := goparser.ParseExpr(src)
	if err != nil || !isConstantString(e) {
		return "", false
	}
	var b strings.Builder
	if !appendConstantString(&b, e) {
		return "", false
	}
	return b.String(), true
}

func appendConstantString(b *strings.Builder, e goast.Expr) bool {
	switch e := unparen(e).(type) {
	case *goast.BasicLit:
		if e.Kind != token.STRING {
			return false
		}
		s, err := strconv.Unquote(e.Value)
		if err != nil {
			return false
		}
		b.WriteString(s)
		return true
	case *goast.BinaryExpr:
		return e.Op == token.ADD && appendConstantString(b, e.X) && appendConstantString(b, e.Y)
	}
	return false
}

// javascript: URL を受け取り得る属性 (正規化済みの名前)。
var javaScriptURLAttrs = map[string]bool{
	"href": true, "xlink:href": true, "src": true, "action": true, "formaction": true, "data": true,
}

func isJavaScriptURLAttr(name string) bool { return javaScriptURLAttrs[name] }

// isJavaScriptURL はブラウザが javascript: スキームとして扱う URL かを判定する。
// ブラウザは先頭の空白と、スキーム中のタブ・改行を無視する。
func isJavaScriptURL(v string) bool {
	v = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, v)
	v = strings.ToLower(strings.TrimLeft(v, " \f\x00"))
	return strings.HasPrefix(v, "javascript:")
}

// isJavaScriptMIME は <script type> が実行されるスクリプトかを判定する。
// HTML 仕様: type が空、JavaScript の MIME タイプ、"module" のとき実行される。
func isJavaScriptMIME(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	if i := strings.IndexByte(t, ';'); i >= 0 {
		t = strings.TrimSpace(t[:i])
	}
	switch t {
	case "", "module", "text/javascript", "application/javascript", "application/ecmascript",
		"text/ecmascript", "application/x-javascript", "application/x-ecmascript",
		"text/x-javascript", "text/x-ecmascript", "text/jscript", "text/livescript",
		"text/javascript1.0", "text/javascript1.1", "text/javascript1.2", "text/javascript1.3",
		"text/javascript1.4", "text/javascript1.5":
		return true
	}
	return false
}
