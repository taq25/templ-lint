package lint

import (
	"regexp"
	"strings"
)

// attrClass は動的な値を受け取った属性がフロントエンドでどう扱われるかの分類。
type attrClass int

const (
	// attrOther は htmx / Alpine / イベントハンドラのいずれでもない通常の属性。
	attrOther attrClass = iota
	// attrJSEval は値が常に JavaScript として評価される属性。
	attrJSEval
	// attrJSEvalPrefixed は値が "js:" / "javascript:" で始まる場合だけ評価される属性
	// (hx-vals, hx-headers, hx-confirm, hx-request)。
	attrJSEvalPrefixed
	// attrRequestURL は htmx のリクエスト先 / 履歴 URL になる属性。
	attrRequestURL
	// attrUnvetted は htmx の名前空間にあるが安全性を確認していない属性。
	// 新しい属性が増えても検知側に倒れるよう、既知の安全な属性以外はここに入る。
	attrUnvetted
	// attrSafe は値が評価されないことを確認済みの htmx / Alpine 属性。
	attrSafe
)

// AttrNormalizer は属性名をフレームワークの正規形に揃える。
//
// htmx も Alpine も属性名の書き方に幅があり、そのまま正規表現に当てると
// 表記揺れがそのまま見逃しになる:
//
//   - HTML の属性名は大文字小文字を区別しない (onClick も onclick と同じ)
//   - htmx は data-hx-* を常に受け付け、htmx 4 は config.prefix で別の接頭辞も設定できる
//   - Alpine も Alpine.prefix() で接頭辞を変えられる (既定は x- だけ。data-x- は
//     ふつうのデータ属性と衝突するので、指定されたときだけ扱う)
//   - htmx 4 は hx-vals:inherited / hx-vals:append のような継承修飾子を持つ
//     (config.metaCharacter を変えると hx-vals-inherited になる)
type AttrNormalizer struct {
	// HTMXPrefixes は hx- と同じ意味を持つ追加の接頭辞 (例: "data-boost-")。
	// "data-hx-" は常に含まれる。
	HTMXPrefixes []string
	// AlpinePrefixes は x- と同じ意味を持つ追加の接頭辞 (例: "data-x-")。
	AlpinePrefixes []string
}

var htmxModifierSuffixes = []string{":inherited", ":append", "-inherited", "-append"}

// Normalize は属性名を小文字化し、接頭辞を hx- / x- に揃え、継承修飾子を取り除く。
func (n AttrNormalizer) Normalize(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = replacePrefix(s, append([]string{"data-hx-"}, n.HTMXPrefixes...), "hx-")
	s = replacePrefix(s, n.AlpinePrefixes, "x-")
	if strings.HasPrefix(s, "hx-") {
		// 修飾子は重ねられる (hx-include:inherited:append) ので、なくなるまで剥がす。
		for trimmed := true; trimmed; {
			trimmed = false
			for _, suf := range htmxModifierSuffixes {
				if len(s) > len("hx-")+len(suf) && strings.HasSuffix(s, suf) {
					s = strings.TrimSuffix(s, suf)
					trimmed = true
				}
			}
		}
	}
	return s
}

func replacePrefix(s string, prefixes []string, to string) string {
	for _, p := range prefixes {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" && p != to && strings.HasPrefix(s, p) {
			return to + strings.TrimPrefix(s, p)
		}
	}
	return s
}

// classifyAttr は正規化済みの属性名を分類する。
//
// htmx と Alpine については「危険な属性を列挙する」のではなく「安全な属性を列挙する」。
// 列挙から漏れた属性は検知側 (Alpine は attrJSEval、htmx は attrUnvetted) に倒れるので、
// ライブラリのバージョンアップで属性が増えても黙って見逃すことがない。
func classifyAttr(name string) attrClass {
	switch {
	case isEventHandlerAttr(name):
		return attrJSEval
	case strings.HasPrefix(name, "@"), strings.HasPrefix(name, ":"):
		// Alpine の x-on:* / x-bind:* の短縮形
		return attrJSEval
	case strings.HasPrefix(name, "x-"):
		return classifyAlpine(name)
	case strings.HasPrefix(name, "hx-"):
		return classifyHTMX(strings.TrimPrefix(name, "hx-"))
	}
	return attrOther
}

// isEventHandlerAttr は HTML のイベントハンドラ属性 (onclick, onerror, ...) か判定する。
func isEventHandlerAttr(name string) bool {
	if len(name) <= 2 || !strings.HasPrefix(name, "on") {
		return false
	}
	for _, r := range name[2:] {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// Alpine で値を JavaScript として評価しないディレクティブ。これ以外の x-* は評価するものとして扱う。
//
//	x-cloak:      値なし
//	x-ref:        参照名
//	x-transition: CSS クラス名 (x-transition:enter="..." など)
//	x-ignore:     値なし
//	x-teleport:   CSS セレクタ
//	x-collapse:   値なし (Collapse プラグイン)
var alpineNonEvalDirectives = map[string]bool{
	"cloak":      true,
	"ref":        true,
	"transition": true,
	"ignore":     true,
	"teleport":   true,
	"collapse":   true,
}

func classifyAlpine(name string) attrClass {
	// x-mask="99/99" はパターン文字列だが、x-mask:dynamic は式を評価する (Mask プラグイン)。
	if name == "x-mask" {
		return attrSafe
	}
	directive := strings.TrimPrefix(name, "x-")
	if i := strings.IndexAny(directive, ":."); i >= 0 {
		directive = directive[:i]
	}
	if alpineNonEvalDirectives[directive] {
		return attrSafe
	}
	return attrJSEval
}

var (
	// 値が常に JavaScript として評価される htmx 属性。
	//   trigger: イベントフィルタ click[expr] の中身を評価する
	//   vars:    htmx 2 の旧属性 (htmx 4 で削除)。値をそのまま評価する
	htmxJSEval = map[string]bool{
		"trigger": true,
		"vars":    true,
	}
	// 値が "js:" / "javascript:" で始まると評価される htmx 属性。
	//   confirm: htmx 4 から js: を受け付ける
	//   request: htmx 2 の旧属性 (htmx 4 で hx-config に置き換え)
	htmxJSEvalPrefixed = map[string]bool{
		"vals":    true,
		"headers": true,
		"confirm": true,
		"request": true,
	}
	// リクエスト先や履歴に積まれる URL になる htmx 属性。
	//   query:  htmx 4 の QUERY メソッド
	//   action: htmx 4 の hx-action (hx-method と組み合わせる)
	htmxRequestURL = map[string]bool{
		"get":         true,
		"post":        true,
		"put":         true,
		"patch":       true,
		"delete":      true,
		"query":       true,
		"action":      true,
		"push-url":    true,
		"replace-url": true,
	}
	// 値が評価されないことを確認済みの htmx 属性。
	// CSS セレクタを受け取る属性 (target, include, select, indicator, disable, sync ...) は
	// セレクタ注入でも XSS には至らず、"#row-" + id のような動的値が日常的なので安全側に置く。
	htmxSafe = map[string]bool{
		"swap":                true,
		"swap-oob":            true,
		"target":              true,
		"include":             true,
		"select":              true,
		"select-oob":          true,
		"indicator":           true,
		"disable":             true,
		"disabled-elt":        true,
		"ignore":              true,
		"sync":                true,
		"boost":               true,
		"encoding":            true,
		"preserve":            true,
		"validate":            true,
		"history":             true,
		"history-elt":         true,
		"prompt":              true,
		"inherit":             true,
		"disinherit":          true,
		"params":              true,
		"morph-skip":          true,
		"morph-skip-children": true,
	}
)

func classifyHTMX(rest string) attrClass {
	// hx-on (htmx 4 の拡張形式), hx-on:<event>, hx-on::<event>, hx-on-<event> / hx-on--<event> (htmx 2)
	if rest == "on" || strings.HasPrefix(rest, "on:") || strings.HasPrefix(rest, "on-") {
		return attrJSEval
	}
	switch {
	case htmxJSEval[rest]:
		return attrJSEval
	case htmxJSEvalPrefixed[rest]:
		return attrJSEvalPrefixed
	case htmxRequestURL[rest]:
		return attrRequestURL
	case htmxSafe[rest]:
		return attrSafe
	}
	// hx-config, hx-status:*, hx-method, hx-ext や未知の属性
	return attrUnvetted
}

// templ が自動で URL サニタイズする (javascript: などを潰す) 要素と属性の組。
// templ の generator.isExpressionAttributeValueURL と同じ集合。
var templSanitizedURLAttrs = map[string]string{
	"a":      "href",
	"link":   "href",
	"form":   "action",
	"object": "data",
}

// isUnsanitizedURLAttr は、templ が URL サニタイズしないのに javascript: URL や
// 攻撃者のスクリプトを実行し得る属性かを判定する。name は小文字化済み。
func isUnsanitizedURLAttr(element, name string) bool {
	if templSanitizedURLAttrs[element] == name {
		return false
	}
	switch name {
	case "href", "xlink:href":
		// area, base, SVG の <use>/<image> など a/link 以外の href
		return true
	case "formaction":
		return true
	case "src":
		switch element {
		case "iframe", "frame", "embed", "script":
			return true
		}
	}
	return false
}

// 抑制ディレクティブ: templ-lint:ignore <rule>[,<rule>...] <理由>
// 理由の記述は必須 (書けない抑制は大抵安全でないため)。
var ignoreDirectivePattern = regexp.MustCompile(
	`templ-lint:ignore\s+([a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*)(?:\s+(\S.*))?`)

// templ のエスケープ / サニタイズをバイパスする関数。非リテラル引数は XSS リスク。
//
//	SafeCSS / SafeCSSProperty: style 属性の CSS サニタイズを無効化する
var escapeBypassFuncs = map[string]bool{
	"Raw":              true,
	"SafeURL":          true,
	"JSExpression":     true,
	"JSUnsafeFuncCall": true,
	"SafeCSS":          true,
	"SafeCSSProperty":  true,
}
