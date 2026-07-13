package lint

import "regexp"

// Alpine.js / htmx / 素の HTML が属性値の文字列をそのまま JavaScript として
// 評価する属性。これらに動的な値を渡すと、templ の HTML エスケープでは
// XSS を防げない。
//
//	HTML:   on* (onclick, onerror などのイベントハンドラ属性)
//	Alpine: x-data, x-init, x-html, x-text, x-show, x-if, x-for, x-effect,
//	        x-on:* / @* (イベント), x-bind:* / :* (バインド), x-model*
//	htmx:   hx-on:* (JS 実行), hx-vals / hx-headers (js: プレフィックスで JS 実行)
var jsEvalAttrPattern = regexp.MustCompile(
	`^(on[a-z]+|x-(data|init|html|text|show|if|for|effect|on:.+|bind:.+|model.*)|@.+|:.+|hx-on:.+|hx-vals|hx-headers)$`)

// 抑制ディレクティブ: templ-lint:ignore <rule>[,<rule>...] <理由>
// 理由の記述は必須 (書けない抑制は大抵安全でないため)。
var ignoreDirectivePattern = regexp.MustCompile(
	`templ-lint:ignore\s+([a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*)(?:\s+(\S.*))?`)

// リクエスト先 URL になる htmx 属性。動的値は許可リスト検証をサーバ側で行うべき。
var urlAttrPattern = regexp.MustCompile(`^hx-(get|post|put|patch|delete)$`)

// templ のエスケープをバイパスする関数。非リテラル引数は XSS リスク。
var escapeBypassFuncs = map[string]bool{
	"Raw":              true,
	"SafeURL":          true,
	"JSExpression":     true,
	"JSUnsafeFuncCall": true,
}
