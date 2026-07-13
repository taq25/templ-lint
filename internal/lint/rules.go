package lint

import "regexp"

// Alpine.js / htmx が属性値の文字列をそのまま JavaScript として評価する属性。
// これらに動的な値を渡すと、templ の HTML エスケープでは XSS を防げない。
//
//	Alpine: x-data, x-init, x-html, x-text, x-show, x-if, x-for, x-effect,
//	        x-on:* / @* (イベント), x-bind:* / :* (バインド), x-model*
//	htmx:   hx-on:* (JS 実行), hx-vals / hx-headers (js: プレフィックスで JS 実行)
var jsEvalAttrPattern = regexp.MustCompile(
	`^(x-(data|init|html|text|show|if|for|effect|on:.+|bind:.+|model.*)|@.+|:.+|hx-on:.+|hx-vals|hx-headers)$`)

// リクエスト先 URL になる htmx 属性。動的値は許可リスト検証をサーバ側で行うべき。
var urlAttrPattern = regexp.MustCompile(`^hx-(get|post|put|patch|delete)$`)

// templ のエスケープをバイパスする関数。非リテラル引数は XSS リスク。
var escapeBypassFuncs = map[string]bool{
	"Raw":              true,
	"SafeURL":          true,
	"JSExpression":     true,
	"JSUnsafeFuncCall": true,
}
