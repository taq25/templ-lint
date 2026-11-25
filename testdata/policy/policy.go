// Package policy は sanitizer-policy の検査用 (templ-lint の testdata。ビルドしない)。
package policy

import "github.com/microcosm-cc/bluemonday"

func UserContent() *bluemonday.Policy {
	p := bluemonday.UGCPolicy()
	p.AllowDataAttributes() // sanitizer-policy
	p.AllowAttrs("class", "title").Globally()
	p.AllowAttrs("data-hx-get").OnElements("a")  // sanitizer-policy
	p.AllowAttrs("x-data", "class").Globally()   // sanitizer-policy
	p.AllowAttrs("onClick").OnElements("button") // sanitizer-policy
	p.AllowUnsafe(true)                          // sanitizer-policy
	p.AllowUnsafe(false)
	// templ-lint:ignore sanitizer-policy data-* is required for the embed widget, output is wrapped in hx-ignore
	p.AllowDataAttributes()
	return p
}
