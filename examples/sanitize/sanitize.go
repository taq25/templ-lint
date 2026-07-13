// Package sanitize is a reference implementation of the sanitizer wrapper that
// templ-lint's -allow-sanitizer flag is designed around. Copy it into your
// project (e.g. internal/sanitize) and run the linter with:
//
//	templ-lint -allow-sanitizer sanitize.HTML ./views
//
// The point of a wrapper is to keep the bluemonday policy in exactly one
// reviewable place. Everywhere else you write templ.Raw(sanitize.HTML(x)),
// and templ-lint verifies that shape statically. It does NOT verify that the
// policy is correct — that is what this package and its tests are for.
package sanitize

import "github.com/microcosm-cc/bluemonday"

// ugc is built once and reused. bluemonday policies are safe for concurrent
// use, so a single package-level value is both correct and efficient.
//
// UGCPolicy ("user generated content") allows common formatting tags
// (p, b, i, a, ul, code, ...) while stripping <script>, event handler
// attributes (onclick, ...), and dangerous URL schemes (javascript:). It is
// the right starting point for rendering rich text authored by users, such as
// comments or Markdown output.
var ugc = func() *bluemonday.Policy {
	p := bluemonday.UGCPolicy()
	// Allowlist the attributes htmx/Alpine need only if your rendered content
	// legitimately contains them. Do NOT blanket-allow hx-* or x-* on
	// user-authored HTML: those attributes are executed by the frontend and
	// would reintroduce the exact XSS templ-lint is trying to prevent.
	return p
}()

// HTML sanitizes untrusted HTML for safe inclusion via templ.Raw.
// The output is HTML with all disallowed tags, attributes, and URL schemes
// removed according to the UGC policy above.
func HTML(unsafe string) string {
	return ugc.Sanitize(unsafe)
}

// strict removes ALL HTML, leaving only text content. Use Text when you want
// to neutralize markup entirely (and could not simply rely on templ's default
// escaping for some reason).
var strict = bluemonday.StrictPolicy()

// Text strips every tag and returns plain text. Prefer templ's default
// escaping ({ value }) over this; Text exists for the rare case where you hold
// a pre-built HTML string that must be flattened.
func Text(unsafe string) string {
	return strict.Sanitize(unsafe)
}
