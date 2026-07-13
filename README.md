# templ-lint

[![CI](https://github.com/taq25/templ-lint/actions/workflows/ci.yaml/badge.svg)](https://github.com/taq25/templ-lint/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A security linter for [a-h/templ](https://github.com/a-h/templ) templates.
It parses `.templ` files directly with templ's official `parser/v2` and detects
patterns that lead to XSS when templ is combined with **htmx** and **Alpine.js**.

日本語ドキュメントは [docs/README.ja.md](docs/README.ja.md) を参照してください。

## Why

templ HTML-escapes all interpolated text and attribute values. That is not
enough when the frontend reads behavior from attributes:

```
<div x-init={ userInput }>
```

Alpine.js **evaluates the attribute value as JavaScript**. The value is
HTML-escaped by templ, but escaping does not matter — Alpine reads the string
back from the DOM and executes it. The same applies to `hx-on:*`, `hx-vals`
(`js:` prefix), and plain HTML `on*` handlers.

This class of bug is invisible to existing tools: golangci-lint and gosec skip
generated code and do not know templ's semantics, and templ's own LSP checks
syntax only. templ-lint fills that gap. Findings point at the `.templ` source
line, not at generated Go code.

Beyond XSS, templ-lint also flags a few non-XSS issues that are visible in the
template structure: reverse tabnabbing (`target="_blank"` without
`rel="noopener"`) and missing Subresource Integrity on cross-origin scripts and
stylesheets. Vulnerabilities that live in handler logic (SQL injection, auth,
CSRF token validation) are out of scope — they are not visible in a `.templ`
file.

## Install

```bash
go install github.com/taq25/templ-lint@latest
```

Or download a binary from [Releases](https://github.com/taq25/templ-lint/releases).

## Usage

```bash
# Lint all *.templ files under ./views (recursive)
templ-lint ./views

# Allow your project's sanitizer wrapper as a templ.Raw argument
templ-lint -allow-sanitizer sanitize.HTML ./views

# JSON output; treat warnings as failures
templ-lint -format json -strict ./views
```

| Flag | Description |
|---|---|
| `-allow-sanitizer pkg.Func` | Allow `templ.Raw(pkg.Func(x))` etc. Repeatable. |
| `-format text\|json` | Output format (default `text`). |
| `-strict` | Exit non-zero on WARNING findings too. |
| `-version` | Print version and exit. |

Exit codes: `0` no findings / `1` findings (ERROR always; WARNING only with
`-strict`) / `2` execution error.

## Rules

| Rule | What it catches | Severity |
|---|---|---|
| `js-eval-attr` | Dynamic values in attributes that are evaluated as JavaScript: HTML `on*`; Alpine `x-data`, `x-init`, `x-html`, `x-text`, `x-show`, `x-if`, `x-for`, `x-effect`, `x-on:*`, `@*`, `:*`, `x-model*`; htmx `hx-on:*`, `hx-vals`, `hx-headers` | ERROR |
| `escape-bypass` | Non-literal arguments to `templ.Raw`, `templ.SafeURL`, `templ.JSExpression`, `templ.JSUnsafeFuncCall` — including inside `{{ ... }}` Go code blocks | ERROR |
| `dyn-attr-name` | Dynamic attribute names (`{ name }={ value }`): an attacker-controlled name can become an event handler | ERROR |
| `url-attr` | Dynamic request targets (`hx-get/post/put/patch/delete`) | WARNING |
| `spread-attr` | Spread attributes (`{ attrs... }`): names and values are decided at runtime | WARNING |
| `unsafe-target-blank` | `target="_blank"` without `rel="noopener"` — reverse tabnabbing (CWE-1022) | WARNING |
| `missing-sri` | Cross-origin `<script>` / `<link rel=stylesheet>` without an `integrity` attribute — supply-chain risk (CWE-353) | WARNING |
| `invalid-ignore` | `templ-lint:ignore` directive without a reason | WARNING |

### Examples

```
// NG: evaluated as JavaScript by Alpine even though templ escapes it
<div x-init={ userInput }>

// OK: static expression
<div x-data="{ open: false }">

// OK: pass data as JSON via a data-* attribute, read it from Alpine
<div data-cfg={ templ.JSONString(cfg) } x-data="{ cfg: JSON.parse($el.dataset.cfg) }">
```

```
// NG: bypasses escaping with a non-literal value
@templ.Raw(userHTML)

// OK: static literal
@templ.Raw("<hr/>")

// OK: sanitized via a bluemonday policy chain (always allowed)
@templ.Raw(bluemonday.UGCPolicy().Sanitize(userHTML))

// OK with -allow-sanitizer sanitize.HTML: your audited wrapper
@templ.Raw(sanitize.HTML(userHTML))
```

The recommended wrapper keeps the bluemonday policy in one reviewable place.
A complete, compiling, tested reference lives in
[examples/sanitize](examples/sanitize/sanitize.go); the essence is:

```go
// internal/sanitize/sanitize.go
package sanitize

import "github.com/microcosm-cc/bluemonday"

// Built once, reused; bluemonday policies are safe for concurrent use.
// UGCPolicy allows common formatting tags while stripping <script>, event
// handler attributes, and javascript: URLs.
var ugc = bluemonday.UGCPolicy()

func HTML(unsafe string) string { return ugc.Sanitize(unsafe) }
```

Do **not** blanket-allow `hx-*` / `x-*` attributes in the policy for
user-authored HTML — the frontend executes them, which would reintroduce the
exact XSS this linter prevents. The linter checks the *shape*
`templ.Raw(sanitize.HTML(x))`; it does **not** verify the policy is correct —
that is what this wrapper and its tests are for.

Note: `p.Sanitize(x)` on a stored policy variable is **not** allowed — the AST
cannot verify that `p` is a bluemonday policy, and allowing any method named
`Sanitize` would be a loophole. Use the chain form or a wrapper.

## Suppressing a finding

When a finding is a false positive, suppress it with a comment on the same or
previous line. **A reason is required**; a directive without one is reported
as `invalid-ignore` and has no effect.

```
// templ-lint:ignore js-eval-attr preset is chosen from a server-side enum, never user input
<div x-init={ preset }>
```

HTML comments work too: `<!-- templ-lint:ignore js-eval-attr <reason> -->`.
Multiple rules can be listed separated by commas.

## CI

```yaml
- uses: actions/setup-go@v5
  with:
    go-version-file: go.mod
- run: go run github.com/taq25/templ-lint@latest -allow-sanitizer sanitize.HTML ./views
```

Pin a version tag instead of `@latest` in CI: new lint rules are effectively
breaking changes for your pipeline.

## How it works

templ-lint combines two official parsers instead of implementing its own:

1. templ's `parser/v2` parses the `.templ` file. Its AST distinguishes static
   (`ConstantAttribute`) from dynamic (`ExpressionAttribute`) values by type,
   and keeps Go expressions as positioned strings.
2. Each embedded Go expression is parsed with the standard `go/parser`, so
   `templ.Raw(...)` arguments are analyzed on a real Go AST (literal detection,
   sanitizer allowlist).

Because it links against the same parser the templ compiler uses, a templ
upgrade that changes the AST fails loudly at compile time — there is no silent
false-negative mode. Keep the `templ` version in this module's `go.mod` aligned
with your application's.

## Limitations

- Only `.templ` files are scanned. `templ.Raw` calls in handwritten `.go`
  files are out of scope (pair with a Go-side linter if you need that).
- No taint tracking: any non-literal argument to `templ.Raw` is flagged unless
  it matches the sanitizer allowlist, even if it was sanitized elsewhere.
- Static analysis cannot see runtime values; combine with runtime hardening:
  the [Alpine.js CSP build](https://alpinejs.dev/advanced/csp), a CSP header
  without `unsafe-eval`, and `htmx.config.allowEval = false` /
  `htmx.config.selfRequestsOnly = true`.

## Development

```bash
go test ./...              # unit tests + CLI golden tests
go test -update ./...      # regenerate testdata/golden/*.txt after intended output changes
go build .
```

CLI output is covered by golden tests: the real output is compared against
stored files in `testdata/golden/`. When you intentionally change a message or
format, rerun with `-update` and review the diff before committing.

## License

[MIT](LICENSE)
