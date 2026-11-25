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

# Go-style recursive path; SARIF for GitHub code scanning
templ-lint -format sarif ./... > templ-lint.sarif
```

Directories are walked recursively (`./...` works too). `vendor`,
`node_modules` and hidden directories are skipped unless named directly. `.go`
files are read only for the `sanitizer-policy` rule (generated `*_templ.go`
and `*_test.go` are skipped).

| Flag | Description |
|---|---|
| `-allow-sanitizer pkg.Func` | Allow `templ.Raw(pkg.Func(x))` etc. Use the import path form (`example.com/app/sanitize.HTML`) to match only that package, not any package with the same name. Repeatable. |
| `-htmx-prefix prefix` | Extra prefix htmx treats as `hx-` (`htmx.config.prefix`, e.g. `data-boost-`). `data-hx-` is always recognized. Repeatable. |
| `-alpine-prefix prefix` | Extra prefix Alpine treats as `x-` (`Alpine.prefix`, e.g. `data-x-`). Not set by default, since `data-x-*` is also an ordinary data attribute. Repeatable. |
| `-htmx 2\|4` | Target htmx major version. Enables checks whose meaning differs between versions (`hx-disable` / `hx-ignore`; `hx-confirm` only evaluates `js:` in htmx 4). Unset: those checks are skipped or fail safe. |
| `-csp strict` | Assume a strict Content-Security-Policy (`script-src` without `'unsafe-inline'` / `'unsafe-eval'`) and warn about code it would silently block (`csp-*` rules). Security checks are the same with or without it. |
| `-format text\|json\|sarif` | Output format (default `text`). `sarif` is SARIF 2.1.0 for GitHub code scanning. |
| `-strict` | Exit non-zero on WARNING findings too. |
| `-version` | Print version and exit. |

Exit codes: `0` no findings / `1` findings (ERROR always; WARNING only with
`-strict`) / `2` execution error.

## Rules

| Rule | What it catches | Severity |
|---|---|---|
| `js-eval-attr` | Dynamic values in attributes that are evaluated as JavaScript: HTML `on*`; every Alpine `x-*` directive except the known non-evaluating ones (see below), plus `@*` and `:*`; htmx `hx-on` / `hx-on:*` / `hx-on::*` / `hx-on-*`, `hx-trigger` (event filters), `hx-vars`; and `hx-vals`, `hx-headers`, `hx-confirm`, `hx-request` unless the value starts with a static literal that cannot become `js:` | ERROR |
| `unsafe-url-attr` | Dynamic URLs in attributes templ does **not** sanitize: `<iframe/frame/embed/script src>`, `formaction`, `href` outside `<a>`/`<link>` (e.g. `<area>`, `<base>`, SVG), `xlink:href`. templ only sanitizes `a/link[href]`, `form[action]` and `object[data]`. Allowed: `templ.URL(x)`, same-origin relative paths | ERROR |
| `srcdoc-attr` | Dynamic `srcdoc`: the browser parses it as an HTML document. Allowed: sanitizer calls accepted by `escape-bypass` | ERROR |
| `escape-bypass` | Non-literal arguments to `templ.Raw`, `templ.SafeURL`, `templ.JSExpression`, `templ.JSUnsafeFuncCall`, `templ.SafeCSS`, `templ.SafeCSSProperty`, and `templ.ComponentScript{...}` literals — including inside `{{ ... }}` blocks and Go code outside templates, through import aliases, and when the function is used as a value (`f := templ.Raw`) | ERROR |
| `dyn-attr-name` | Dynamic attribute names (`{ name }={ value }`): an attacker-controlled name can become an event handler | ERROR |
| `url-attr` | Dynamic request targets (`hx-get/post/put/patch/delete/query`, `hx-action`) and history URLs (`hx-push-url`, `hx-replace-url`). Relative paths that are statically same-origin (a leading `"/x…"` string literal, e.g. `"/posts/" + id`) are excluded; protocol-relative `//host` and variable-built URLs are still flagged | WARNING |
| `htmx-config-meta` | Dynamic `content` in `<meta name="htmx-config">`: htmx reads global settings (prefix, extensions, request mode, ...) from it. `templ.JSONString(cfg)` is allowed | ERROR |
| `htmx-disable-semantics` | With `-htmx 4`: `hx-disable` used the htmx 2 way (no value, or around `templ.Raw` / `{ children... }`). htmx 4 renamed that behavior to `hx-ignore`; `hx-disable` now only disables elements during requests, so the content becomes live. With `-htmx 2`: `hx-ignore`, which htmx 2 does not have | ERROR |
| `unvetted-attr` | Dynamic values in htmx attributes that templ-lint has not classified (e.g. `hx-config`, `hx-status:*`, `hx-method`, attributes added by future htmx versions) | WARNING |
| `spread-attr` | Spread attributes (`{ attrs... }`): names and values are decided at runtime | WARNING |
| `unsafe-target-blank` | `target="_blank"` without `rel="noopener"` — reverse tabnabbing (CWE-1022) | WARNING |
| `missing-sri` | Cross-origin `<script>` / `<link rel=stylesheet>` without an `integrity` attribute — supply-chain risk (CWE-353) | WARNING |
| `sanitizer-policy` | bluemonday policies (in `.go` files or `.templ` Go code) that keep attributes the frontend acts on: `AllowDataAttributes()` (htmx treats `data-hx-*` as `hx-*`), `AllowAttrs("onclick" / "x-data" / "@click" / "hx-get" / "data-hx-get" ...)`, `AllowUnsafe(true)` | WARNING |
| `invalid-ignore` | `templ-lint:ignore` directive without a reason, or naming an unknown rule | WARNING |
| `unused-ignore` | `templ-lint:ignore` directive that suppresses nothing (rules that cannot fire under the current flags, such as `csp-*` without `-csp strict`, are not reported) | WARNING |

### CSP compatibility (`-csp strict`)

These rules find code that does not run under a strict CSP. They are
compatibility checks, not vulnerability checks, so they are warnings (use
`-strict` to fail on them). The security rules above are **not** relaxed when
a CSP is assumed: a CSP is a safety net that can be misconfigured or missing.
Dynamic values that already trigger a security rule are not reported again.

| Rule | Detects | Severity |
|---|---|---|
| `csp-inline-handler` | Inline event handlers (`onclick="..."`, including `templ.JSFuncCall` / `templ.ComponentScript` values) and static `javascript:` URLs. Nonces do not apply to them | WARNING |
| `csp-eval-attr` | Static htmx values that htmx runs through `eval` / `new Function`: `hx-on*`, `hx-trigger` event filters (`click[ctrlKey]`), `js:` in `hx-vals` / `hx-headers` / `hx-confirm` / `hx-request`, `hx-vars` | WARNING |
| `csp-inline-script` | Inline `<script>` without a `nonce` (templ only adds nonces to `script` templates and `templ.JSONScript`, not to plain `<script>`), and static `nonce="..."` values. Data blocks such as `type="application/json"` are ignored | WARNING |

Alpine expressions are not checked: what the Alpine CSP build accepts depends
on its version.

### Attribute name normalization

Attribute names are normalized before classification, so spelling variants do
not slip through: names are lowercased (`onClick` = `onclick`), `data-hx-*` and
the prefixes given by `-htmx-prefix` / `-alpine-prefix` are mapped to `hx-*` /
`x-*`, and htmx 4 inheritance modifiers (`:inherited`,
`:append`, and the `-inherited` / `-append` forms) are stripped.

Classification is allowlist-based within the htmx and Alpine namespaces: only
attributes known not to evaluate their value are exempt. An unknown Alpine
directive is treated as evaluating JavaScript (`js-eval-attr`), and an unknown
htmx attribute is reported as `unvetted-attr`, so new attributes in future
versions fail safe instead of being silently ignored.

- Alpine non-evaluating directives: `x-cloak`, `x-ref`, `x-transition*`,
  `x-ignore`, `x-teleport`, `x-collapse`, `x-mask` (but not `x-mask:dynamic`).
- htmx attributes treated as safe: `hx-swap`, `hx-swap-oob`, `hx-boost`,
  `hx-encoding`, `hx-preserve`, `hx-validate`, `hx-history`, `hx-history-elt`,
  `hx-prompt`, `hx-inherit`, `hx-disinherit`, `hx-params`, `hx-morph-skip*`,
  and the selector attributes `hx-target`, `hx-include`, `hx-select`,
  `hx-select-oob`, `hx-indicator`, `hx-disable`, `hx-disabled-elt`,
  `hx-ignore`, `hx-sync` (a dynamic selector cannot lead to XSS, and
  `"#row-" + id` is everyday code).

Values made only of string literals (`x-init={ "load()" }`) are exempt from
the attribute rules: they are written by the developer, like a static
attribute.

Values that cannot inject code whatever they contain are also exempt:

- `templ.JSONString(v)` in any JS-evaluating attribute except `hx-trigger`
  (JSON is data as a JavaScript expression, and never starts with `js:`).
- `templ.JSFuncCall("name", args...)` in `on*` / `hx-on:*`, where templ renders
  it as a function call with JSON-encoded arguments. The function name must be
  a string literal: templ only checks that it looks like an identifier, so a
  dynamic name could be `eval`.

```
<button onclick={ templ.JSFuncCall("select", id) }>            // OK
<div x-data={ templ.JSONString(cfg) }>                          // OK
<button data-id={ id } hx-on:click="select(this.dataset.id)">   // OK
```

Note: templ requires `templ.ComponentScript` values for attributes whose name
starts with `on` or `hx-on:`, so a plain string there does not compile. The
string-injection risk is in Alpine attributes and in htmx attributes templ does
not special-case (`hx-on-click`, `data-hx-on:click`, `hx-vals`, ...).
`templ.ComponentScript{Call: x}` built by hand is reported as `escape-bypass`.

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
that is what this wrapper and its tests are for. The `sanitizer-policy` rule
catches the common mistakes (`AllowDataAttributes()`, allowing `on*` / `x-*` /
`hx-*` attributes, `AllowUnsafe(true)`).

`-allow-sanitizer sanitize.HTML` matches any package whose local name is
`sanitize`. Prefer `-allow-sanitizer example.com/app/sanitize.HTML`, which is
checked against the file's imports. The bluemonday chain is also checked
against imports, so an aliased import (`bm "github.com/microcosm-cc/bluemonday"`)
works and an unrelated package named `bluemonday` does not.

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
Multiple rules can be listed separated by commas. Unknown rule names are
reported as `invalid-ignore`, and directives that suppress nothing as
`unused-ignore`, so stale suppressions do not pile up.

## CI

```yaml
- uses: actions/setup-go@v5
  with:
    go-version-file: go.mod
- run: go run github.com/taq25/templ-lint@latest -allow-sanitizer sanitize.HTML ./views
```

Pin a version tag instead of `@latest` in CI: new lint rules are effectively
breaking changes for your pipeline.

To show findings in GitHub code scanning, upload SARIF (the job needs
`permissions: security-events: write`):

```yaml
- run: go run github.com/taq25/templ-lint@latest -format sarif ./... > templ-lint.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: templ-lint.sarif
```

## How it works

templ-lint combines two official parsers instead of implementing its own:

1. templ's `parser/v2` parses the `.templ` file. Its AST distinguishes static
   (`ConstantAttribute`) from dynamic (`ExpressionAttribute`) values by type,
   and keeps Go expressions as positioned strings.
2. Each embedded Go expression is parsed with the standard `go/parser`, so
   `templ.Raw(...)` arguments are analyzed on a real Go AST (literal detection,
   sanitizer allowlist).

Because it links against the same parser the templ compiler uses, a templ
upgrade that changes the AST fails loudly at compile time. Keep the `templ`
version in this module's `go.mod` aligned with your application's.

That guarantee covers templ's syntax only. What an attribute *means* is decided
by htmx and Alpine, and a parser cannot see that change. The allowlist-based
classification above is what keeps new or renamed attributes from silently
passing.

## Limitations

- Only `.templ` files are scanned for XSS. `.go` files are read only for
  bluemonday policies; `templ.Raw` calls in handwritten `.go` files are out of
  scope (pair with a Go-side linter if you need that).
- No taint tracking: any non-literal argument to `templ.Raw` is flagged unless
  it matches the sanitizer allowlist, even if it was sanitized elsewhere.
- Static analysis cannot see runtime values; combine with runtime hardening:
  - A CSP header without `unsafe-eval`, and the
    [Alpine.js CSP build](https://alpinejs.dev/advanced/csp). Run with
    `-csp strict` to find templates that such a CSP would break.
  - htmx 2: `htmx.config.allowEval = false` and
    `htmx.config.selfRequestsOnly = true` (the default).
  - htmx 4: `allowEval` and `selfRequestsOnly` were removed. Requests are
    restricted by `htmx.config.mode = "same-origin"` (the default; per-element
    `hx-config` cannot override it). Eval cannot be switched off by config, so
    avoid `hx-on`, trigger filters and `js:` values under a strict CSP, or use
    the `hx-csp` extension. Restrict extensions with `htmx.config.extensions`.
  - Wrap untrusted HTML in `hx-disable` (htmx 2) / `hx-ignore` (htmx 4) as a
    second layer behind the sanitizer.

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
