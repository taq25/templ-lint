# Security Policy

## Reporting a Vulnerability

templ-lint is a security tool, so a bug here can give users false confidence.
The two failure modes we care about most:

- **False negative** — a dangerous pattern that templ-lint should flag but does
  not (e.g. an htmx/Alpine attribute or a `templ.Raw` bypass that slips
  through). This is the highest-severity class: a user relies on the linter and
  ships XSS.
- **Sanitizer allowlist bypass** — a code shape that the `-allow-sanitizer`
  logic accepts as "sanitized" when it does not guarantee sanitization.

Please report these privately rather than opening a public issue:

1. Use GitHub's **"Report a vulnerability"** button under the repository's
   **Security** tab (private advisory), or
2. email the maintainer.

Include a minimal `.templ` snippet that reproduces the miss, the version of
templ-lint (`templ-lint -version`), and the templ version in your `go.mod`.

We aim to acknowledge reports within a week.

## Scope

In scope:

- Missed detections (false negatives) in any rule.
- `-allow-sanitizer` accepting an unsafe shape.
- Crashes or panics on valid `.templ` input.

Out of scope (by design — see the README "Limitations"):

- Vulnerabilities in handler logic not visible in `.templ` files (SQL
  injection, authn/authz, CSRF token validation).
- False positives — these are correctness/UX issues; open a normal issue.
- Findings that require runtime hardening the README already recommends (CSP,
  Alpine CSP build, SRI). templ-lint reports; it does not enforce at runtime.

## Supported Versions

Only the latest tagged release receives fixes. Pin a version tag in CI and
upgrade deliberately, since new rules can newly fail your pipeline.
