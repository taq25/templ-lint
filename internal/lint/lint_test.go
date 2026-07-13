package lint

import (
	"testing"
)

func TestLintFileDangerous(t *testing.T) {
	l := &Linter{AllowedSanitizers: []string{"sanitize.HTML"}}
	findings, err := l.LintFile("../../testdata/dangerous.templ")
	if err != nil {
		t.Fatalf("LintFile failed: %v", err)
	}

	got := map[string]int{}
	for _, f := range findings {
		got[f.Rule]++
	}
	want := map[string]int{
		RuleEscapeBypass: 3, // @templ.Raw, templ.SafeURL, GoCode 内の templ.Raw
		RuleJSEvalAttr:   7, // x-data, x-init, @click, x-on:click, hx-on:click, hx-vals, onerror
		RuleURLAttr:      1, // hx-get
		RuleSpreadAttr:   1, // { attrs... }
	}
	for rule, n := range want {
		if got[rule] != n {
			t.Errorf("rule %s: got %d findings, want %d", rule, got[rule], n)
		}
	}
	if len(findings) != 12 {
		t.Errorf("total findings: got %d, want 12", len(findings))
		for _, f := range findings {
			t.Logf("  %s:%d [%s] %s", f.File, f.Line, f.Rule, f.Message)
		}
	}

	// 位置が .templ の実際の行を指すこと (@templ.Raw は 5 行目)
	for _, f := range findings {
		if f.Rule == RuleEscapeBypass && f.Line == 5 {
			return
		}
	}
	t.Errorf("expected an escape-bypass finding at line 5 (@templ.Raw)")
}

func TestLintFileSafe(t *testing.T) {
	l := &Linter{AllowedSanitizers: []string{"sanitize.HTML"}}
	findings, err := l.LintFile("../../testdata/safe.templ")
	if err != nil {
		t.Fatalf("LintFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d:", len(findings))
		for _, f := range findings {
			t.Errorf("  %s:%d [%s] %s", f.File, f.Line, f.Rule, f.Message)
		}
	}
}

func TestLintFileSafeWithoutAllowlist(t *testing.T) {
	// 許可リストなしなら sanitize.HTML 経由の templ.Raw は検出される
	l := &Linter{}
	findings, err := l.LintFile("../../testdata/safe.templ")
	if err != nil {
		t.Fatalf("LintFile failed: %v", err)
	}
	count := 0
	for _, f := range findings {
		if f.Rule == RuleEscapeBypass {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 escape-bypass finding without allowlist, got %d", count)
	}
}

func TestElementRules(t *testing.T) {
	l := &Linter{}
	findings, err := l.LintFile("../../testdata/elements.templ")
	if err != nil {
		t.Fatalf("LintFile failed: %v", err)
	}
	got := map[string]int{}
	for _, f := range findings {
		got[f.Rule]++
	}
	want := map[string]int{
		RuleTabnabbing: 1, // rel なしの target=_blank
		RuleMissingSRI: 2, // integrity なしの cross-origin script と link[stylesheet]
	}
	for rule, n := range want {
		if got[rule] != n {
			t.Errorf("rule %s: got %d findings, want %d", rule, got[rule], n)
		}
	}
	if len(findings) != 3 {
		t.Errorf("total findings: got %d, want 3", len(findings))
		for _, f := range findings {
			t.Logf("  %s:%d [%s] %s", f.File, f.Line, f.Rule, f.Message)
		}
	}
}

func TestLintPathsDirectory(t *testing.T) {
	l := &Linter{AllowedSanitizers: []string{"sanitize.HTML"}}
	findings, err := l.LintPaths([]string{"../../testdata"})
	if err != nil {
		t.Fatalf("LintPaths failed: %v", err)
	}
	// dangerous: 12, safe: 0, suppressed: 2, elements: 3
	if len(findings) != 17 {
		t.Errorf("total findings from directory walk: got %d, want 17", len(findings))
	}
}

func TestIgnoreDirective(t *testing.T) {
	l := &Linter{}
	findings, err := l.LintFile("../../testdata/suppressed.templ")
	if err != nil {
		t.Fatalf("LintFile failed: %v", err)
	}

	got := map[string]int{}
	for _, f := range findings {
		got[f.Rule]++
	}
	// 理由付きディレクティブ直後の x-init は抑制される。
	// 理由なしディレクティブは invalid-ignore として報告され、
	// 直後の x-data は抑制されない。
	want := map[string]int{
		RuleJSEvalAttr:    1,
		RuleInvalidIgnore: 1,
	}
	if len(findings) != 2 {
		t.Errorf("total findings: got %d, want 2", len(findings))
		for _, f := range findings {
			t.Logf("  %s:%d [%s] %s", f.File, f.Line, f.Rule, f.Message)
		}
	}
	for rule, n := range want {
		if got[rule] != n {
			t.Errorf("rule %s: got %d findings, want %d", rule, got[rule], n)
		}
	}
}
