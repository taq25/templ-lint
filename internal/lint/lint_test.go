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
		RuleJSEvalAttr:   6, // x-data, x-init, @click, x-on:click, hx-on:click, hx-vals
		RuleURLAttr:      1, // hx-get
		RuleSpreadAttr:   1, // { attrs... }
	}
	for rule, n := range want {
		if got[rule] != n {
			t.Errorf("rule %s: got %d findings, want %d", rule, got[rule], n)
		}
	}
	if len(findings) != 11 {
		t.Errorf("total findings: got %d, want 11", len(findings))
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

func TestLintPathsDirectory(t *testing.T) {
	l := &Linter{AllowedSanitizers: []string{"sanitize.HTML"}}
	findings, err := l.LintPaths([]string{"../../testdata"})
	if err != nil {
		t.Fatalf("LintPaths failed: %v", err)
	}
	if len(findings) != 11 {
		t.Errorf("total findings from directory walk: got %d, want 11", len(findings))
	}
}
