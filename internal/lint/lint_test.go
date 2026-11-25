package lint

import (
	"os"
	"regexp"
	"strings"
	"testing"

	parser "github.com/a-h/templ/parser/v2"
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

func TestURLAttrRelativeExclusion(t *testing.T) {
	l := &Linter{}
	findings, err := l.LintFile("../../testdata/urlattr.templ")
	if err != nil {
		t.Fatalf("LintFile failed: %v", err)
	}
	got := 0
	for _, f := range findings {
		if f.Rule == RuleURLAttr {
			got++
		}
	}
	// 検知されるのは: base+"/x", "//evil"+userURL, userURL の 3 件。
	// 除外されるのは: "/?page="+strconv, "/items" の 2 件。
	if got != 3 {
		t.Errorf("url-attr findings: got %d, want 3", got)
		for _, f := range findings {
			t.Logf("  %s:%d [%s] %s", f.File, f.Line, f.Rule, f.Message)
		}
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
	// dangerous: 12, safe: 0, suppressed: 2, elements: 3, urlattr: 3,
	// evasion: 32 (data-x-init は -alpine-prefix なしでは対象外)
	if len(findings) != 52 {
		t.Errorf("total findings from directory walk: got %d, want 52", len(findings))
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

// evasion.templ は過去に見逃していた書き方の回帰テスト。
// 各行末のコメントに期待するルールを書き、その行で 1 件だけ検出されることを確かめる。
func TestEvasionRegression(t *testing.T) {
	const path = "../../testdata/evasion.templ"
	l := &Linter{AlpinePrefixes: []string{"data-x-"}}
	findings, err := l.LintFile(path)
	if err != nil {
		t.Fatalf("LintFile failed: %v", err)
	}
	want := expectedRulesByLine(t, path)
	got := map[uint32][]string{}
	for _, f := range findings {
		got[f.Line] = append(got[f.Line], f.Rule)
	}
	for line, rule := range want {
		if len(got[line]) != 1 || got[line][0] != rule {
			t.Errorf("line %d: got %v, want [%s]", line, got[line], rule)
		}
	}
	for line, rules := range got {
		if _, ok := want[line]; !ok {
			t.Errorf("line %d: unexpected findings %v", line, rules)
		}
	}
}

// expectedRulesByLine は「// <rule>」で終わる行を集める。
// 複数行にまたがる要素 (条件付き属性) は、検出位置の行にコメントを書けないので
// 「>conditional</div> // rule」の直前の属性行を期待位置として扱う。
func expectedRulesByLine(t *testing.T, path string) map[uint32]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ruleComment := regexp.MustCompile(`//\s*([a-z-]+)\s*$`)
	want := map[uint32]string{}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		m := ruleComment.FindStringSubmatch(line)
		if m == nil || !knownRules[m[1]] {
			continue
		}
		n := uint32(i + 1)
		if strings.HasPrefix(strings.TrimSpace(line), ">") {
			// 条件付き属性: 属性は 2 行上 (属性 → } → >)
			n -= 2
		}
		want[n] = m[1]
	}
	if len(want) == 0 {
		t.Fatal("no expectations found")
	}
	return want
}

var knownRules = map[string]bool{
	RuleJSEvalAttr: true, RuleURLAttr: true, RuleSpreadAttr: true, RuleEscapeBypass: true,
	RuleDynAttrName: true, RuleTabnabbing: true, RuleMissingSRI: true, RuleInvalidIgnore: true,
	RuleUnvettedAttr: true, RuleUnsafeURLAttr: true, RuleSrcdocAttr: true,
}

func TestNormalize(t *testing.T) {
	n := AttrNormalizer{HTMXPrefixes: []string{"data-boost-"}, AlpinePrefixes: []string{"data-x-"}}
	cases := map[string]string{
		"onClick":                       "onclick",
		"data-hx-on:click":              "hx-on:click",
		"DATA-HX-VALS":                  "hx-vals",
		"data-boost-get":                "hx-get",
		"data-x-init":                   "x-init",
		"data-x-data":                   "x-data",
		"hx-vals:inherited":             "hx-vals",
		"hx-include:inherited:append":   "hx-include",
		"hx-confirm-inherited":          "hx-confirm",
		"hx-on::before:request":         "hx-on::before:request",
		"data-id":                       "data-id",
		"x-transition:enter.duration.5": "x-transition:enter.duration.5",
	}
	for in, want := range cases {
		if got := n.Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyAttr(t *testing.T) {
	cases := map[string]attrClass{
		"onclick":               attrJSEval,
		"one":                   attrJSEval, // on + 英字は全てイベントハンドラ扱い (安全側)
		"on":                    attrOther,
		"on-x":                  attrOther,
		"@click.prevent":        attrJSEval,
		":class":                attrJSEval,
		"x-data":                attrJSEval,
		"x-bind":                attrJSEval,
		"x-new-directive":       attrJSEval, // 未知の Alpine ディレクティブは評価する扱い
		"x-cloak":               attrSafe,
		"x-transition:enter":    attrSafe,
		"x-mask":                attrSafe,
		"x-mask:dynamic":        attrJSEval,
		"hx-on":                 attrJSEval,
		"hx-on:click":           attrJSEval,
		"hx-on::before:request": attrJSEval,
		"hx-on-click":           attrJSEval,
		"hx-on--after-request":  attrJSEval,
		"hx-trigger":            attrJSEval,
		"hx-vals":               attrJSEvalPrefixed,
		"hx-confirm":            attrJSEvalPrefixed,
		"hx-get":                attrRequestURL,
		"hx-action":             attrRequestURL,
		"hx-query":              attrRequestURL,
		"hx-target":             attrSafe,
		"hx-config":             attrUnvetted,
		"hx-status:422":         attrUnvetted,
		"hx-something-new":      attrUnvetted, // 未知の htmx 属性は要確認扱い
		"class":                 attrOther,
		"data-id":               attrOther,
	}
	for name, want := range cases {
		if got := classifyAttr(name); got != want {
			t.Errorf("classifyAttr(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestHasNonScriptLiteralPrefix(t *testing.T) {
	cases := map[string]bool{
		`"Delete " + name`:   true,
		`"{\"id\": " + id`:   true,
		`name`:               false,
		`"" + name`:          false,
		`"  " + name`:        false,
		`"js:" + name`:       false,
		`" JavaScript:" + x`: false,
		`"j" + rest`:         false, // 続きで js: になり得る
		`"javas" + rest`:     false,
	}
	for src, want := range cases {
		if got := hasNonScriptLiteralPrefix(parser.Expression{Value: src}); got != want {
			t.Errorf("hasNonScriptLiteralPrefix(%s) = %v, want %v", src, got, want)
		}
	}
}
