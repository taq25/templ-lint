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
	// evasion: 36 (data-x-init は -alpine-prefix なしでは対象外),
	// htmx4: 2, htmx2: 1 (-htmx なしではバージョン依存の検査をしない)
	if len(findings) != 61 {
		t.Errorf("total findings from directory walk: got %d, want 61", len(findings))
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

// 行末のコメントに期待するルールを書いた testdata を、設定ごとに検査する。
// 各行で期待どおりのルールが 1 件だけ検出され、それ以外の行では何も検出されないこと。
//
//	evasion.templ: 過去に見逃していた書き方の回帰テスト
//	htmx4.templ / htmx2.templ: バージョンによって意味が変わる属性
func TestAnnotatedTestdata(t *testing.T) {
	cases := []struct {
		file   string
		linter *Linter
	}{
		{"evasion.templ", &Linter{AlpinePrefixes: []string{"data-x-"}}},
		{"htmx4.templ", &Linter{HTMXVersion: htmxVersion4, AllowedSanitizers: []string{"sanitize.HTML"}}},
		{"htmx2.templ", &Linter{HTMXVersion: htmxVersion2, AllowedSanitizers: []string{"sanitize.HTML"}}},
		{"csp.templ", &Linter{CSP: CSPStrict}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			path := "../../testdata/" + c.file
			findings, err := c.linter.LintFile(path)
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
		})
	}
}

// バージョン未指定では、バージョンによって意味が変わる検査は行わない
// (hx-disable / hx-ignore は報告しない、hx-confirm は htmx 4 の js: を想定して安全側)。
func TestHTMXVersionUnspecified(t *testing.T) {
	l := &Linter{AllowedSanitizers: []string{"sanitize.HTML"}}
	for file, want := range map[string]map[string]int{
		"htmx4.templ": {RuleHTMXConfigMeta: 1, RuleJSEvalAttr: 1},
		"htmx2.templ": {RuleJSEvalAttr: 1},
	} {
		findings, err := l.LintFile("../../testdata/" + file)
		if err != nil {
			t.Fatalf("LintFile failed: %v", err)
		}
		got := map[string]int{}
		for _, f := range findings {
			got[f.Rule]++
		}
		if len(got) != len(want) {
			t.Errorf("%s: got %v, want %v", file, got, want)
		}
		for rule, n := range want {
			if got[rule] != n {
				t.Errorf("%s: rule %s: got %d, want %d", file, rule, got[rule], n)
			}
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
	RuleHTMXConfigMeta: true, RuleHTMXDisableSemantics: true,
	RuleCSPInlineHandler: true, RuleCSPEvalAttr: true, RuleCSPInlineScript: true,
}

// -csp を指定しなければ CSP の互換性の検査は行わない (セキュリティの検査だけが残る)。
func TestCSPUnspecified(t *testing.T) {
	findings, err := (&Linter{}).LintFile("../../testdata/csp.templ")
	if err != nil {
		t.Fatalf("LintFile failed: %v", err)
	}
	got := map[string]int{}
	for _, f := range findings {
		got[f.Rule]++
	}
	want := map[string]int{RuleJSEvalAttr: 2}
	if len(got) != len(want) || got[RuleJSEvalAttr] != 2 {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestIsJavaScriptURL(t *testing.T) {
	cases := map[string]bool{
		"javascript:void(0)":  true,
		" JavaScript:x":       true,
		"java\tscript:x":      true,
		"java\nscript:x":      true,
		"/javascript:x":       false,
		"https://example.com": false,
		"#":                   false,
	}
	for in, want := range cases {
		if got := isJavaScriptURL(in); got != want {
			t.Errorf("isJavaScriptURL(%q) = %v, want %v", in, got, want)
		}
	}
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
