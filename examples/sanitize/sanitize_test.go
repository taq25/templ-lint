package sanitize

import "testing"

func TestHTMLStripsDangerousMarkup(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		mustHave   []string // 出力に残るべき部分文字列
		mustNotHav []string // 出力から除去されるべき部分文字列
	}{
		{
			name:       "script tag removed",
			in:         `<p>hi</p><script>steal()</script>`,
			mustHave:   []string{"<p>", "hi"},
			mustNotHav: []string{"<script", "steal()"},
		},
		{
			name:       "event handler attribute removed",
			in:         `<img src="/x.png" onerror="steal()">`,
			mustNotHav: []string{"onerror", "steal()"},
		},
		{
			name:       "javascript URL removed",
			in:         `<a href="javascript:steal()">click</a>`,
			mustHave:   []string{"click"},
			mustNotHav: []string{"javascript:"},
		},
		{
			name:       "safe formatting kept",
			in:         `<p><b>bold</b> and <a href="https://example.com">link</a></p>`,
			mustHave:   []string{"<b>", "bold", `href="https://example.com"`},
			mustNotHav: []string{"onerror"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := HTML(c.in)
			for _, s := range c.mustHave {
				if !contains(got, s) {
					t.Errorf("HTML(%q) = %q; want it to contain %q", c.in, got, s)
				}
			}
			for _, s := range c.mustNotHav {
				if contains(got, s) {
					t.Errorf("HTML(%q) = %q; want it NOT to contain %q", c.in, got, s)
				}
			}
		})
	}
}

func TestTextStripsAllMarkup(t *testing.T) {
	got := Text(`<p>hello <b>world</b></p>`)
	if contains(got, "<") {
		t.Errorf("Text kept markup: %q", got)
	}
	if !contains(got, "hello") || !contains(got, "world") {
		t.Errorf("Text dropped content: %q", got)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 ||
		(len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
