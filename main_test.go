package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -update を付けて実行すると golden ファイルを現在の出力で更新する:
//
//	go test -run TestCLI -update ./...
var update = flag.Bool("update", false, "update golden files")

// golden テスト: CLI の実出力を testdata/golden/*.txt と突き合わせる。
// フラグ解析・出力形式・件数表示・終了コードの契約をまとめて固定する。
func TestCLIGolden(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantExit int
	}{
		{
			name:     "text_dangerous",
			args:     []string{"-allow-sanitizer", "sanitize.HTML", "testdata/dangerous.templ"},
			wantExit: 1, // ERROR を含む
		},
		{
			name:     "text_safe",
			args:     []string{"-allow-sanitizer", "sanitize.HTML", "testdata/safe.templ"},
			wantExit: 0, // 検出なし
		},
		{
			name:     "text_elements",
			args:     []string{"testdata/elements.templ"},
			wantExit: 0, // WARNING のみ → 既定では成功
		},
		{
			name:     "strict_elements",
			args:     []string{"-strict", "testdata/elements.templ"},
			wantExit: 1, // -strict で WARNING も失敗
		},
		{
			name:     "json_dangerous",
			args:     []string{"-format", "json", "-allow-sanitizer", "sanitize.HTML", "testdata/dangerous.templ"},
			wantExit: 1,
		},
		{
			name:     "sarif_elements",
			args:     []string{"-format", "sarif", "testdata/elements.templ"},
			wantExit: 0,
		},
		{
			name:     "version",
			args:     []string{"-version"},
			wantExit: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(c.args, &stdout, &stderr)

			if got != c.wantExit {
				t.Errorf("exit code = %d, want %d (stderr: %s)", got, c.wantExit, stderr.String())
			}

			golden := filepath.Join("testdata", "golden", c.name+".txt")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, stdout.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden (run with -update to create): %v", err)
			}
			if stdout.String() != string(want) {
				t.Errorf("stdout mismatch for %s.\n--- got ---\n%s\n--- want ---\n%s",
					c.name, stdout.String(), string(want))
			}
		})
	}
}

// -version の出力に埋め込みバージョンが反映されることを個別に検証する。
func TestVersionInjection(t *testing.T) {
	orig := version
	version = "v9.9.9-test"
	defer func() { version = orig }()

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if stdout.String() != "templ-lint v9.9.9-test\n" {
		t.Errorf("version output = %q", stdout.String())
	}
}

// 存在しないパスは実行エラー (終了コード 2) を返す。
func TestUnknownPathExits2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"testdata/does-not-exist"}, &stdout, &stderr); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Error("expected an error message on stderr")
	}
}

// -htmx-prefix で指定した接頭辞の属性も hx- として検査する。
func TestHTMXPrefixFlag(t *testing.T) {
	dir := t.TempDir()
	src := "package p\n\ntempl P(u string) {\n\t<div data-boost-vals={ u }>x</div>\n}\n"
	file := filepath.Join(dir, "p.templ")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{file}, &stdout, &stderr); code != 0 {
		t.Errorf("without -htmx-prefix: exit = %d, want 0\n%s", code, stdout.String())
	}
	stdout.Reset()
	if code := run([]string{"-htmx-prefix", "data-boost-", file}, &stdout, &stderr); code != 1 {
		t.Errorf("with -htmx-prefix: exit = %d, want 1\n%s", code, stdout.String())
	}
}

// -htmx は 2 か 4 だけを受け付ける。
func TestHTMXVersionFlagValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-htmx", "3", "testdata/safe.templ"}, &stdout, &stderr); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	stderr.Reset()
	if code := run([]string{"-htmx", "4", "-allow-sanitizer", "sanitize.HTML", "testdata/safe.templ"}, &stdout, &stderr); code != 0 {
		t.Errorf("exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
}

func TestCSPFlagValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-csp", "lax", "testdata/safe.templ"}, &stdout, &stderr); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	stdout.Reset()
	stderr.Reset()
	// CSP の互換性の検査は警告なので、-strict がなければ終了コードは 0
	if code := run([]string{"-csp", "strict", "-allow-sanitizer", "sanitize.HTML", "testdata/safe.templ"}, &stdout, &stderr); code != 0 {
		t.Errorf("exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "csp-inline-handler") {
		t.Errorf("expected csp-inline-handler warning, got:\n%s", stdout.String())
	}
}

func TestFormatFlagValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-format", "xml", "testdata/safe.templ"}, &stdout, &stderr); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

// SARIF の結果がルール一覧を正しく指し、パスが %SRCROOT% からの相対 URI になる。
func TestSARIFOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-format", "sarif", "-allow-sanitizer", "sanitize.HTML", "./testdata/dangerous.templ"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr.String())
	}
	var log sarifLog
	if err := json.Unmarshal(stdout.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("unexpected log: %+v", log)
	}
	sr := log.Runs[0]
	if len(sr.Results) == 0 {
		t.Fatal("no results")
	}
	for _, r := range sr.Results {
		if sr.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex %d does not point to %s", r.RuleIndex, r.RuleID)
		}
		loc := r.Locations[0].PhysicalLocation.ArtifactLocation
		if loc.URI != "testdata/dangerous.templ" || loc.URIBaseID != "%SRCROOT%" {
			t.Errorf("unexpected location %+v", loc)
		}
	}
}
