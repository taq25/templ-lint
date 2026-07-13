// templ-lint: a-h/templ の .templ ファイルを parser/v2 で直接解析し、
// htmx / Alpine.js 利用時に XSS へつながる危険な記述を検出するリンタ。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/taq25/templ-lint/internal/lint"
)

// version はリリース時に -ldflags "-X main.version=v0.2.0" で埋め込まれる。
var version = "dev"

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }

func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run はテスト可能なエントリポイント。引数・出力先を受け取り、終了コードを返す。
// グローバルな flag 状態には触れず、独自の FlagSet を使う。
func run(args []string, stdout, stderr io.Writer) int {
	var (
		format      string
		strict      bool
		showVersion bool
		sanitizers  stringsFlag
	)
	fs := flag.NewFlagSet("templ-lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&format, "format", "text", "output format: text | json")
	fs.BoolVar(&strict, "strict", false, "treat WARNING findings as failures too")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.Var(&sanitizers, "allow-sanitizer",
		"sanitizer allowed as templ.Raw argument in pkg.Func form (e.g. sanitize.HTML); repeatable")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if showVersion {
		fmt.Fprintf(stdout, "templ-lint %s\n", version)
		return 0
	}

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	l := &lint.Linter{AllowedSanitizers: sanitizers}
	findings, err := l.LintPaths(paths)
	if err != nil {
		fmt.Fprintf(stderr, "templ-lint: %v\n", err)
		return 2
	}

	switch format {
	case "json":
		if findings == nil {
			findings = []lint.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			fmt.Fprintf(stderr, "templ-lint: %v\n", err)
			return 2
		}
	default:
		for _, f := range findings {
			fmt.Fprintf(stdout, "%s:%d:%d: [%s] %s: %s\n",
				f.File, f.Line, f.Col, f.Severity, f.Rule, f.Message)
		}
		fmt.Fprintf(stdout, "%d findings\n", len(findings))
	}

	for _, f := range findings {
		if f.Severity == lint.SeverityError || strict {
			return 1
		}
	}
	return 0
}
