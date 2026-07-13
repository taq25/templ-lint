// templ-lint: a-h/templ の .templ ファイルを parser/v2 で直接解析し、
// htmx / Alpine.js 利用時に XSS へつながる危険な記述を検出するリンタ。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/taq25/templ-lint/internal/lint"
)

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }

func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		format     string
		strict     bool
		sanitizers stringsFlag
	)
	flag.StringVar(&format, "format", "text", "output format: text | json")
	flag.BoolVar(&strict, "strict", false, "treat WARNING findings as failures too")
	flag.Var(&sanitizers, "allow-sanitizer",
		"sanitizer allowed as templ.Raw argument in pkg.Func form (e.g. sanitize.HTML); repeatable")
	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	l := &lint.Linter{AllowedSanitizers: sanitizers}
	findings, err := l.LintPaths(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "templ-lint: %v\n", err)
		return 2
	}

	switch format {
	case "json":
		if findings == nil {
			findings = []lint.Finding{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			fmt.Fprintf(os.Stderr, "templ-lint: %v\n", err)
			return 2
		}
	default:
		for _, f := range findings {
			fmt.Fprintf(os.Stdout, "%s:%d:%d: [%s] %s: %s\n",
				f.File, f.Line, f.Col, f.Severity, f.Rule, f.Message)
		}
		fmt.Fprintf(os.Stdout, "%d findings\n", len(findings))
	}

	for _, f := range findings {
		if f.Severity == lint.SeverityError || strict {
			return 1
		}
	}
	return 0
}
