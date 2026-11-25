package main

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/m-mizutani/goerr/v2"
	"github.com/taq25/templ-lint/internal/lint"
)

// SARIF 2.1.0 の最小限の構造。GitHub code scanning などが読み込める。
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	ShortDescription     sarifMessage       `json:"shortDescription"`
	HelpURI              string             `json:"helpUri"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   uint32 `json:"startLine"`
	StartColumn uint32 `json:"startColumn,omitempty"`
}

const repoURL = "https://github.com/taq25/templ-lint"

func sarifLevel(s lint.Severity) string {
	if s == lint.SeverityError {
		return "error"
	}
	return "warning"
}

// sarifURI はファイルパスを SARIF の URI にする。相対パスはリポジトリのルート
// (%SRCROOT%) からの相対として扱い、GitHub code scanning がファイルに結び付けられるようにする。
func sarifURI(path string) sarifArtifactLocation {
	p := filepath.ToSlash(filepath.Clean(path))
	if filepath.IsAbs(path) {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p // Windows のドライブレター
		}
		return sarifArtifactLocation{URI: "file://" + p}
	}
	return sarifArtifactLocation{URI: strings.TrimPrefix(p, "./"), URIBaseID: "%SRCROOT%"}
}

func writeSARIF(w io.Writer, findings []lint.Finding) error {
	rules := make([]sarifRule, len(lint.Rules))
	index := make(map[string]int, len(lint.Rules))
	for i, r := range lint.Rules {
		index[r.ID] = i
		rules[i] = sarifRule{
			ID:                   r.ID,
			ShortDescription:     sarifMessage{Text: r.Description},
			HelpURI:              repoURL + "#rules",
			DefaultConfiguration: sarifConfiguration{Level: sarifLevel(r.Severity)},
		}
	}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:    f.Rule,
			RuleIndex: index[f.Rule],
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: f.Message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifURI(f.File),
				Region:           sarifRegion{StartLine: f.Line, StartColumn: f.Col},
			}}},
		})
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "templ-lint", Version: version, InformationURI: repoURL, Rules: rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return goerr.Wrap(err, "failed to encode SARIF")
	}
	return nil
}
