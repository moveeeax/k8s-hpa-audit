package report

import (
	"encoding/json"
	"io"

	"github.com/moveeeax/k8s-hpa-audit/internal/audit"
)

// Minimal SARIF 2.1.0 model — just the fields code-scanning tools require.
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
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	ShortDescription sarifText     `json:"shortDescription"`
	Properties       sarifRuleProp `json:"properties,omitempty"`
}

type sarifRuleProp struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// Version is stamped into SARIF output; overridden by the build via ldflags.
var Version = "dev"

// sarifLevel maps our severity to the SARIF level vocabulary.
func sarifLevel(s audit.Severity) string {
	switch s {
	case audit.SevHigh:
		return "error"
	case audit.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func writeSARIF(w io.Writer, findings []audit.Finding) error {
	rules := make([]sarifRule, 0, len(audit.Rules))
	for _, r := range audit.Rules {
		rules = append(rules, sarifRule{
			ID:               r.ID,
			Name:             r.Name,
			ShortDescription: sarifText{Text: r.Description},
			Properties:       sarifRuleProp{Tags: []string{"kubernetes", "hpa", "autoscaling"}},
		})
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.File},
				},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "k8s-hpa-audit",
				InformationURI: "https://github.com/moveeeax/k8s-hpa-audit",
				Version:        Version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
