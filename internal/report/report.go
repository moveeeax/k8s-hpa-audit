// Package report renders audit findings as a table, JSON, or SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/moveeeax/k8s-hpa-audit/internal/audit"
)

// Format is an output encoding.
type Format string

const (
	// FormatTable is a human-readable aligned table (the default).
	FormatTable Format = "table"
	// FormatJSON is machine-readable findings plus a summary.
	FormatJSON Format = "json"
	// FormatSARIF is SARIF 2.1.0 for code-scanning dashboards.
	FormatSARIF Format = "sarif"
)

// ParseFormat validates an --output value.
func ParseFormat(s string) (Format, bool) {
	switch Format(s) {
	case FormatTable, FormatJSON, FormatSARIF:
		return Format(s), true
	default:
		return "", false
	}
}

// Write renders findings in the requested format to w.
func Write(w io.Writer, format Format, findings []audit.Finding) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, findings)
	case FormatSARIF:
		return writeSARIF(w, findings)
	default:
		return writeTable(w, findings)
	}
}

func writeTable(w io.Writer, findings []audit.Finding) error {
	s := audit.Summarize(findings)
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No HPA hygiene findings. ✓")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE\tRESOURCE\tMESSAGE")
	for _, f := range findings {
		resource := fmt.Sprintf("%s/%s/%s", f.Kind, f.Namespace, f.Name)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, resource, f.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d finding(s): %d high, %d medium, %d low\n",
		s.Total, s.High, s.Medium, s.Low)
	return err
}

type jsonReport struct {
	Findings []audit.Finding `json:"findings"`
	Summary  audit.Summary   `json:"summary"`
}

func writeJSON(w io.Writer, findings []audit.Finding) error {
	if findings == nil {
		findings = []audit.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{Findings: findings, Summary: audit.Summarize(findings)})
}
