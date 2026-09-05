package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moveeeax/k8s-hpa-audit/internal/audit"
)

func sample() []audit.Finding {
	f := []audit.Finding{
		{RuleID: "HPA001", Severity: audit.SevHigh, Kind: "HorizontalPodAutoscaler",
			Name: "web", Namespace: "shop", File: "web.yaml", Message: "no-op"},
		{RuleID: "HPA004", Severity: audit.SevMedium, Kind: "HorizontalPodAutoscaler",
			Name: "api", Namespace: "shop", File: "api.yaml", Message: "cpu out of band"},
	}
	for i := range f {
		f[i].Level = f[i].Severity.String()
	}
	return f
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"table", "json", "sarif"} {
		if _, ok := ParseFormat(s); !ok {
			t.Errorf("ParseFormat(%q) should succeed", s)
		}
	}
	if _, ok := ParseFormat("yaml"); ok {
		t.Error("ParseFormat(yaml) should fail")
	}
}

func TestTableEmpty(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatTable, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No HPA hygiene findings") {
		t.Errorf("empty table missing clean message: %q", b.String())
	}
}

func TestTableRendersFindings(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatTable, sample()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"HPA001", "high", "shop", "2 finding(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestJSONIsValidAndHasSummary(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatJSON, sample()); err != nil {
		t.Fatal(err)
	}
	var got jsonReport
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("JSON output does not parse: %v", err)
	}
	if got.Summary.Total != 2 || got.Summary.High != 1 || got.Summary.Medium != 1 {
		t.Errorf("unexpected summary: %+v", got.Summary)
	}
	if got.Findings[0].Level != "high" {
		t.Errorf("expected severity string in JSON, got %q", got.Findings[0].Level)
	}
}

func TestJSONEmptyFindingsIsArrayNotNull(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatJSON, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"findings": []`) {
		t.Errorf("empty findings should serialize as [], got:\n%s", b.String())
	}
}

func TestSARIFStructure(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatSARIF, sample()); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatalf("SARIF output does not parse: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "k8s-hpa-audit" {
		t.Errorf("unexpected driver name %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != len(audit.Rules) {
		t.Errorf("expected %d rules in SARIF, got %d", len(audit.Rules), len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Errorf("high severity should map to SARIF level error, got %q", run.Results[0].Level)
	}
	if run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "web.yaml" {
		t.Errorf("missing artifact location uri")
	}
}
