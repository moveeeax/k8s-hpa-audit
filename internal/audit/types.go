package audit

// Severity ranks a finding. The zero value is intentionally invalid so an
// unset severity never silently passes a --fail-on gate.
type Severity int

const (
	// SevLow is informational: worth noticing, not worth paging.
	SevLow Severity = iota + 1
	// SevMedium is a real gap that degrades autoscaling behaviour.
	SevMedium
	// SevHigh is a broken or missing autoscaler.
	SevHigh
)

// String returns the lower-case label used in every output format.
func (s Severity) String() string {
	switch s {
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	default:
		return "unknown"
	}
}

// ParseSeverity maps a label to a Severity. It is used by --fail-on.
func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "low":
		return SevLow, true
	case "medium":
		return SevMedium, true
	case "high":
		return SevHigh, true
	default:
		return 0, false
	}
}

// Finding is a single hygiene problem discovered in the manifest tree.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Severity  Severity `json:"-"`
	Level     string   `json:"severity"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Message   string   `json:"message"`
	File      string   `json:"file"`
}

// Rule describes a check. It is surfaced in SARIF so results can be grouped.
type Rule struct {
	ID          string
	Name        string
	Description string
}

// Rules is the catalogue of checks this tool performs.
var Rules = []Rule{
	{"HPA001", "no-op-hpa", "HPA can never scale (min==max, min<=0, or max<min)."},
	{"HPA002", "missing-metrics", "HPA has no metrics and can never make a scaling decision."},
	{"HPA003", "dangling-target", "HPA scaleTargetRef points at a workload not present in the tree."},
	{"HPA004", "cpu-target-out-of-band", "HPA CPU utilization target is outside the sane band."},
	{"HPA005", "workload-without-hpa", "Scalable workload has no HorizontalPodAutoscaler."},
}
