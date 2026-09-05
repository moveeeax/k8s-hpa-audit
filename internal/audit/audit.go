package audit

import (
	"fmt"
	"sort"
)

// Options tunes the CPU-utilization band check.
type Options struct {
	CPUMin int32 // inclusive lower bound for a sane CPU utilization target
	CPUMax int32 // inclusive upper bound
}

// DefaultOptions returns the recommended thresholds (20-90% CPU).
func DefaultOptions() Options {
	return Options{CPUMin: 20, CPUMax: 90}
}

type workloadKey struct {
	kind      string
	name      string
	namespace string
}

// Audit runs every rule over the parsed resources and returns findings sorted
// deterministically (file, namespace, name, ruleID).
func Audit(resources []Resource, opts Options) []Finding {
	workloads := map[workloadKey]Resource{}
	for _, r := range resources {
		if scalableKinds[r.Kind] {
			workloads[workloadKey{r.Kind, r.Name, r.Namespace}] = r
		}
	}

	// Which workloads are targeted by at least one HPA.
	targeted := map[workloadKey]bool{}
	var findings []Finding

	for _, r := range resources {
		if r.HPA == nil {
			continue
		}
		findings = append(findings, auditHPA(r, workloads, targeted, opts)...)
	}

	// Scalable workloads with no HPA pointing at them.
	for _, r := range resources {
		if !scalableKinds[r.Kind] {
			continue
		}
		key := workloadKey{r.Kind, r.Name, r.Namespace}
		if targeted[key] {
			continue
		}
		findings = append(findings, Finding{
			RuleID:    "HPA005",
			Severity:  SevMedium,
			Kind:      r.Kind,
			Name:      r.Name,
			Namespace: r.Namespace,
			File:      r.File,
			Message: fmt.Sprintf("%s %s/%s has no HorizontalPodAutoscaler; it will never scale automatically.",
				r.Kind, r.Namespace, r.Name),
		})
	}

	finalize(findings)
	return findings
}

func auditHPA(r Resource, workloads map[workloadKey]Resource, targeted map[workloadKey]bool, opts Options) []Finding {
	var findings []Finding
	spec := r.HPA
	add := func(rule string, sev Severity, msg string) {
		findings = append(findings, Finding{
			RuleID: rule, Severity: sev, Kind: r.Kind,
			Name: r.Name, Namespace: r.Namespace, File: r.File, Message: msg,
		})
	}

	// HPA003: dangling scaleTargetRef.
	ref := spec.ScaleTargetRef
	if ref.Name != "" && scalableKinds[ref.Kind] {
		key := workloadKey{ref.Kind, ref.Name, r.Namespace}
		if _, ok := workloads[key]; ok {
			targeted[key] = true
		} else {
			add("HPA003", SevHigh, fmt.Sprintf(
				"HPA %s/%s targets %s/%s which is not present in the manifest tree (dangling scaleTargetRef).",
				r.Namespace, r.Name, ref.Kind, ref.Name))
		}
	}

	// HPA001: no-op ranges.
	min := int32(1)
	if spec.MinReplicas != nil {
		min = *spec.MinReplicas
	}
	switch {
	case spec.MinReplicas != nil && *spec.MinReplicas <= 0:
		add("HPA001", SevHigh, fmt.Sprintf(
			"HPA %s/%s has minReplicas=%d; a value of zero or less is invalid and disables scaling.",
			r.Namespace, r.Name, *spec.MinReplicas))
	case spec.MaxReplicas < min:
		add("HPA001", SevHigh, fmt.Sprintf(
			"HPA %s/%s has maxReplicas=%d below minReplicas=%d; it can never scale up.",
			r.Namespace, r.Name, spec.MaxReplicas, min))
	case spec.MaxReplicas == min:
		add("HPA001", SevHigh, fmt.Sprintf(
			"HPA %s/%s has minReplicas==maxReplicas==%d; it is a no-op and can never scale.",
			r.Namespace, r.Name, min))
	}

	// HPA002: no metrics.
	if len(spec.Metrics) == 0 {
		add("HPA002", SevHigh, fmt.Sprintf(
			"HPA %s/%s declares no metrics; it has nothing to scale on.", r.Namespace, r.Name))
	}

	// HPA004: CPU utilization target out of band.
	for _, m := range spec.Metrics {
		if m.Type != "Resource" || m.Resource == nil || m.Resource.Name != "cpu" {
			continue
		}
		t := m.Resource.Target
		if t.Type != "Utilization" || t.AverageUtilization == nil {
			continue
		}
		v := *t.AverageUtilization
		if v < opts.CPUMin || v > opts.CPUMax {
			add("HPA004", SevMedium, fmt.Sprintf(
				"HPA %s/%s targets CPU utilization %d%%, outside the sane band %d-%d%%.",
				r.Namespace, r.Name, v, opts.CPUMin, opts.CPUMax))
		}
	}

	return findings
}

// finalize fills the string level and sorts findings for stable output.
func finalize(findings []Finding) {
	for i := range findings {
		findings[i].Level = findings[i].Severity.String()
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.RuleID < b.RuleID
	})
}

// Summary counts findings by severity.
type Summary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

// Summarize tallies a finding slice.
func Summarize(findings []Finding) Summary {
	s := Summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case SevHigh:
			s.High++
		case SevMedium:
			s.Medium++
		case SevLow:
			s.Low++
		}
	}
	return s
}

// MaxSeverity returns the highest severity present, or 0 if there are none.
func MaxSeverity(findings []Finding) Severity {
	var max Severity
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}
