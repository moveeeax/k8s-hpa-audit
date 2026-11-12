package audit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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

	defaults := limitRangeDefaults(resources)

	// Which workloads are targeted by at least one HPA.
	targeted := map[workloadKey]bool{}
	var findings []Finding

	for _, r := range resources {
		if r.HPA == nil {
			continue
		}
		findings = append(findings, auditHPA(r, workloads, targeted, defaults, opts)...)
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

func auditHPA(r Resource, workloads map[workloadKey]Resource, targeted map[workloadKey]bool,
	defaults map[string]map[string]bool, opts Options) []Finding {
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
	var target *Resource
	if ref.Name != "" && scalableKinds[ref.Kind] {
		key := workloadKey{ref.Kind, ref.Name, r.Namespace}
		if w, ok := workloads[key]; ok {
			targeted[key] = true
			target = &w
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

	// HPA006: utilization target on containers without the matching request.
	if target != nil && target.Pod != nil && len(target.Pod.Containers) > 0 {
		for _, m := range spec.Metrics {
			if msg := missingRequest(r, *target, m, defaults[r.Namespace]); msg != "" {
				add("HPA006", SevHigh, msg)
			}
		}
	}

	// HPA008: resource metric that the resource metrics API does not serve.
	for _, m := range spec.Metrics {
		name := ""
		switch {
		case m.Type == "Resource" && m.Resource != nil:
			name = m.Resource.Name
		case m.Type == "ContainerResource" && m.ContainerResource != nil:
			name = m.ContainerResource.Name
		}
		if name != "" && !resourceMetricNames[name] {
			add("HPA008", SevMedium, fmt.Sprintf(
				"HPA %s/%s uses %s metric %q; metrics-server publishes only cpu and memory, so the HPA gets no value for it.",
				r.Namespace, r.Name, m.Type, name))
		}
	}

	// HPA007: the controller itself reports that the HPA cannot act. Only
	// present when the manifests were dumped from a live cluster.
	if r.HPAStatus != nil {
		for _, c := range r.HPAStatus.Conditions {
			if (c.Type != "AbleToScale" && c.Type != "ScalingActive") || c.Status != "False" {
				continue
			}
			msg := fmt.Sprintf("HPA %s/%s reports %s=False", r.Namespace, r.Name, c.Type)
			if c.Reason != "" {
				msg += " (" + c.Reason + ")"
			}
			if c.Message != "" {
				msg += ": " + c.Message
			}
			add("HPA007", SevHigh, strings.TrimSuffix(msg, ".")+".")
		}
	}

	return findings
}

// resourceMetricNames are the resources metrics-server publishes through the
// resource metrics API (metrics.k8s.io).
var resourceMetricNames = map[string]bool{"cpu": true, "memory": true}

// limitRangeDefaults maps namespace -> resource names for which a Container
// LimitRange injects a default request at admission. Kubernetes defaults
// defaultRequest from default, and default from max, so any of the three counts.
func limitRangeDefaults(resources []Resource) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, r := range resources {
		if r.LimitRange == nil {
			continue
		}
		for _, l := range r.LimitRange.Limits {
			if l.Type != "Container" {
				continue
			}
			for _, m := range []map[string]json.RawMessage{l.Max, l.Default, l.DefaultRequest} {
				for name := range m {
					if out[r.Namespace] == nil {
						out[r.Namespace] = map[string]bool{}
					}
					out[r.Namespace][name] = true
				}
			}
		}
	}
	return out
}

// hasRequest reports whether a container ends up with a request for resource
// once admitted: an explicit request, a limit (requests default to limits), or
// a namespace LimitRange default.
func hasRequest(res Requirements, resource string, nsDefaults map[string]bool) bool {
	if _, ok := res.Requests[resource]; ok {
		return true
	}
	if _, ok := res.Limits[resource]; ok {
		return true
	}
	return nsDefaults[resource]
}

// missingRequest returns an HPA006 message when a Utilization target on m
// cannot be computed for the target workload, or "" when it can. It mirrors
// the HPA controller: requests are summed over regular containers and native
// sidecars (init containers with restartPolicy Always); pod-level requests
// replace the sum for Resource metrics; a ContainerResource metric looks only
// at its named container.
func missingRequest(hpa, target Resource, m Metric, nsDefaults map[string]bool) string {
	var resource, container string
	switch {
	case m.Type == "Resource" && m.Resource != nil && m.Resource.Target.Type == "Utilization":
		resource = m.Resource.Name
	case m.Type == "ContainerResource" && m.ContainerResource != nil &&
		m.ContainerResource.Target.Type == "Utilization":
		resource = m.ContainerResource.Name
		container = m.ContainerResource.Container
	default:
		return ""
	}
	if resource == "" {
		return ""
	}

	pod := target.Pod
	containers := append([]Container{}, pod.Containers...)
	for _, c := range pod.InitContainers {
		if c.RestartPolicy == "Always" {
			containers = append(containers, c)
		}
	}

	if container == "" {
		if hasRequest(pod.Resources, resource, nil) {
			return ""
		}
		var missing []string
		for _, c := range containers {
			if !hasRequest(c.Resources, resource, nsDefaults) {
				missing = append(missing, c.Name)
			}
		}
		if len(missing) == 0 {
			return ""
		}
		return fmt.Sprintf(
			"HPA %s/%s targets %s utilization but %s %s/%s has no %s request on container(s) %s; utilization is undefined and the HPA never scales.",
			hpa.Namespace, hpa.Name, resource, target.Kind, target.Namespace, target.Name,
			resource, strings.Join(missing, ", "))
	}

	for _, c := range containers {
		if c.Name != container {
			continue
		}
		if hasRequest(c.Resources, resource, nsDefaults) {
			return ""
		}
		return fmt.Sprintf(
			"HPA %s/%s targets %s utilization of container %s but %s %s/%s sets no %s request on it; utilization is undefined and the HPA never scales.",
			hpa.Namespace, hpa.Name, resource, container, target.Kind, target.Namespace, target.Name, resource)
	}
	return fmt.Sprintf(
		"HPA %s/%s targets %s utilization of container %s, which is not in the pod template of %s %s/%s.",
		hpa.Namespace, hpa.Name, resource, container, target.Kind, target.Namespace, target.Name)
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
