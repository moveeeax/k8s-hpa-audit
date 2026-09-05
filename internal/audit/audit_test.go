package audit

import (
	"sort"
	"testing"
)

// parse is a test helper that decodes a manifest string.
func parse(t *testing.T, name, yaml string) []Resource {
	t.Helper()
	res, err := ParseBytes([]byte(yaml), name)
	if err != nil {
		t.Fatalf("ParseBytes(%s): %v", name, err)
	}
	return res
}

func ruleIDs(findings []Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	sort.Strings(ids)
	return ids
}

func hasRule(findings []Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

const deployWeb = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
`

func TestDeploymentWithoutHPA(t *testing.T) {
	res := parse(t, "web.yaml", deployWeb)
	f := Audit(res, DefaultOptions())
	if !hasRule(f, "HPA005") {
		t.Fatalf("expected HPA005 (workload without HPA), got %v", ruleIDs(f))
	}
}

func TestWellFormedHPAHasNoFindings(t *testing.T) {
	manifest := deployWeb + `
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
  namespace: shop
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
`
	f := Audit(parse(t, "web.yaml", manifest), DefaultOptions())
	if len(f) != 0 {
		t.Fatalf("expected zero findings for a well-formed HPA, got %v", ruleIDs(f))
	}
}

func TestNoOpHPA_MinEqualsMax(t *testing.T) {
	manifest := deployWeb + `
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
  namespace: shop
spec:
  scaleTargetRef:
    kind: Deployment
    name: web
  minReplicas: 3
  maxReplicas: 3
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 60
`
	f := Audit(parse(t, "web.yaml", manifest), DefaultOptions())
	if !hasRule(f, "HPA001") {
		t.Fatalf("expected HPA001 for min==max, got %v", ruleIDs(f))
	}
	for _, x := range f {
		if x.RuleID == "HPA001" && x.Severity != SevHigh {
			t.Errorf("HPA001 should be high severity, got %s", x.Severity)
		}
	}
}

func TestMaxBelowMin(t *testing.T) {
	manifest := deployWeb + `
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
  namespace: shop
spec:
  scaleTargetRef: {kind: Deployment, name: web}
  minReplicas: 5
  maxReplicas: 2
  metrics:
  - type: Resource
    resource: {name: cpu, target: {type: Utilization, averageUtilization: 50}}
`
	f := Audit(parse(t, "web.yaml", manifest), DefaultOptions())
	if !hasRule(f, "HPA001") {
		t.Fatalf("expected HPA001 for max<min, got %v", ruleIDs(f))
	}
}

func TestDanglingTarget(t *testing.T) {
	manifest := `
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ghost
  namespace: shop
spec:
  scaleTargetRef: {kind: Deployment, name: does-not-exist}
  minReplicas: 1
  maxReplicas: 5
  metrics:
  - type: Resource
    resource: {name: cpu, target: {type: Utilization, averageUtilization: 50}}
`
	f := Audit(parse(t, "ghost.yaml", manifest), DefaultOptions())
	if !hasRule(f, "HPA003") {
		t.Fatalf("expected HPA003 for dangling target, got %v", ruleIDs(f))
	}
}

func TestMissingMetrics(t *testing.T) {
	manifest := deployWeb + `
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
  namespace: shop
spec:
  scaleTargetRef: {kind: Deployment, name: web}
  minReplicas: 2
  maxReplicas: 8
`
	f := Audit(parse(t, "web.yaml", manifest), DefaultOptions())
	if !hasRule(f, "HPA002") {
		t.Fatalf("expected HPA002 for missing metrics, got %v", ruleIDs(f))
	}
}

func TestCPUTargetOutOfBand(t *testing.T) {
	manifest := deployWeb + `
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
  namespace: shop
spec:
  scaleTargetRef: {kind: Deployment, name: web}
  minReplicas: 2
  maxReplicas: 8
  metrics:
  - type: Resource
    resource: {name: cpu, target: {type: Utilization, averageUtilization: 5}}
`
	f := Audit(parse(t, "web.yaml", manifest), DefaultOptions())
	if !hasRule(f, "HPA004") {
		t.Fatalf("expected HPA004 for CPU target 5%%, got %v", ruleIDs(f))
	}
	// A workload targeted by this HPA should NOT also raise HPA005.
	if hasRule(f, "HPA005") {
		t.Errorf("HPA005 should not fire for a targeted workload")
	}
}

func TestNamespaceDefaultingIsolatesTargets(t *testing.T) {
	// HPA in default namespace must not match a workload in another namespace.
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api
spec:
  scaleTargetRef: {kind: Deployment, name: api}
  minReplicas: 2
  maxReplicas: 6
  metrics:
  - type: Resource
    resource: {name: cpu, target: {type: Utilization, averageUtilization: 60}}
`
	f := Audit(parse(t, "api.yaml", manifest), DefaultOptions())
	if !hasRule(f, "HPA003") {
		t.Fatalf("expected HPA003: default-namespace HPA must not match prod workload, got %v", ruleIDs(f))
	}
	if !hasRule(f, "HPA005") {
		t.Fatalf("expected HPA005: prod/api has no HPA in its namespace, got %v", ruleIDs(f))
	}
}

func TestSummaryAndMaxSeverity(t *testing.T) {
	manifest := deployWeb + `
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: web, namespace: shop}
spec:
  scaleTargetRef: {kind: Deployment, name: web}
  minReplicas: 3
  maxReplicas: 3
`
	f := Audit(parse(t, "web.yaml", manifest), DefaultOptions())
	s := Summarize(f)
	if s.Total != s.High+s.Medium+s.Low {
		t.Errorf("summary totals inconsistent: %+v", s)
	}
	if MaxSeverity(f) != SevHigh {
		t.Errorf("expected max severity high, got %s", MaxSeverity(f))
	}
}

func TestFindingsAreSortedDeterministically(t *testing.T) {
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: zebra, namespace: a}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: alpha, namespace: a}
`
	f := Audit(parse(t, "z.yaml", manifest), DefaultOptions())
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
	if f[0].Name != "alpha" || f[1].Name != "zebra" {
		t.Errorf("findings not sorted by name: %s then %s", f[0].Name, f[1].Name)
	}
}

func TestParseSeverityRoundTrip(t *testing.T) {
	for _, s := range []Severity{SevLow, SevMedium, SevHigh} {
		got, ok := ParseSeverity(s.String())
		if !ok || got != s {
			t.Errorf("ParseSeverity(%q) = %v,%v", s.String(), got, ok)
		}
	}
	if _, ok := ParseSeverity("bogus"); ok {
		t.Error("ParseSeverity(bogus) should fail")
	}
}
