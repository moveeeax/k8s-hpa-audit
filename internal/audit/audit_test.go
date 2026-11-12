package audit

import (
	"sort"
	"strings"
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

// hpaWith builds a shop/web HPA targeting Deployment web with the given metrics block.
func hpaWith(metrics string) string {
	return `
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: web, namespace: shop}
spec:
  scaleTargetRef: {kind: Deployment, name: web}
  minReplicas: 2
  maxReplicas: 8
  metrics:
` + metrics
}

const cpuUtil = `  - type: Resource
    resource: {name: cpu, target: {type: Utilization, averageUtilization: 60}}
`

func findingsFor(f []Finding, id string) []Finding {
	var out []Finding
	for _, x := range f {
		if x.RuleID == id {
			out = append(out, x)
		}
	}
	return out
}

func TestUtilizationWithoutRequestNamesContainers(t *testing.T) {
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      containers:
      - name: app
        resources: {requests: {cpu: 250m}}
      - name: proxy
      - name: logger
        resources: {requests: {memory: 64Mi}}
` + hpaWith(cpuUtil)
	f := findingsFor(Audit(parse(t, "web.yaml", manifest), DefaultOptions()), "HPA006")
	if len(f) != 1 {
		t.Fatalf("expected one HPA006, got %d", len(f))
	}
	if f[0].Severity != SevHigh {
		t.Errorf("HPA006 should be high, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "proxy, logger") || strings.Contains(f[0].Message, "app") {
		t.Errorf("message should name proxy and logger only: %s", f[0].Message)
	}
}

func TestUtilizationRequestSatisfiedBy(t *testing.T) {
	cases := map[string]string{
		"explicit requests": `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      containers:
      - {name: app, resources: {requests: {cpu: "1"}}}
`,
		"limits default requests": `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      containers:
      - {name: app, resources: {limits: {cpu: 500m}}}
`,
		"pod-level requests": `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      resources: {requests: {cpu: "1"}}
      containers:
      - {name: app}
`,
		"namespace LimitRange default": `
apiVersion: v1
kind: LimitRange
metadata: {name: defaults, namespace: shop}
spec:
  limits:
  - type: Container
    defaultRequest: {cpu: 100m}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      containers:
      - {name: app}
`,
		"plain init container is ignored": `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      initContainers:
      - {name: migrate}
      containers:
      - {name: app, resources: {requests: {cpu: 100m}}}
`,
	}
	for name, workload := range cases {
		t.Run(name, func(t *testing.T) {
			f := Audit(parse(t, "web.yaml", workload+hpaWith(cpuUtil)), DefaultOptions())
			if hasRule(f, "HPA006") {
				t.Fatalf("unexpected HPA006: %v", findingsFor(f, "HPA006"))
			}
		})
	}
}

func TestUtilizationLimitRangeInOtherNamespaceDoesNotCount(t *testing.T) {
	manifest := `
apiVersion: v1
kind: LimitRange
metadata: {name: defaults, namespace: other}
spec:
  limits:
  - {type: Container, default: {cpu: 100m}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      containers:
      - {name: app}
` + hpaWith(cpuUtil)
	if f := Audit(parse(t, "web.yaml", manifest), DefaultOptions()); !hasRule(f, "HPA006") {
		t.Fatalf("expected HPA006, got %v", ruleIDs(f))
	}
}

func TestUtilizationNativeSidecarNeedsRequest(t *testing.T) {
	manifest := `
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      initContainers:
      - {name: mesh, restartPolicy: Always}
      containers:
      - {name: app, resources: {requests: {memory: 128Mi}}}
` + strings.Replace(hpaWith(`  - type: Resource
    resource: {name: memory, target: {type: Utilization, averageUtilization: 75}}
`), "kind: Deployment", "kind: StatefulSet", 1)
	f := findingsFor(Audit(parse(t, "web.yaml", manifest), DefaultOptions()), "HPA006")
	if len(f) != 1 || !strings.Contains(f[0].Message, "mesh") {
		t.Fatalf("expected HPA006 naming the mesh sidecar, got %v", f)
	}
}

func TestAverageValueTargetNeedsNoRequest(t *testing.T) {
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      containers:
      - {name: app}
` + hpaWith(`  - type: Resource
    resource: {name: cpu, target: {type: AverageValue, averageValue: 500m}}
`)
	if f := Audit(parse(t, "web.yaml", manifest), DefaultOptions()); hasRule(f, "HPA006") {
		t.Fatalf("AverageValue targets do not use requests, got %v", ruleIDs(f))
	}
}

func TestContainerResourceUtilization(t *testing.T) {
	workload := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      resources: {requests: {cpu: "2"}}
      containers:
      - {name: app}
      - {name: proxy, resources: {requests: {cpu: 50m}}}
`
	metric := func(container string) string {
		return `  - type: ContainerResource
    containerResource:
      name: cpu
      container: ` + container + `
      target: {type: Utilization, averageUtilization: 60}
`
	}
	// The named container has a request: fine, the other container is irrelevant.
	if f := Audit(parse(t, "web.yaml", workload+hpaWith(metric("proxy"))), DefaultOptions()); hasRule(f, "HPA006") {
		t.Errorf("proxy has a cpu request, got %v", findingsFor(f, "HPA006"))
	}
	// Pod-level requests do not apply to a ContainerResource metric.
	f := findingsFor(Audit(parse(t, "web.yaml", workload+hpaWith(metric("app"))), DefaultOptions()), "HPA006")
	if len(f) != 1 || !strings.Contains(f[0].Message, "container app") {
		t.Errorf("expected HPA006 for container app, got %v", f)
	}
	// A container that does not exist can never be measured.
	f = findingsFor(Audit(parse(t, "web.yaml", workload+hpaWith(metric("sidecar"))), DefaultOptions()), "HPA006")
	if len(f) != 1 || !strings.Contains(f[0].Message, "not in the pod template") {
		t.Errorf("expected HPA006 for missing container, got %v", f)
	}
}

func TestUnpublishedResourceMetric(t *testing.T) {
	manifest := deployWeb + hpaWith(`  - type: Resource
    resource: {name: ephemeral-storage, target: {type: AverageValue, averageValue: 1Gi}}
`)
	f := findingsFor(Audit(parse(t, "web.yaml", manifest), DefaultOptions()), "HPA008")
	if len(f) != 1 || f[0].Severity != SevMedium {
		t.Fatalf("expected one medium HPA008, got %v", f)
	}
	if f := Audit(parse(t, "web.yaml", deployWeb+hpaWith(cpuUtil)), DefaultOptions()); hasRule(f, "HPA008") {
		t.Errorf("cpu is published by metrics-server")
	}
}

func TestStatusConditionsSurfaced(t *testing.T) {
	manifest := deployWeb + hpaWith(cpuUtil) + `status:
  conditions:
  - type: AbleToScale
    status: "True"
    reason: SucceededGetScale
  - type: ScalingActive
    status: "False"
    reason: FailedGetResourceMetric
    message: "the HPA was unable to compute the replica count: failed to get cpu utilization"
  - type: ScalingLimited
    status: "True"
    reason: TooFewReplicas
`
	f := findingsFor(Audit(parse(t, "web.yaml", manifest), DefaultOptions()), "HPA007")
	if len(f) != 1 {
		t.Fatalf("expected one HPA007 for ScalingActive=False, got %v", f)
	}
	want := "HPA shop/web reports ScalingActive=False (FailedGetResourceMetric): the HPA was unable to compute the replica count: failed to get cpu utilization."
	if f[0].Message != want {
		t.Errorf("message:\n got %q\nwant %q", f[0].Message, want)
	}
}
