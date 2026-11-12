package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDirReadsExamples(t *testing.T) {
	// Load the shipped example tree and confirm both good and bad show up.
	root := filepath.Join("..", "..", "examples")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("examples dir not present: %v", err)
	}
	res, err := LoadDir(root)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected to load some resources from examples/")
	}
	var hpas, workloads int
	for _, r := range res {
		if r.HPA != nil {
			hpas++
		}
		if scalableKinds[r.Kind] {
			workloads++
		}
	}
	if hpas == 0 || workloads == 0 {
		t.Fatalf("examples should contain both HPAs and workloads, got %d hpas %d workloads", hpas, workloads)
	}
}

func TestParseSkipsNonKubernetesDocs(t *testing.T) {
	blob := `
# a bare values fragment, not a k8s object
replicaCount: 3
image:
  tag: latest
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
`
	res, err := ParseBytes([]byte(blob), "mixed.yaml")
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(res) != 1 || res[0].Kind != "Deployment" {
		t.Fatalf("expected only the Deployment, got %+v", res)
	}
	if res[0].Namespace != "default" {
		t.Errorf("expected default namespace, got %q", res[0].Namespace)
	}
}

func TestParseExpandsKubectlList(t *testing.T) {
	// Shape of `kubectl get deploy,hpa -o yaml`.
	blob := `
apiVersion: v1
kind: List
items:
- apiVersion: apps/v1
  kind: Deployment
  metadata: {name: web, namespace: shop}
  spec:
    template:
      spec:
        containers:
        - {name: app, resources: {requests: {cpu: 100m}}}
- apiVersion: autoscaling/v2
  kind: HorizontalPodAutoscaler
  metadata: {name: web, namespace: shop}
  spec:
    scaleTargetRef: {kind: Deployment, name: web}
    maxReplicas: 4
  status:
    conditions:
    - {type: AbleToScale, status: "False", reason: FailedGetScale}
`
	res, err := ParseBytes([]byte(blob), "dump.yaml")
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 items from the List, got %d", len(res))
	}
	if res[0].Pod == nil || len(res[0].Pod.Containers) != 1 {
		t.Errorf("Deployment pod template not decoded: %+v", res[0].Pod)
	}
	if res[1].HPAStatus == nil || len(res[1].HPAStatus.Conditions) != 1 {
		t.Errorf("HPA status not decoded: %+v", res[1].HPAStatus)
	}
}
