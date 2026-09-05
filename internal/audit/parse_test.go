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
