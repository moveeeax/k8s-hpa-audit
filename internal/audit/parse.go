package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

// Resource is a decoded Kubernetes object. Only the fields this tool needs are
// kept; everything else in the manifest is ignored.
type Resource struct {
	APIVersion string
	Kind       string
	Name       string
	Namespace  string
	File       string
	HPA        *HPASpec // populated only for HorizontalPodAutoscaler objects
}

// HPASpec is the subset of an autoscaling/v2 HPA spec we audit.
type HPASpec struct {
	ScaleTargetRef struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"scaleTargetRef"`
	MinReplicas *int32   `json:"minReplicas"`
	MaxReplicas int32    `json:"maxReplicas"`
	Metrics     []Metric `json:"metrics"`
}

// Metric is one entry of an HPA's spec.metrics list.
type Metric struct {
	Type     string `json:"type"`
	Resource *struct {
		Name   string `json:"name"`
		Target struct {
			Type               string `json:"type"`
			AverageUtilization *int32 `json:"averageUtilization"`
		} `json:"target"`
	} `json:"resource"`
}

// scalableKinds are workload kinds an HPA can target.
var scalableKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
}

type rawObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec json.RawMessage `json:"spec"`
}

// LoadDir walks root and parses every .yaml/.yml file into Resources.
// Multi-document files (separated by "---") are supported.
func LoadDir(root string) ([]Resource, error) {
	var out []Resource
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		res, err := ParseBytes(data, path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, res...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ParseBytes decodes one manifest blob (possibly multi-document) into Resources.
// The file argument is recorded on each Resource for reporting.
func ParseBytes(data []byte, file string) ([]Resource, error) {
	var out []Resource
	for _, doc := range splitDocuments(data) {
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		var raw rawObject
		if err := yaml.Unmarshal(doc, &raw); err != nil {
			return nil, err
		}
		if raw.Kind == "" {
			continue // not a Kubernetes object (e.g. a values fragment)
		}
		ns := raw.Metadata.Namespace
		if ns == "" {
			ns = "default"
		}
		r := Resource{
			APIVersion: raw.APIVersion,
			Kind:       raw.Kind,
			Name:       raw.Metadata.Name,
			Namespace:  ns,
			File:       file,
		}
		if raw.Kind == "HorizontalPodAutoscaler" && len(raw.Spec) > 0 {
			var spec HPASpec
			if err := json.Unmarshal(raw.Spec, &spec); err != nil {
				return nil, fmt.Errorf("decode HPA spec of %s: %w", raw.Metadata.Name, err)
			}
			r.HPA = &spec
		}
		out = append(out, r)
	}
	return out, nil
}

// splitDocuments splits a YAML stream on "---" separators that sit on their own
// line, mirroring how kubectl reads multi-document manifests.
func splitDocuments(data []byte) [][]byte {
	lines := bytes.Split(data, []byte("\n"))
	var docs [][]byte
	var cur [][]byte
	flush := func() {
		docs = append(docs, bytes.Join(cur, []byte("\n")))
		cur = nil
	}
	for _, line := range lines {
		if string(bytes.TrimRight(line, " \t\r")) == "---" {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return docs
}
