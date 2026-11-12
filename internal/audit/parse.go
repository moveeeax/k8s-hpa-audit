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
	HPAStatus  *HPAStatus
	Pod        *PodSpec        // pod template spec, populated only for scalable workloads
	LimitRange *LimitRangeSpec // populated only for LimitRange objects
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
	Type              string                   `json:"type"`
	Resource          *ResourceMetricSource    `json:"resource"`
	ContainerResource *ContainerResourceSource `json:"containerResource"`
}

// MetricTarget is the target block shared by Resource and ContainerResource metrics.
type MetricTarget struct {
	Type               string `json:"type"`
	AverageUtilization *int32 `json:"averageUtilization"`
}

// ResourceMetricSource is a metric of type Resource.
type ResourceMetricSource struct {
	Name   string       `json:"name"`
	Target MetricTarget `json:"target"`
}

// ContainerResourceSource is a metric of type ContainerResource: a resource of
// one named container rather than the sum over the pod.
type ContainerResourceSource struct {
	Name      string       `json:"name"`
	Container string       `json:"container"`
	Target    MetricTarget `json:"target"`
}

// HPAStatus is the subset of an HPA status we audit. It is only present when
// the manifests were dumped from a live cluster (kubectl get hpa -o yaml).
type HPAStatus struct {
	Conditions []HPACondition `json:"conditions"`
}

// HPACondition is one entry of status.conditions.
type HPACondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// PodSpec is the subset of a pod template spec needed to resolve the resource
// requests an HPA divides usage by.
type PodSpec struct {
	Containers     []Container  `json:"containers"`
	InitContainers []Container  `json:"initContainers"`
	Resources      Requirements `json:"resources"` // pod-level resources (KEP-2837)
}

// Container is the subset of a container spec we audit.
type Container struct {
	Name          string       `json:"name"`
	RestartPolicy string       `json:"restartPolicy"` // "Always" marks a native sidecar
	Resources     Requirements `json:"resources"`
}

// Requirements holds requests and limits keyed by resource name. Values are
// kept raw: only the presence of a key matters to the audit.
type Requirements struct {
	Requests map[string]json.RawMessage `json:"requests"`
	Limits   map[string]json.RawMessage `json:"limits"`
}

// LimitRangeSpec is the subset of a LimitRange spec that injects default
// container requests at admission time.
type LimitRangeSpec struct {
	Limits []struct {
		Type           string                     `json:"type"`
		Max            map[string]json.RawMessage `json:"max"`
		Default        map[string]json.RawMessage `json:"default"`
		DefaultRequest map[string]json.RawMessage `json:"defaultRequest"`
	} `json:"limits"`
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
	Spec   json.RawMessage   `json:"spec"`
	Status json.RawMessage   `json:"status"`
	Items  []json.RawMessage `json:"items"` // set on v1 List objects
}

// workloadSpec is the part of a Deployment/StatefulSet spec we read.
type workloadSpec struct {
	Template struct {
		Spec PodSpec `json:"spec"`
	} `json:"template"`
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
// The file argument is recorded on each Resource for reporting. A v1 List (the
// shape of kubectl get -o yaml) is expanded into its items.
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
		res, err := decodeObject(raw, file)
		if err != nil {
			return nil, err
		}
		out = append(out, res...)
	}
	return out, nil
}

func decodeObject(raw rawObject, file string) ([]Resource, error) {
	if raw.Kind == "" {
		return nil, nil // not a Kubernetes object (e.g. a values fragment)
	}
	if raw.Kind == "List" || (strings.HasSuffix(raw.Kind, "List") && raw.Items != nil) {
		var out []Resource
		for i, item := range raw.Items {
			var obj rawObject
			if err := json.Unmarshal(item, &obj); err != nil {
				return nil, fmt.Errorf("decode %s item %d: %w", raw.Kind, i, err)
			}
			res, err := decodeObject(obj, file)
			if err != nil {
				return nil, err
			}
			out = append(out, res...)
		}
		return out, nil
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
	switch {
	case raw.Kind == "HorizontalPodAutoscaler" && len(raw.Spec) > 0:
		var spec HPASpec
		if err := json.Unmarshal(raw.Spec, &spec); err != nil {
			return nil, fmt.Errorf("decode HPA spec of %s: %w", raw.Metadata.Name, err)
		}
		r.HPA = &spec
		if len(raw.Status) > 0 && string(raw.Status) != "null" {
			var st HPAStatus
			if err := json.Unmarshal(raw.Status, &st); err != nil {
				return nil, fmt.Errorf("decode HPA status of %s: %w", raw.Metadata.Name, err)
			}
			r.HPAStatus = &st
		}
	case scalableKinds[raw.Kind] && len(raw.Spec) > 0:
		var spec workloadSpec
		if err := json.Unmarshal(raw.Spec, &spec); err != nil {
			return nil, fmt.Errorf("decode %s spec of %s: %w", raw.Kind, raw.Metadata.Name, err)
		}
		r.Pod = &spec.Template.Spec
	case raw.Kind == "LimitRange" && len(raw.Spec) > 0:
		var spec LimitRangeSpec
		if err := json.Unmarshal(raw.Spec, &spec); err != nil {
			return nil, fmt.Errorf("decode LimitRange spec of %s: %w", raw.Metadata.Name, err)
		}
		r.LimitRange = &spec
	}
	return []Resource{r}, nil
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
