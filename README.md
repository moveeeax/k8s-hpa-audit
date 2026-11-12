# k8s-hpa-audit

[![ci](https://github.com/moveeeax/k8s-hpa-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-hpa-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Static audit of Kubernetes manifests for **HorizontalPodAutoscaler hygiene**. It reads a
directory of YAML and flags the autoscaling gaps that never fail `kubectl apply` but page you
later: scalable workloads with no HPA, no-op HPAs, HPAs with no metrics, out-of-band CPU
targets, HPAs pointing at workloads that don't exist, and utilization targets that can never
be computed.

It never talks to a cluster — it only reads files — so it is safe in CI and pre-commit.

## Why

Horizontal Pod Autoscalers are opt-in and easy to misconfigure. A Deployment ships without one
and never scales under load; an HPA lands with `minReplicas == maxReplicas` so it can never
move; another targets a metric the cluster doesn't collect. None of this is rejected at apply
time, so it sits unnoticed until an incident. `k8s-hpa-audit` gives you a fast, read-only view
of the whole tree.

## What it checks

| Rule   | Severity | Meaning                                                              |
|--------|----------|---------------------------------------------------------------------|
| HPA001 | high     | No-op HPA: `min == max`, `min <= 0`, or `max < min`.                 |
| HPA002 | high     | HPA declares no metrics — nothing to scale on.                      |
| HPA003 | high     | `scaleTargetRef` points at a workload not present in the tree.      |
| HPA004 | medium   | CPU utilization target outside the sane band (default 20–90%).      |
| HPA005 | medium   | Scalable workload (Deployment/StatefulSet) has no HPA targeting it. |
| HPA006 | high     | `Utilization` target on a resource some containers do not request.  |
| HPA007 | high     | HPA status says `AbleToScale` or `ScalingActive` is `False`.        |
| HPA008 | medium   | Resource metric other than `cpu`/`memory` (metrics-server has none). |

Namespaces are respected: an HPA in `default` will not be considered to cover a workload in
another namespace.

HPA006 follows how the HPA controller computes utilization: usage is divided by the sum of
the pod's requests for that resource, so every regular container and every native sidecar
(an init container with `restartPolicy: Always`) needs one. A container counts as having a
request when it sets `requests`, when it sets `limits` (Kubernetes copies limits into missing
requests), or when a `LimitRange` of type `Container` in the same namespace in the tree sets
`defaultRequest`, `default`, or `max` for that resource. Pod-level `spec.resources.requests`
satisfy a `Resource` metric. A `ContainerResource` metric checks only its named container, and
flags a container name that is not in the pod template. `AverageValue` targets do not use
requests and are not checked. The rule needs the target workload's pod template in the tree.

HPA007 only fires when the input carries HPA `status`, i.e. a dump from a cluster. Lists in the
shape of `kubectl get ... -o yaml` (`kind: List` with `items`) are expanded, so you can audit a
live namespace offline:

```shell
kubectl get deploy,sts,hpa,limitrange -n shop -o yaml > dump/shop.yaml
k8s-hpa-audit audit dump/
```

The condition's reason and message are printed as-is; for example `ScalingActive=False` with
`FailedGetExternalMetric` means the external metrics API does not publish the metric the HPA
asks for. The tool itself still never queries the metrics APIs.

## Install

```shell
go install github.com/moveeeax/k8s-hpa-audit@latest
```

Or build from source:

```shell
git clone https://github.com/moveeeax/k8s-hpa-audit
cd k8s-hpa-audit
go build -o k8s-hpa-audit .
```

## Usage

```shell
# Audit every manifest under ./k8s
k8s-hpa-audit audit ./k8s

# JSON for a dashboard
k8s-hpa-audit audit ./k8s --output json > hpa.json

# Fail the pipeline on any high-severity finding, emit SARIF
k8s-hpa-audit audit ./k8s --fail-on high --output sarif > hpa.sarif
```

Running against the bundled bad examples:

```shell
$ k8s-hpa-audit audit examples/bad
SEVERITY  RULE    RESOURCE                                MESSAGE
high      HPA007  HorizontalPodAutoscaler/queue/consumer  HPA queue/consumer reports ScalingActive=False (FailedGetExternalMetric): the HPA was unable to compute the replica count: unable to get external metric queue/queue_messages_ready/nil: no metrics returned from external metrics API.
high      HPA001  HorizontalPodAutoscaler/batch/api       HPA batch/api has minReplicas==maxReplicas==3; it is a no-op and can never scale.
medium    HPA004  HorizontalPodAutoscaler/batch/cache     HPA batch/cache targets CPU utilization 5%, outside the sane band 20-90%.
high      HPA006  HorizontalPodAutoscaler/batch/checkout  HPA batch/checkout targets cpu utilization but Deployment batch/checkout has no cpu request on container(s) log-shipper; utilization is undefined and the HPA never scales.
high      HPA002  HorizontalPodAutoscaler/batch/ghost     HPA batch/ghost declares no metrics; it has nothing to scale on.
high      HPA003  HorizontalPodAutoscaler/batch/ghost     HPA batch/ghost targets Deployment/deleted-service which is not present in the manifest tree (dangling scaleTargetRef).
medium    HPA008  HorizontalPodAutoscaler/batch/uploader  HPA batch/uploader uses Resource metric "ephemeral-storage"; metrics-server publishes only cpu and memory, so the HPA gets no value for it.
medium    HPA005  Deployment/batch/worker                 Deployment batch/worker has no HorizontalPodAutoscaler; it will never scale automatically.

8 finding(s): 5 high, 3 medium, 0 low
```

### Flags

| Flag             | Default | Description                                                  |
|------------------|---------|--------------------------------------------------------------|
| `--output`, `-o` | `table` | `table`, `json`, or `sarif`.                                 |
| `--fail-on`      | `none`  | Exit non-zero when a finding is at least this severe.        |
| `--cpu-min`      | `20`    | Lowest sane CPU utilization target (percent).                |
| `--cpu-max`      | `90`    | Highest sane CPU utilization target (percent).               |

### Exit codes

| Code | Meaning                                             |
|------|-----------------------------------------------------|
| `0`  | Clean, or findings below the `--fail-on` threshold. |
| `1`  | Usage or runtime error.                             |
| `3`  | Findings at or above the `--fail-on` threshold.     |

## How it works

Each `.yaml`/`.yml` file is split on `---` and decoded with `sigs.k8s.io/yaml` into just the
fields the audit needs. Workloads are indexed by `(kind, name, namespace)`; every HPA's
`scaleTargetRef` is resolved against that index within the same namespace. A workload that no
HPA resolves to raises HPA005; an HPA that resolves to nothing raises HPA003; an HPA that
resolves to a workload has its utilization targets checked against that workload's pod
template (HPA006). The remaining rules are pure checks on the HPA spec and status. Findings are sorted deterministically so diffs and
snapshots stay stable.

## CI example

```yaml
- name: Audit HPA hygiene
  run: |
    go install github.com/moveeeax/k8s-hpa-audit@latest
    k8s-hpa-audit audit ./k8s --fail-on high --output sarif > hpa.sarif
```

Upload `hpa.sarif` with `github/codeql-action/upload-sarif` to see findings in the Security tab.

## License

MIT — see [LICENSE](LICENSE).
