# k8s-hpa-audit

[![ci](https://github.com/moveeeax/k8s-hpa-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-hpa-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Static audit of Kubernetes manifests for **HorizontalPodAutoscaler hygiene**. It reads a
directory of YAML and flags the autoscaling gaps that never fail `kubectl apply` but page you
later: scalable workloads with no HPA, no-op HPAs, HPAs with no metrics, out-of-band CPU
targets, and HPAs pointing at workloads that don't exist.

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

Namespaces are respected: an HPA in `default` will not be considered to cover a workload in
another namespace.

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
SEVERITY  RULE    RESOURCE                             MESSAGE
high      HPA001  HorizontalPodAutoscaler/batch/api    HPA batch/api has minReplicas==maxReplicas==3; it is a no-op and can never scale.
medium    HPA004  HorizontalPodAutoscaler/batch/cache  HPA batch/cache targets CPU utilization 5%, outside the sane band 20-90%.
high      HPA002  HorizontalPodAutoscaler/batch/ghost  HPA batch/ghost declares no metrics; it has nothing to scale on.
high      HPA003  HorizontalPodAutoscaler/batch/ghost  HPA batch/ghost targets Deployment/deleted-service which is not present in the manifest tree (dangling scaleTargetRef).
medium    HPA005  Deployment/batch/worker              Deployment batch/worker has no HorizontalPodAutoscaler; it will never scale automatically.

5 finding(s): 3 high, 2 medium, 0 low
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
HPA resolves to raises HPA005; an HPA that resolves to nothing raises HPA003. The remaining
rules are pure checks on the HPA spec. Findings are sorted deterministically so diffs and
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
