# k8s-hpa-audit
CLI that statically audits Kubernetes manifests for HorizontalPodAutoscaler hygiene: scalable workloads with no HPA, no-op HPAs, missing metrics, out-of-band CPU targets, and dangling scaleTargetRefs, with table/JSON/SARIF output and a CI gate.
