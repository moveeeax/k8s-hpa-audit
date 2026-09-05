// Command k8s-hpa-audit statically audits Kubernetes manifests for
// HorizontalPodAutoscaler hygiene without ever talking to a cluster.
package main

import "github.com/moveeeax/k8s-hpa-audit/cmd"

func main() {
	cmd.Execute()
}
