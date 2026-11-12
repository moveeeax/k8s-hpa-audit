// Package cmd wires the k8s-hpa-audit CLI.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is set by the build via -ldflags "-X ...cmd.version=...".
var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "k8s-hpa-audit",
		Short: "Static audit of Kubernetes manifests for HorizontalPodAutoscaler hygiene",
		Long: "k8s-hpa-audit reads a tree of Kubernetes manifests and reports autoscaling " +
			"gaps — workloads with no HPA, no-op HPAs, missing metrics, out-of-band CPU " +
			"targets, dangling scaleTargetRefs, utilization targets without requests, and " +
			"status conditions in cluster dumps — without ever contacting a cluster.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newAuditCmd())
	return root
}

// Execute runs the CLI and maps outcomes to process exit codes:
//
//	0  clean, or findings below the --fail-on threshold
//	1  usage or runtime error
//	3  findings at or above the --fail-on threshold
func Execute() {
	err := newRootCmd().Execute()
	if err == nil {
		return
	}
	if ge, ok := err.(*gateError); ok {
		fmt.Fprintln(os.Stderr, ge.Error())
		os.Exit(3)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
