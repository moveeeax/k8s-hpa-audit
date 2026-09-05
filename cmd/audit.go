package cmd

import (
	"fmt"
	"os"

	"github.com/moveeeax/k8s-hpa-audit/internal/audit"
	"github.com/moveeeax/k8s-hpa-audit/internal/report"
	"github.com/spf13/cobra"
)

// gateError signals that findings met or exceeded the --fail-on threshold.
type gateError struct{ msg string }

func (e *gateError) Error() string { return e.msg }

func newAuditCmd() *cobra.Command {
	var (
		output string
		failOn string
		cpuMin int32
		cpuMax int32
	)

	cmd := &cobra.Command{
		Use:   "audit <path>",
		Short: "Audit the manifests under <path>",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ok := report.ParseFormat(output)
			if !ok {
				return fmt.Errorf("invalid --output %q (want table, json, or sarif)", output)
			}
			var threshold audit.Severity
			if failOn != "none" {
				threshold, ok = audit.ParseSeverity(failOn)
				if !ok {
					return fmt.Errorf("invalid --fail-on %q (want none, low, medium, or high)", failOn)
				}
			}
			if cpuMin > cpuMax {
				return fmt.Errorf("--cpu-min (%d) must not exceed --cpu-max (%d)", cpuMin, cpuMax)
			}

			path := args[0]
			if info, err := os.Stat(path); err != nil {
				return fmt.Errorf("cannot read %s: %w", path, err)
			} else if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", path)
			}

			resources, err := audit.LoadDir(path)
			if err != nil {
				return err
			}
			findings := audit.Audit(resources, audit.Options{CPUMin: cpuMin, CPUMax: cpuMax})

			if err := report.Write(cmd.OutOrStdout(), format, findings); err != nil {
				return err
			}

			if threshold != 0 {
				if max := audit.MaxSeverity(findings); max >= threshold {
					return &gateError{msg: fmt.Sprintf(
						"failing: found %s severity findings at or above --fail-on=%s",
						max, threshold)}
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table, json, or sarif")
	cmd.Flags().StringVar(&failOn, "fail-on", "none", "exit non-zero when a finding is at least this severe: none, low, medium, high")
	cmd.Flags().Int32Var(&cpuMin, "cpu-min", 20, "lowest sane CPU utilization target (percent)")
	cmd.Flags().Int32Var(&cpuMax, "cpu-max", 90, "highest sane CPU utilization target (percent)")
	return cmd
}
