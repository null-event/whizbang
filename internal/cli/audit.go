package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/nullevent/whizbang/internal/engine"
	"github.com/nullevent/whizbang/internal/output"
	"github.com/nullevent/whizbang/internal/probe"
	"github.com/spf13/cobra"
)

var (
	auditFormat     string
	auditNoColor    bool
	auditVerbose    bool
	auditWorkers    int
	auditCategories []string
	auditProbes     []string
	auditExclude    []string
	auditSevMin     string
	auditFailAbove  string
)

var auditCmd = &cobra.Command{
	Use:   "audit [path]",
	Short: "Audit local AI agent setup for security issues",
	Long:  "Scans local configuration files, credentials, permissions, and tool setups for security vulnerabilities.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runAudit,
}

func init() {
	auditCmd.Flags().StringVarP(&auditFormat, "format", "f", "text", "output format (text|json|sarif)")
	auditCmd.Flags().BoolVar(&auditNoColor, "no-color", false, "disable colored output")
	auditCmd.Flags().BoolVarP(&auditVerbose, "verbose", "v", false, "show passing checks")
	auditCmd.Flags().IntVarP(&auditWorkers, "workers", "w", runtime.NumCPU(), "number of parallel workers")
	auditCmd.Flags().StringSliceVar(&auditCategories, "category", nil, "filter by category")
	auditCmd.Flags().StringSliceVar(&auditProbes, "probe", nil, "run specific probes by ID")
	auditCmd.Flags().StringSliceVar(&auditExclude, "exclude", nil, "skip specific probes")
	auditCmd.Flags().StringVar(&auditSevMin, "severity-min", "", "minimum severity to report")
	auditCmd.Flags().StringVar(&auditFailAbove, "fail-above", "", "exit 1 if any finding >= severity")

	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	target := &probe.Target{Path: path}

	reg := engine.NewDefaultAuditRegistry()
	probes := selectProbes(reg, auditCategories, auditProbes, auditExclude)

	runner := engine.NewRunner(auditWorkers)
	report := runner.Run(context.Background(), probes, target, appVersion)

	if auditSevMin != "" {
		sev, err := probe.ParseSeverity(auditSevMin)
		if err != nil {
			return err
		}
		report = filterBySeverity(report, sev)
	}

	formatter, err := output.NewFormatter(auditFormat, auditNoColor, auditVerbose)
	if err != nil {
		return err
	}
	if err := formatter.Format(os.Stdout, report); err != nil {
		return err
	}

	if auditFailAbove != "" {
		sev, err := probe.ParseSeverity(auditFailAbove)
		if err != nil {
			return err
		}
		for _, f := range report.Findings {
			if f.Severity.AtLeast(sev) {
				fmt.Fprintf(os.Stderr, "Findings at or above %s severity detected\n", auditFailAbove)
				os.Exit(1)
			}
		}
	} else if report.Summary.Total > 0 {
		os.Exit(1)
	}

	return nil
}
