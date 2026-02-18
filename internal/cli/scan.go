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
	scanFormat     string
	scanNoColor    bool
	scanWorkers    int
	scanTimeout    string
	scanMaxConns   int
	scanCategories []string
	scanExclude    []string
)

var scanCmd = &cobra.Command{
	Use:   "scan <target-url>",
	Short: "Scan external AI agent endpoints for exposure",
	Long:  "Non-exploitative reconnaissance of running agent endpoints. Detects exposed MCP endpoints, public configs, API keys in responses, and debug interfaces.",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", "text", "output format (text|json|sarif)")
	scanCmd.Flags().BoolVar(&scanNoColor, "no-color", false, "disable colored output")
	scanCmd.Flags().IntVarP(&scanWorkers, "workers", "w", runtime.NumCPU(), "number of parallel workers")
	scanCmd.Flags().StringVar(&scanTimeout, "timeout", "10s", "per-probe timeout")
	scanCmd.Flags().IntVar(&scanMaxConns, "max-connections", 10, "max concurrent HTTP connections")
	scanCmd.Flags().StringSliceVar(&scanCategories, "category", nil, "filter by category")
	scanCmd.Flags().StringSliceVar(&scanExclude, "exclude", nil, "skip specific probes")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := &probe.Target{URL: args[0]}

	reg := engine.NewDefaultScanRegistry()
	probes := selectProbes(reg, scanCategories, nil, scanExclude)

	runner := engine.NewRunner(scanWorkers)
	report := runner.Run(context.Background(), probes, target, appVersion)
	report.Summary.Grade = calculateGrade(report)

	formatter, err := output.NewFormatter(scanFormat, scanNoColor, false)
	if err != nil {
		return err
	}
	if err := formatter.Format(os.Stdout, report); err != nil {
		return err
	}

	if report.Summary.Total > 0 {
		os.Exit(1)
	}
	return nil
}

func calculateGrade(report *probe.Report) string {
	score := 100
	for _, f := range report.Findings {
		switch f.Severity {
		case probe.SeverityCritical:
			score -= 25
		case probe.SeverityHigh:
			score -= 15
		case probe.SeverityMedium:
			score -= 8
		case probe.SeverityLow:
			score -= 3
		}
	}
	if score < 0 {
		score = 0
	}

	switch {
	case score >= 90:
		return fmt.Sprintf("A (%d/100)", score)
	case score >= 80:
		return fmt.Sprintf("B (%d/100)", score)
	case score >= 70:
		return fmt.Sprintf("C (%d/100)", score)
	case score >= 60:
		return fmt.Sprintf("D (%d/100)", score)
	default:
		return fmt.Sprintf("F (%d/100)", score)
	}
}
