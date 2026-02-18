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
	fixDryRun bool
	fixYes    bool
	fixProbes []string
)

var fixCmd = &cobra.Command{
	Use:   "fix [path]",
	Short: "Auto-remediate audit findings with backup",
	Long:  "Runs audit, then applies fixes for all fixable findings. Creates backups before modifying files.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runFix,
}

func init() {
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "show diffs without applying changes")
	fixCmd.Flags().BoolVarP(&fixYes, "yes", "y", false, "skip confirmation prompt")
	fixCmd.Flags().StringSliceVar(&fixProbes, "probe", nil, "fix specific probes only")

	rootCmd.AddCommand(fixCmd)
}

func runFix(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	target := &probe.Target{Path: path}

	reg := engine.NewDefaultAuditRegistry()
	probes := selectProbes(reg, nil, fixProbes, nil)
	runner := engine.NewRunner(runtime.NumCPU())
	report := runner.Run(context.Background(), probes, target, appVersion)

	var fixable []probe.Finding
	for _, f := range report.Findings {
		if f.Fixable {
			fixable = append(fixable, f)
		}
	}

	if len(fixable) == 0 {
		fmt.Println("No fixable findings detected.")
		return nil
	}

	formatter, _ := output.NewFormatter("text", false, false)
	fixableReport := probe.NewReport(appVersion, *target, fixable)
	formatter.Format(os.Stdout, fixableReport)

	if fixDryRun {
		fmt.Println("\n(dry run — no changes applied)")
		return nil
	}

	if !fixYes {
		fmt.Printf("\nApply %d fixes? [y/N] ", len(fixable))
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Apply fixes sequentially
	for _, finding := range fixable {
		p := reg.ByID(finding.ProbeID)
		if p == nil || !p.CanFix() {
			continue
		}
		if _, err := p.Fix(context.Background(), finding); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fix %s failed: %v\n", finding.ProbeID, err)
		}
	}

	fmt.Printf("\nApplied fixes. Run 'whizbang audit' to verify.\n")
	return nil
}
