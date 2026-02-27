package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/output"
	"github.com/null-event/whizbang/internal/probe"
	"github.com/spf13/cobra"
)

var (
	attackFormat      string
	attackNoColor     bool
	attackVerbose     bool
	attackWorkers     int
	attackIntensity   string
	attackTimeout     string
	attackDelay       string
	attackStopSuccess bool
	attackCategories  []string
	attackPayloadFile string
	attackAPIFormat   string
)

var attackCmd = &cobra.Command{
	Use:   "attack <target-url>",
	Short: "Red-team test AI agent endpoints",
	Long:  "Active adversarial testing with payloads for prompt injection, data exfiltration, tool abuse, memory poisoning, and config leaks.",
	Args:  cobra.ExactArgs(1),
	RunE:  runAttack,
}

func init() {
	attackCmd.Flags().StringVarP(&attackFormat, "format", "f", "text", "output format (text|json|sarif)")
	attackCmd.Flags().BoolVar(&attackNoColor, "no-color", false, "disable colored output")
	attackCmd.Flags().BoolVarP(&attackVerbose, "verbose", "v", false, "show probe execution progress")
	attackCmd.Flags().IntVarP(&attackWorkers, "workers", "w", runtime.NumCPU(), "number of parallel workers")
	attackCmd.Flags().StringVar(&attackIntensity, "intensity", "active", "payload intensity (passive|active|aggressive)")
	attackCmd.Flags().StringVar(&attackTimeout, "timeout", "10s", "per-probe timeout")
	attackCmd.Flags().StringVar(&attackDelay, "delay", "0s", "delay between probe launches")
	attackCmd.Flags().BoolVar(&attackStopSuccess, "stop-on-success", false, "halt after first successful exploit")
	attackCmd.Flags().StringSliceVar(&attackCategories, "category", nil, "filter by category")
	attackCmd.Flags().StringVar(&attackPayloadFile, "payload-file", "", "custom payloads JSON file")
	attackCmd.Flags().StringVar(&attackAPIFormat, "api-format", "openai", "target API format (openai|anthropic|raw)")

	rootCmd.AddCommand(attackCmd)
}

func runAttack(cmd *cobra.Command, args []string) error {
	target := &probe.Target{
		URL: args[0],
		Options: map[string]string{
			"intensity":  attackIntensity,
			"api-format": attackAPIFormat,
		},
	}

	if attackDelay != "" {
		if d, err := time.ParseDuration(attackDelay); err == nil && d > 0 {
			target.Options["delay"] = attackDelay
		}
	}

	reg := engine.NewDefaultAttackRegistry()
	probes := selectProbes(reg, attackCategories, nil, nil)

	runner := engine.NewRunner(attackWorkers)
	if attackVerbose {
		runner.OnProbe = func(info probe.ProbeInfo, status engine.ProbeStatus, err error) {
			switch status {
			case engine.ProbeStatusStart:
				fmt.Fprintf(os.Stderr, "  ▸ %-12s %s ...\n", info.ID, info.Name)
			case engine.ProbeStatusFail:
				fmt.Fprintf(os.Stderr, "  ✗ %-12s finding detected\n", info.ID)
			case engine.ProbeStatusPass:
				fmt.Fprintf(os.Stderr, "  ✓ %-12s no finding\n", info.ID)
			case engine.ProbeStatusError:
				fmt.Fprintf(os.Stderr, "  ! %-12s error: %v\n", info.ID, err)
			}
		}
	}
	report := runner.Run(context.Background(), probes, target, appVersion)

	formatter, err := output.NewFormatter(attackFormat, attackNoColor, false)
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
