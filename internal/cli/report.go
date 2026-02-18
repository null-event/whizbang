package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/null-event/whizbang/internal/output"
	"github.com/null-event/whizbang/internal/probe"
	"github.com/spf13/cobra"
)

var (
	reportFormat string
	reportOutput string
)

var reportCmd = &cobra.Command{
	Use:   "report <scan-output.json>",
	Short: "Convert scan results between output formats",
	Args:  cobra.ExactArgs(1),
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "sarif", "output format (text|sarif)")
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "output file path (default: stdout)")

	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var report probe.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("parsing input: %w", err)
	}

	formatter, err := output.NewFormatter(reportFormat, false, false)
	if err != nil {
		return err
	}

	w := os.Stdout
	if reportOutput != "" {
		f, err := os.Create(reportOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	return formatter.Format(w, &report)
}
