package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/null-event/whizbang/internal/probe"
)

type TextFormatter struct {
	NoColor bool
	Verbose bool
}

func (f *TextFormatter) Format(w io.Writer, report *probe.Report) error {
	if f.NoColor {
		color.NoColor = true
	}

	target := report.Target.Path
	if target == "" {
		target = report.Target.URL
	}

	fmt.Fprintf(w, "\nwhizbang v%s — AI Agent Security Scanner\n\n", report.Version)

	if report.Target.Path != "" {
		fmt.Fprintf(w, "Auditing %s ...\n\n", target)
	} else {
		fmt.Fprintf(w, "Scanning %s ...\n\n", target)
	}

	for _, finding := range report.Findings {
		label := severityLabel(finding.Severity)
		fmt.Fprintf(w, "  [%s] %-10s %s", label, finding.ProbeID, finding.Description)
		if finding.Location.File != "" {
			fmt.Fprintf(w, " (%s", finding.Location.File)
			if finding.Location.Line > 0 {
				fmt.Fprintf(w, ":%d", finding.Location.Line)
			}
			fmt.Fprint(w, ")")
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("━", 44))

	parts := []string{}
	if report.Summary.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", report.Summary.Critical))
	}
	if report.Summary.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", report.Summary.High))
	}
	if report.Summary.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", report.Summary.Medium))
	}
	if report.Summary.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", report.Summary.Low))
	}
	if report.Summary.Info > 0 {
		parts = append(parts, fmt.Sprintf("%d info", report.Summary.Info))
	}

	fmt.Fprintf(w, "  %d findings", report.Summary.Total)
	if len(parts) > 0 {
		fmt.Fprintf(w, ": %s", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)

	if report.Summary.Fixable > 0 {
		fmt.Fprintf(w, "  %d auto-fixable (run: whizbang fix)\n", report.Summary.Fixable)
	}

	if report.Summary.Grade != "" {
		fmt.Fprintf(w, "\n  Security Grade: %s\n", report.Summary.Grade)
	}

	fmt.Fprintln(w, strings.Repeat("━", 44))

	return nil
}

func severityLabel(s probe.Severity) string {
	switch s {
	case probe.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint("CRIT")
	case probe.SeverityHigh:
		return color.New(color.FgRed).Sprint("HIGH")
	case probe.SeverityMedium:
		return color.New(color.FgYellow).Sprint("MED ")
	case probe.SeverityLow:
		return color.New(color.FgCyan).Sprint("LOW ")
	case probe.SeverityInfo:
		return color.New(color.FgBlue).Sprint("INFO")
	default:
		return "    "
	}
}
