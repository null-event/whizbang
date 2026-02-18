package output

import (
	"io"

	"github.com/nullevent/whizbang/internal/probe"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type SARIFFormatter struct{}

func (f *SARIFFormatter) Format(w io.Writer, report *probe.Report) error {
	s, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI("whizbang", "https://github.com/nullevent/whizbang")
	run.Tool.Driver.WithVersion(report.Version)

	for _, finding := range report.Findings {
		rule := run.AddRule(finding.ProbeID).
			WithDescription(finding.Description).
			WithShortDescription(&sarif.MultiformatMessageString{Text: &finding.ProbeName})

		result := run.CreateResultForRule(rule.ID).
			WithMessage(sarif.NewTextMessage(finding.Description)).
			WithLevel(sarifLevel(finding.Severity))

		if finding.Location.File != "" {
			loc := sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(finding.Location.File))
			if finding.Location.Line > 0 {
				loc.WithRegion(sarif.NewRegion().WithStartLine(finding.Location.Line))
			}
			result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(loc)})
		} else if finding.Location.URL != "" {
			loc := sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(finding.Location.URL))
			result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(loc)})
		}
	}

	s.AddRun(run)
	return s.Write(w)
}

func sarifLevel(s probe.Severity) string {
	switch s {
	case probe.SeverityCritical, probe.SeverityHigh:
		return "error"
	case probe.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
