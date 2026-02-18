package probe

import "fmt"

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityCritical: "critical",
	SeverityHigh:     "high",
	SeverityMedium:   "medium",
	SeverityLow:      "low",
	SeverityInfo:     "info",
}

var severityFromName = map[string]Severity{
	"critical": SeverityCritical,
	"high":     SeverityHigh,
	"medium":   SeverityMedium,
	"low":      SeverityLow,
	"info":     SeverityInfo,
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", s)
}

func (s Severity) AtLeast(threshold Severity) bool {
	return s >= threshold
}

func ParseSeverity(s string) (Severity, error) {
	if sev, ok := severityFromName[s]; ok {
		return sev, nil
	}
	return 0, fmt.Errorf("unknown severity: %q", s)
}
