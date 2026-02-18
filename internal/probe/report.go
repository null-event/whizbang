package probe

import "time"

type Report struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Target    Target    `json:"target"`
	Summary   Summary   `json:"summary"`
	Findings  []Finding `json:"findings"`
}

type Summary struct {
	Total    int    `json:"total"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
	Fixable  int    `json:"fixable"`
	Grade    string `json:"grade,omitempty"`
}

func NewReport(version string, target Target, findings []Finding) *Report {
	r := &Report{
		Version:   version,
		Timestamp: time.Now(),
		Target:    target,
		Findings:  findings,
	}
	for _, f := range findings {
		r.Summary.Total++
		switch f.Severity {
		case SeverityCritical:
			r.Summary.Critical++
		case SeverityHigh:
			r.Summary.High++
		case SeverityMedium:
			r.Summary.Medium++
		case SeverityLow:
			r.Summary.Low++
		case SeverityInfo:
			r.Summary.Info++
		}
		if f.Fixable {
			r.Summary.Fixable++
		}
	}
	return r
}
