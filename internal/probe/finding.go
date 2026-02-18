package probe

type Finding struct {
	ProbeID     string   `json:"id"`
	ProbeName   string   `json:"name"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Location    Location `json:"location"`
	Fixable     bool     `json:"fixable"`
	Remediation string   `json:"remediation"`
}

type Location struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	URL  string `json:"url,omitempty"`
}
