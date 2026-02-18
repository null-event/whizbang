package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestSARIFFormatter(t *testing.T) {
	report := probe.NewReport("0.1.0", probe.Target{Path: "/tmp"}, []probe.Finding{
		{
			ProbeID:     "CRED-001",
			ProbeName:   "Hardcoded API Key",
			Severity:    probe.SeverityCritical,
			Description: "Hardcoded API key in config",
			Location:    probe.Location{File: "mcp.json", Line: 14},
		},
	})

	var buf bytes.Buffer
	f := &SARIFFormatter{}
	if err := f.Format(&buf, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if v, ok := raw["version"]; !ok || v != "2.1.0" {
		t.Error("expected SARIF version 2.1.0")
	}
}
