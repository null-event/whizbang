package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestJSONFormatter(t *testing.T) {
	report := probe.NewReport("0.1.0", probe.Target{Path: "/tmp"}, []probe.Finding{
		{ProbeID: "CRED-001", Severity: probe.SeverityHigh, Description: "test finding"},
	})

	var buf bytes.Buffer
	f := &JSONFormatter{}
	if err := f.Format(&buf, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var decoded probe.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if decoded.Summary.Total != 1 {
		t.Errorf("expected 1 total, got %d", decoded.Summary.Total)
	}
	if decoded.Version != "0.1.0" {
		t.Errorf("expected version 0.1.0, got %s", decoded.Version)
	}
}
