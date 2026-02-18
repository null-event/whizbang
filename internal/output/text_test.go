package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nullevent/whizbang/internal/probe"
)

func TestTextFormatter(t *testing.T) {
	report := probe.NewReport("0.1.0", probe.Target{Path: "/tmp"}, []probe.Finding{
		{ProbeID: "CRED-001", Severity: probe.SeverityCritical, Description: "Hardcoded API key"},
		{ProbeID: "MCP-001", Severity: probe.SeverityHigh, Description: "Broad filesystem access"},
	})

	var buf bytes.Buffer
	f := &TextFormatter{NoColor: true}
	if err := f.Format(&buf, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CRED-001") {
		t.Error("expected output to contain CRED-001")
	}
	if !strings.Contains(out, "CRIT") {
		t.Error("expected output to contain CRIT severity label")
	}
	if !strings.Contains(out, "2 findings") {
		t.Error("expected output to contain finding count")
	}
}

func TestTextFormatterGrade(t *testing.T) {
	report := probe.NewReport("0.1.0", probe.Target{URL: "http://localhost"}, []probe.Finding{
		{ProbeID: "SCAN-MCP-001", Severity: probe.SeverityHigh},
	})
	report.Summary.Grade = "D"

	var buf bytes.Buffer
	f := &TextFormatter{NoColor: true}
	if err := f.Format(&buf, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "Grade: D") {
		t.Error("expected output to contain grade")
	}
}
