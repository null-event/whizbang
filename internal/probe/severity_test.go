package probe

import "testing"

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityHigh) {
		t.Error("Critical should be at least High")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Error("Low should not be at least High")
	}
}

func TestParseSeverity(t *testing.T) {
	sev, err := ParseSeverity("high")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sev != SeverityHigh {
		t.Errorf("got %v, want High", sev)
	}

	_, err = ParseSeverity("bogus")
	if err == nil {
		t.Error("expected error for bogus severity")
	}
}
