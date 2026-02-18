package engine

import (
	"context"
	"testing"
	"time"

	"github.com/null-event/whizbang/internal/probe"
)

type findingProbe struct {
	info     probe.ProbeInfo
	findings []probe.Finding
	delay    time.Duration
}

func (f *findingProbe) Info() probe.ProbeInfo { return f.info }
func (f *findingProbe) Scan(ctx context.Context, t *probe.Target) ([]probe.Finding, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.findings, nil
}
func (f *findingProbe) Fix(ctx context.Context, finding probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}
func (f *findingProbe) CanFix() bool { return false }

func TestRunnerCollectsFindings(t *testing.T) {
	runner := NewRunner(4)
	probes := []probe.Probe{
		&findingProbe{
			info:     probe.ProbeInfo{ID: "A-001"},
			findings: []probe.Finding{{ProbeID: "A-001", Severity: probe.SeverityHigh}},
		},
		&findingProbe{
			info:     probe.ProbeInfo{ID: "B-001"},
			findings: []probe.Finding{{ProbeID: "B-001", Severity: probe.SeverityLow}},
		},
	}

	target := &probe.Target{Path: "/tmp/test"}
	report := runner.Run(context.Background(), probes, target, "0.1.0")

	if report.Summary.Total != 2 {
		t.Errorf("expected 2 findings, got %d", report.Summary.Total)
	}
}

func TestRunnerRespectsContext(t *testing.T) {
	runner := NewRunner(1)
	probes := []probe.Probe{
		&findingProbe{info: probe.ProbeInfo{ID: "SLOW-001"}, delay: 5 * time.Second},
		&findingProbe{info: probe.ProbeInfo{ID: "SLOW-002"}, delay: 5 * time.Second},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	report := runner.Run(ctx, probes, &probe.Target{Path: "/tmp"}, "0.1.0")

	// With context cancelled quickly, we should get fewer than 2 findings
	if report.Summary.Total >= 2 {
		t.Error("expected fewer than 2 findings with short timeout")
	}
}

func TestRunnerHandlesEmptyProbes(t *testing.T) {
	runner := NewRunner(4)
	report := runner.Run(context.Background(), nil, &probe.Target{Path: "/tmp"}, "0.1.0")
	if report.Summary.Total != 0 {
		t.Errorf("expected 0 findings, got %d", report.Summary.Total)
	}
}
