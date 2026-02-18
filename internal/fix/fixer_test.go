package fix

import (
	"context"
	"testing"

	"github.com/nullevent/whizbang/internal/engine"
	"github.com/nullevent/whizbang/internal/probe"
)

type fixableProbe struct {
	info  probe.ProbeInfo
	fixed bool
}

func (f *fixableProbe) Info() probe.ProbeInfo { return f.info }
func (f *fixableProbe) Scan(ctx context.Context, t *probe.Target) ([]probe.Finding, error) {
	return nil, nil
}
func (f *fixableProbe) Fix(ctx context.Context, finding probe.Finding) (*probe.FixResult, error) {
	f.fixed = true
	return &probe.FixResult{Finding: finding, Description: "fixed"}, nil
}
func (f *fixableProbe) CanFix() bool { return true }

func TestFixerApplyAll(t *testing.T) {
	fp := &fixableProbe{info: probe.ProbeInfo{ID: "TEST-001"}}

	reg := engine.NewRegistry()
	reg.Register(fp)

	findings := []probe.Finding{
		{ProbeID: "TEST-001", Fixable: true},
	}

	fixer := NewFixer()
	results, err := fixer.ApplyAll(context.Background(), reg, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if !fp.fixed {
		t.Error("expected probe Fix to be called")
	}
}

func TestFixerSkipsUnknownProbe(t *testing.T) {
	reg := engine.NewRegistry()

	findings := []probe.Finding{
		{ProbeID: "UNKNOWN-001", Fixable: true},
	}

	fixer := NewFixer()
	results, err := fixer.ApplyAll(context.Background(), reg, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for unknown probe, got %d", len(results))
	}
}
