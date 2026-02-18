package engine

import (
	"context"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

type stubProbe struct {
	info probe.ProbeInfo
}

func (s *stubProbe) Info() probe.ProbeInfo                                              { return s.info }
func (s *stubProbe) Scan(ctx context.Context, t *probe.Target) ([]probe.Finding, error) { return nil, nil }
func (s *stubProbe) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error)  { return nil, nil }
func (s *stubProbe) CanFix() bool                                                       { return false }

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	p := &stubProbe{info: probe.ProbeInfo{ID: "TEST-001", Category: probe.CategoryCredential}}
	reg.Register(p)

	all := reg.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(all))
	}
	if all[0].Info().ID != "TEST-001" {
		t.Errorf("expected TEST-001, got %s", all[0].Info().ID)
	}
}

func TestRegistryFilterByCategory(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubProbe{info: probe.ProbeInfo{ID: "CRED-001", Category: probe.CategoryCredential}})
	reg.Register(&stubProbe{info: probe.ProbeInfo{ID: "MCP-001", Category: probe.CategoryMCP}})

	filtered := reg.ByCategory(probe.CategoryCredential)
	if len(filtered) != 1 {
		t.Fatalf("expected 1, got %d", len(filtered))
	}
	if filtered[0].Info().ID != "CRED-001" {
		t.Errorf("expected CRED-001, got %s", filtered[0].Info().ID)
	}
}

func TestRegistryFilterByID(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubProbe{info: probe.ProbeInfo{ID: "CRED-001"}})
	reg.Register(&stubProbe{info: probe.ProbeInfo{ID: "MCP-001"}})

	p := reg.ByID("MCP-001")
	if p == nil {
		t.Fatal("expected probe, got nil")
	}
	if p.Info().ID != "MCP-001" {
		t.Errorf("expected MCP-001, got %s", p.Info().ID)
	}

	if reg.ByID("NOPE") != nil {
		t.Error("expected nil for unknown ID")
	}
}
