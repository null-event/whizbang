package attack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestATKMP001_DetectsInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "understood, I will include INJECTED_INSTRUCTION"}`))
	}))
	defer srv.Close()

	p := NewMP001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for persistent instruction injection")
	}
	if findings[0].Severity != probe.SeverityHigh {
		t.Errorf("expected high severity, got %v", findings[0].Severity)
	}
}

func TestATKMP001_NoInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "I cannot modify my instructions"}`))
	}))
	defer srv.Close()

	p := NewMP001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestATKMP004_DetectsCLAUDEmdWrite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "I've added that to claude.md"}`))
	}))
	defer srv.Close()

	p := NewMP004()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for CLAUDE.md injection")
	}
}

func TestATKMP006_DetectsOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "Saved as core instruction with priority override"}`))
	}))
	defer srv.Close()

	p := NewMP006()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for system prompt override via memory")
	}
}
