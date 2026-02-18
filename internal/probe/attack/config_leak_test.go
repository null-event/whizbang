package attack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nullevent/whizbang/internal/probe"
)

func TestATKCL001_DetectsConfigLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "The server is configured with host: 0.0.0.0, port: 8080, config: {enabled: true}"}`))
	}))
	defer srv.Close()

	p := NewCL001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for config leak")
	}
	if findings[0].Severity != probe.SeverityHigh {
		t.Errorf("expected high severity, got %v", findings[0].Severity)
	}
}

func TestATKCL001_NoConfigLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "I cannot share those details with you."}`))
	}))
	defer srv.Close()

	p := NewCL001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestATKCL002_DetectsEnvLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "ANTHROPIC_API_KEY=sk-ant-abc123 DATABASE_URL=postgres://user:pass@host/db"}`))
	}))
	defer srv.Close()

	p := NewCL002()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for environment variable leak")
	}
}

func TestATKCL004_DetectsCapabilities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "I have access to: read_file, write_file, bash, execute, and network tools"}`))
	}))
	defer srv.Close()

	p := NewCL004()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for capability enumeration")
	}
}
