package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestSCANMCP001_DetectsExposedSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("data: connected\n\n"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := NewMCP001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for exposed SSE endpoint")
	}
	if findings[0].ProbeID != "SCAN-MCP-001" {
		t.Errorf("expected SCAN-MCP-001, got %s", findings[0].ProbeID)
	}
}

func TestSCANMCP001_NoSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := NewMCP001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestSCANMCP002_DetectsToolsListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tools" || r.URL.Path == "/mcp/tools" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"tools": [{"name": "read_file"}, {"name": "write_file"}]}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := NewMCP002()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for exposed tools listing")
	}
}

func TestSCANMCP002_NoTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := NewMCP002()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestSCANMCP003_DetectsVersionDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "MCP-Server/1.2.3")
		if r.URL.Path == "/" || r.URL.Path == "/mcp" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name": "my-mcp-server", "version": "1.2.3", "capabilities": {"tools": true}}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := NewMCP003()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for version/capability disclosure")
	}
}

func TestSCANMCP003_NoDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := NewMCP003()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
