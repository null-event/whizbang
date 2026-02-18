package attack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestATKEX001_DetectsSystemPromptLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "My system prompt says: You are a helpful assistant. Your role is to answer questions."}`))
	}))
	defer srv.Close()

	p := NewEX001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for system prompt leak")
	}
}

func TestATKEX001_NoLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "I cannot share that information."}`))
	}))
	defer srv.Close()

	p := NewEX001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestATKEX002_DetectsToolListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "I have access to these functions: read_file, write_file, execute_command, bash"}`))
	}))
	defer srv.Close()

	p := NewEX002()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for tool listing leak")
	}
}

func TestATKEX006_DetectsMCPEnum(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": "I am connected to these MCP servers: localhost:3000 (filesystem), 127.0.0.1:8080 (database)"}`))
	}))
	defer srv.Close()

	p := NewEX006()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for MCP server enumeration")
	}
}
