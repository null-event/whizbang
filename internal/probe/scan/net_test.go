package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestSCANNET001_DetectsWildcardBinding(t *testing.T) {
	// Test server will be on 127.0.0.1 by default, so we simulate
	// detection by checking if the response header indicates binding
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"bind": "0.0.0.0:3000", "host": "0.0.0.0"}`))
	}))
	defer srv.Close()

	p := NewNET001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for 0.0.0.0 binding")
	}
	if findings[0].ProbeID != "SCAN-NET-001" {
		t.Errorf("expected SCAN-NET-001, got %s", findings[0].ProbeID)
	}
}

func TestSCANNET001_NoWildcardBinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer srv.Close()

	p := NewNET001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestSCANNET002_DetectsTLSIssues(t *testing.T) {
	// Create a server with a self-signed cert (TLS issues)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	p := NewNET002()
	// Use the HTTPS URL which has a self-signed cert
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Self-signed cert should be detected
	if len(findings) == 0 {
		t.Fatal("expected finding for TLS certificate issues")
	}
}

func TestSCANNET002_PlainHTTP(t *testing.T) {
	// Plain HTTP server — should flag missing TLS
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	p := NewNET002()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for plain HTTP (no TLS)")
	}
}

// Suppress unused import warnings
var _ = tls.Config{}
var _ = x509.Certificate{}
var _ = strings.Contains
