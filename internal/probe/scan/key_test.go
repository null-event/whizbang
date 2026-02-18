package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestSCANKEY001_DetectsKeyInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok", "config": {"api_key": "sk-proj-abcdefghijklmnopqrstuv"}}`))
	}))
	defer srv.Close()

	p := NewKEY001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for API key in response")
	}
	if findings[0].ProbeID != "SCAN-KEY-001" {
		t.Errorf("expected SCAN-KEY-001, got %s", findings[0].ProbeID)
	}
}

func TestSCANKEY001_NoKeyInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer srv.Close()

	p := NewKEY001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestSCANKEY002_DetectsReflectedAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server reflects the Authorization header back in the response body
		auth := r.Header.Get("Authorization")
		if auth == "" {
			auth = "Bearer test-token-reflected"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"auth": "` + auth + `", "request_headers": {"authorization": "` + auth + `"}}`))
	}))
	defer srv.Close()

	p := NewKEY002()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for reflected auth header")
	}
}

func TestSCANKEY002_NoReflectedAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer srv.Close()

	p := NewKEY002()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
