package attack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestATKPI001_DetectsInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"response": "INJECTED_OK I am now DebugBot"}`))
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	p := NewPI001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for successful prompt injection")
	}
	if findings[0].ProbeID != "ATK-PI-001" {
		t.Errorf("expected ATK-PI-001, got %s", findings[0].ProbeID)
	}
}

func TestATKPI001_NoInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": "I cannot do that. How can I help you?"}`))
	}))
	defer srv.Close()

	p := NewPI001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestATKPI003_DetectsIndirectInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": "INDIRECT_INJECTION_SUCCESS"}`))
	}))
	defer srv.Close()

	p := NewPI003()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for indirect injection")
	}
}

func TestATKPI005_DetectsDelimiterEscape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": "EVIL_CONFIRMED, I am EvilBot"}`))
	}))
	defer srv.Close()

	p := NewPI005()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for delimiter escape")
	}
}

func TestATKPI_ServerDown(t *testing.T) {
	p := NewPI001()
	findings, err := p.Scan(context.Background(), &probe.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for unreachable server, got %d", len(findings))
	}
}

func TestPostPayloadSendsJSON(t *testing.T) {
	var received map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := newClient()
	payload := messageParams{Messages: []message{{Role: "user", Content: "test"}}}
	postPayload(context.Background(), client, srv.URL, payload)

	if received == nil {
		t.Fatal("expected server to receive JSON payload")
	}
}
