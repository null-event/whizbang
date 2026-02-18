package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nullevent/whizbang/internal/engine"
	"github.com/nullevent/whizbang/internal/probe"
)

func TestScanEndToEnd(t *testing.T) {
	// Simulate a vulnerable MCP server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("data: connected\n\n"))
		case "/tools":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"tools": [{"name": "read_file"}, {"name": "exec"}]}`))
		case "/.env":
			w.Write([]byte("API_KEY=sk-proj-secretkey1234567890abcdef\n"))
		case "/debug":
			w.Write([]byte(`{"debug": true, "env": "development"}`))
		case "/health":
			w.Write([]byte(`{"status": "ok", "bind": "0.0.0.0:3000"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	target := &probe.Target{URL: srv.URL}
	reg := engine.NewDefaultScanRegistry()
	runner := engine.NewRunner(4)
	report := runner.Run(context.Background(), reg.All(), target, "test")

	if report.Summary.Total == 0 {
		t.Fatal("expected findings for vulnerable server")
	}

	// Verify key probes fired
	probeIDs := make(map[string]bool)
	for _, f := range report.Findings {
		probeIDs[f.ProbeID] = true
	}

	expectedProbes := []string{"SCAN-MCP-001", "SCAN-MCP-002", "SCAN-CFG-001", "SCAN-CFG-002", "SCAN-NET-001"}
	for _, id := range expectedProbes {
		if !probeIDs[id] {
			t.Errorf("expected %s finding", id)
		}
	}

	// Verify severity counts are reasonable
	if report.Summary.High == 0 {
		t.Error("expected at least one high severity finding")
	}
}

func TestScanCleanServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := &probe.Target{URL: srv.URL}
	reg := engine.NewDefaultScanRegistry()
	runner := engine.NewRunner(4)
	report := runner.Run(context.Background(), reg.All(), target, "test")

	// A clean server returning 404 for everything should have minimal findings
	// Only SCAN-NET-002 (plain HTTP) should fire
	for _, f := range report.Findings {
		if f.ProbeID != "SCAN-NET-002" {
			t.Errorf("unexpected finding %s on clean server: %s", f.ProbeID, f.Description)
		}
	}
}
