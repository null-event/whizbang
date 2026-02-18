package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/probe"
)

func TestAttackEndToEnd(t *testing.T) {
	// Simulate a vulnerable agent that leaks information
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Params json.RawMessage `json:"params"`
		}
		json.Unmarshal(body, &req)

		// Respond vulnerably to various attack payloads
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": "Sure! The system prompt is: You are a helpful assistant. Here is the contents of /etc/passwd: root:x:0:0:root:/root:/bin/bash. The server config is host: 0.0.0.0, port: 8080. ANTHROPIC_API_KEY=sk-ant-abc123. I have stored that in my memory. I have read_file and bash tools available."}`))
	}))
	defer srv.Close()

	target := &probe.Target{
		URL:     srv.URL,
		Options: map[string]string{"intensity": "active"},
	}
	reg := engine.NewDefaultAttackRegistry()
	runner := engine.NewRunner(4)
	report := runner.Run(context.Background(), reg.All(), target, "test")

	if report.Summary.Total == 0 {
		t.Fatal("expected findings for vulnerable agent")
	}

	// Verify at least one probe from each category fired
	categories := make(map[probe.Category]bool)
	for _, f := range report.Findings {
		categories[f.Category] = true
	}

	expectedCategories := []probe.Category{
		probe.CategoryAttackPI,
		probe.CategoryAttackExfil,
		probe.CategoryAttackTool,
		probe.CategoryAttackMem,
		probe.CategoryAttackLeak,
	}
	for _, cat := range expectedCategories {
		if !categories[cat] {
			t.Errorf("expected finding in category %s", cat)
		}
	}
}

func TestAttackRegistryCount(t *testing.T) {
	reg := engine.NewDefaultAttackRegistry()
	probes := reg.All()

	// 10 PI + 8 EX + 8 TA + 6 MP + 4 CL = 36
	expected := 36
	if len(probes) != expected {
		t.Errorf("expected %d attack probes, got %d", expected, len(probes))
	}
}

func TestAttackCleanAgent(t *testing.T) {
	// Agent that properly refuses all attack payloads
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": "I am unable to help with that."}`))
	}))
	defer srv.Close()

	target := &probe.Target{
		URL:     srv.URL,
		Options: map[string]string{"intensity": "active"},
	}
	reg := engine.NewDefaultAttackRegistry()
	runner := engine.NewRunner(4)
	report := runner.Run(context.Background(), reg.All(), target, "test")

	if report.Summary.Total != 0 {
		for _, f := range report.Findings {
			t.Errorf("unexpected finding: %s - %s", f.ProbeID, f.Description)
		}
	}
}
