package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nullevent/whizbang/internal/engine"
	"github.com/nullevent/whizbang/internal/probe"
)

func TestAuditEndToEnd(t *testing.T) {
	dir := t.TempDir()

	// Set up a vulnerable project
	os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
				"env": {
					"API_KEY": "sk-proj-realkey123456789abcdef"
				}
			}
		}
	}`), 0644)

	target := &probe.Target{Path: dir}
	reg := engine.NewDefaultAuditRegistry()
	runner := engine.NewRunner(4)
	report := runner.Run(context.Background(), reg.All(), target, "test")

	if report.Summary.Total == 0 {
		t.Fatal("expected findings for vulnerable setup")
	}

	foundCred := false
	foundMCP := false
	for _, f := range report.Findings {
		if f.ProbeID == "CRED-001" {
			foundCred = true
		}
		if f.ProbeID == "MCP-001" {
			foundMCP = true
		}
	}

	if !foundCred {
		t.Error("expected CRED-001 finding for hardcoded API key")
	}
	if !foundMCP {
		t.Error("expected MCP-001 finding for root filesystem access")
	}
}

func TestAuditCleanProject(t *testing.T) {
	dir := t.TempDir()

	// Set up a clean project — no config files at all
	// GIT-001 will fire because there's no .gitignore, but CRED/MCP/PERM should be clean
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env\n.claude/\n"), 0644)

	target := &probe.Target{Path: dir}
	reg := engine.NewDefaultAuditRegistry()
	runner := engine.NewRunner(4)
	report := runner.Run(context.Background(), reg.All(), target, "test")

	for _, f := range report.Findings {
		if f.ProbeID == "CRED-001" || f.ProbeID == "MCP-001" {
			t.Errorf("unexpected finding %s in clean project: %s", f.ProbeID, f.Description)
		}
	}
}

func TestAuditReportSummary(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(`{
		"mcpServers": {
			"fs": {
				"command": "node",
				"args": ["server.js", "/"],
				"env": {"KEY": "sk-proj-abcdefghijklmnopqrstuv"}
			}
		}
	}`), 0644)

	target := &probe.Target{Path: dir}
	reg := engine.NewDefaultAuditRegistry()
	runner := engine.NewRunner(4)
	report := runner.Run(context.Background(), reg.All(), target, "0.1.0")

	if report.Version != "0.1.0" {
		t.Errorf("expected version 0.1.0, got %s", report.Version)
	}
	if report.Summary.Critical == 0 {
		t.Error("expected at least one critical finding (CRED-001)")
	}
	if report.Summary.High == 0 {
		t.Error("expected at least one high finding (MCP-001)")
	}
}
