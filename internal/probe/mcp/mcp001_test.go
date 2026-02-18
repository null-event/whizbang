package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestMCP001_DetectsBroadFilesystemAccess(t *testing.T) {
	dir := t.TempDir()

	configFile := filepath.Join(dir, "mcp.json")
	os.WriteFile(configFile, []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
			}
		}
	}`), 0644)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for root filesystem access")
	}
	if findings[0].ProbeID != "MCP-001" {
		t.Errorf("expected MCP-001, got %s", findings[0].ProbeID)
	}
}

func TestMCP001_AllowsScopedAccess(t *testing.T) {
	dir := t.TempDir()

	configFile := filepath.Join(dir, "mcp.json")
	os.WriteFile(configFile, []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/project"]
			}
		}
	}`), 0644)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for scoped access, got %d", len(findings))
	}
}

func TestMCP001_SkipsMissingConfig(t *testing.T) {
	dir := t.TempDir()

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
