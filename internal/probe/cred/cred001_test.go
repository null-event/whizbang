package cred

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nullevent/whizbang/internal/probe"
)

func TestCRED001_DetectsHardcodedKeys(t *testing.T) {
	dir := t.TempDir()

	configFile := filepath.Join(dir, "mcp.json")
	os.WriteFile(configFile, []byte(`{
		"mcpServers": {
			"example": {
				"env": {
					"OPENAI_API_KEY": "sk-proj-abc123def456ghi789jkl"
				}
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
		t.Fatal("expected at least one finding for hardcoded key")
	}

	if findings[0].ProbeID != "CRED-001" {
		t.Errorf("expected CRED-001, got %s", findings[0].ProbeID)
	}
}

func TestCRED001_NoFalsePositives(t *testing.T) {
	dir := t.TempDir()

	configFile := filepath.Join(dir, "mcp.json")
	os.WriteFile(configFile, []byte(`{
		"mcpServers": {
			"example": {
				"env": {
					"OPENAI_API_KEY": "${OPENAI_API_KEY}"
				}
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
		t.Errorf("expected no findings for env var reference, got %d", len(findings))
	}
}

func TestCRED001_DetectsAnthropicKey(t *testing.T) {
	dir := t.TempDir()

	configFile := filepath.Join(dir, "mcp.json")
	os.WriteFile(configFile, []byte(`{
		"apiKey": "sk-ant-api03-abcdefghijklmnopqrstuvwx"
	}`), 0644)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected finding for Anthropic key")
	}
}

func TestCRED001_SkipsMissingFiles(t *testing.T) {
	dir := t.TempDir()

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d", len(findings))
	}
}
