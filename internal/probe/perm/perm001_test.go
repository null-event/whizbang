package perm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nullevent/whizbang/internal/probe"
)

func TestPERM001_DetectsWorldReadable(t *testing.T) {
	dir := t.TempDir()

	claudeDir := filepath.Join(dir, ".claude")
	os.MkdirAll(claudeDir, 0755)
	configFile := filepath.Join(claudeDir, "settings.json")
	os.WriteFile(configFile, []byte(`{}`), 0644)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for world-readable config")
	}
	if findings[0].ProbeID != "PERM-001" {
		t.Errorf("expected PERM-001, got %s", findings[0].ProbeID)
	}
}

func TestPERM001_AllowsRestrictive(t *testing.T) {
	dir := t.TempDir()

	claudeDir := filepath.Join(dir, ".claude")
	os.MkdirAll(claudeDir, 0700)
	configFile := filepath.Join(claudeDir, "settings.json")
	os.WriteFile(configFile, []byte(`{}`), 0600)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestPERM001_SkipsMissing(t *testing.T) {
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
