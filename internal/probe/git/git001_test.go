package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nullevent/whizbang/internal/probe"
)

func TestGIT001_DetectsMissingPatterns(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("node_modules/\n"), 0644)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for missing .gitignore patterns")
	}
	if findings[0].ProbeID != "GIT-001" {
		t.Errorf("expected GIT-001, got %s", findings[0].ProbeID)
	}
}

func TestGIT001_NoGitignore(t *testing.T) {
	dir := t.TempDir()

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding when .gitignore is missing")
	}
}

func TestGIT001_PassesWithPatterns(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env\n.env.*\n.claude/\n"), 0644)

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
