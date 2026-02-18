package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "whizbang.yaml")
	os.WriteFile(cfgFile, []byte(`
workers: 8
timeout: 45s

audit:
  exclude:
    - PERM-003
  severity_min: medium

output:
  format: json
  no_color: true
`), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Workers != 8 {
		t.Errorf("expected 8 workers, got %d", cfg.Workers)
	}
	if cfg.Audit.SeverityMin != "medium" {
		t.Errorf("expected medium, got %s", cfg.Audit.SeverityMin)
	}
	if len(cfg.Audit.Exclude) != 1 || cfg.Audit.Exclude[0] != "PERM-003" {
		t.Errorf("expected [PERM-003], got %v", cfg.Audit.Exclude)
	}
	if cfg.Output.Format != "json" {
		t.Errorf("expected json, got %s", cfg.Output.Format)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Workers != 0 {
		t.Errorf("expected 0, got %d", cfg.Workers)
	}
	if cfg.Output.Format != "" {
		t.Errorf("expected empty, got %s", cfg.Output.Format)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	_, err := Load("/nonexistent/whizbang.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
