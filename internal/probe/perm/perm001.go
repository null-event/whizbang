package perm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/null-event/whizbang/internal/probe"
)

var sensitiveFiles = []string{
	".claude/settings.json",
	".claude/settings.local.json",
	"mcp.json",
	"claude_desktop_config.json",
	".env",
	".env.local",
}

type probe001 struct{}

func New001() probe.Probe {
	return &probe001{}
}

func (p *probe001) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "PERM-001",
		Name:        "World-Readable Config Files",
		Category:    probe.CategoryPermission,
		Severity:    probe.SeverityMedium,
		Description: "Detects configuration files with overly permissive file permissions",
		Tags:        []string{"general"},
	}
}

func (p *probe001) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	var findings []probe.Finding

	for _, sf := range sensitiveFiles {
		fullPath := filepath.Join(target.Path, sf)
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}

		mode := info.Mode().Perm()
		if mode&0044 != 0 {
			findings = append(findings, probe.Finding{
				ProbeID:     "PERM-001",
				ProbeName:   "World-Readable Config File",
				Category:    probe.CategoryPermission,
				Severity:    probe.SeverityMedium,
				Description: fmt.Sprintf("%s is world-readable (%o)", sf, mode),
				Location:    probe.Location{File: sf},
				Fixable:     true,
				Remediation: "Set restrictive permissions: chmod 600 " + sf,
			})
		}
	}

	return findings, nil
}

func (p *probe001) Fix(ctx context.Context, finding probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}

func (p *probe001) CanFix() bool {
	return true
}
