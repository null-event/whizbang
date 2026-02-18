package cred

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nullevent/whizbang/internal/probe"
)

var keyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[a-zA-Z0-9_-]{20,}`),
	regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{20,}`),
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20,}`),
	regexp.MustCompile(`xoxb-[a-zA-Z0-9-]+`),
	regexp.MustCompile(`(?i)["']?[a-z_]*(?:api[_-]?key|secret|token|password)["']?\s*[:=]\s*["']([a-zA-Z0-9_/+=-]{16,})["']`),
}

var configFiles = []string{
	"mcp.json",
	".claude/settings.json",
	".claude/settings.local.json",
	"claude_desktop_config.json",
	".cursorrules",
	".env",
	".env.local",
}

type probe001 struct{}

func New001() probe.Probe {
	return &probe001{}
}

func (p *probe001) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "CRED-001",
		Name:        "Hardcoded API Keys",
		Category:    probe.CategoryCredential,
		Severity:    probe.SeverityCritical,
		Description: "Detects hardcoded API keys, tokens, and passwords in configuration files",
		Tags:        []string{"mcp", "claude", "general"},
	}
}

func (p *probe001) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	var findings []probe.Finding

	for _, cfgFile := range configFiles {
		fullPath := filepath.Join(target.Path, cfgFile)
		f, err := os.Open(fullPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			if strings.Contains(line, "${") || strings.Contains(line, "$ENV{") {
				continue
			}

			for _, pattern := range keyPatterns {
				if pattern.MatchString(line) {
					findings = append(findings, probe.Finding{
						ProbeID:     "CRED-001",
						ProbeName:   "Hardcoded API Key",
						Category:    probe.CategoryCredential,
						Severity:    probe.SeverityCritical,
						Description: "Hardcoded API key or secret found in " + cfgFile,
						Location:    probe.Location{File: cfgFile, Line: lineNum},
						Fixable:     true,
						Remediation: "Replace hardcoded value with environment variable reference (e.g. ${ENV_VAR})",
					})
					break
				}
			}
		}
		f.Close()
	}

	return findings, nil
}

func (p *probe001) Fix(ctx context.Context, finding probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}

func (p *probe001) CanFix() bool {
	return true
}
