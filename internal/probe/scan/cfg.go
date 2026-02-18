package scan

import (
	"context"
	"strings"

	"github.com/null-event/whizbang/internal/probe"
)

// SCAN-CFG-001: Public config files accessible via HTTP
type scanCFG001 struct{}

func NewCFG001() probe.Probe { return &scanCFG001{} }

func (p *scanCFG001) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "SCAN-CFG-001",
		Name:        "Public Config Files",
		Category:    probe.CategoryScanConfig,
		Severity:    probe.SeverityHigh,
		Description: "Detects configuration files accessible via HTTP without authentication",
		Tags:        []string{"mcp", "network"},
	}
}

func (p *scanCFG001) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	client := newHTTPClient()
	var findings []probe.Finding

	configPaths := []string{
		"/.claude/settings.json",
		"/.claude/settings.local.json",
		"/mcp.json",
		"/claude_desktop_config.json",
		"/.env",
		"/.cursorrules",
		"/CLAUDE.md",
		"/config.json",
		"/config.yaml",
	}

	for _, path := range configPaths {
		paths := []string{path}
		resp, foundPath, err := tryGET(ctx, client, target.URL, paths)
		if err != nil || resp == nil {
			continue
		}
		resp.Body.Close()

		findings = append(findings, probe.Finding{
			ProbeID:     "SCAN-CFG-001",
			ProbeName:   "Public Config File",
			Category:    probe.CategoryScanConfig,
			Severity:    probe.SeverityHigh,
			Description: "Configuration file publicly accessible at " + foundPath,
			Location:    probe.Location{URL: target.URL + foundPath},
			Remediation: "Block access to configuration files via web server rules or remove from public paths",
		})
	}

	return findings, nil
}

func (p *scanCFG001) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) { return nil, nil }
func (p *scanCFG001) CanFix() bool                                                       { return false }

// SCAN-CFG-002: Debug/diagnostic endpoints responding
type scanCFG002 struct{}

func NewCFG002() probe.Probe { return &scanCFG002{} }

func (p *scanCFG002) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "SCAN-CFG-002",
		Name:        "Debug Endpoint Exposed",
		Category:    probe.CategoryScanConfig,
		Severity:    probe.SeverityMedium,
		Description: "Detects debug and diagnostic endpoints that leak internal information",
		Tags:        []string{"network"},
	}
}

func (p *scanCFG002) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	client := newHTTPClient()
	var findings []probe.Finding

	debugPaths := []string{"/debug", "/debug/vars", "/debug/pprof", "/_debug", "/diagnostics", "/internal/status"}

	for _, path := range debugPaths {
		paths := []string{path}
		resp, foundPath, err := tryGET(ctx, client, target.URL, paths)
		if err != nil || resp == nil {
			continue
		}

		body := readBody(resp, 4096)

		// Only flag if the response contains debug-like content
		debugIndicators := []string{"debug", "stack", "trace", "env", "pprof", "goroutine", "memstats", "development"}
		hasIndicator := false
		bodyLower := strings.ToLower(body)
		for _, indicator := range debugIndicators {
			if strings.Contains(bodyLower, indicator) {
				hasIndicator = true
				break
			}
		}

		if hasIndicator {
			findings = append(findings, probe.Finding{
				ProbeID:     "SCAN-CFG-002",
				ProbeName:   "Debug Endpoint Exposed",
				Category:    probe.CategoryScanConfig,
				Severity:    probe.SeverityMedium,
				Description: "Debug/diagnostic endpoint responding at " + foundPath,
				Location:    probe.Location{URL: target.URL + foundPath},
				Remediation: "Disable debug endpoints in production or restrict access to authenticated users",
			})
		}
	}

	return findings, nil
}

func (p *scanCFG002) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) { return nil, nil }
func (p *scanCFG002) CanFix() bool                                                       { return false }
