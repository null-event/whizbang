package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/null-event/whizbang/internal/probe"
)

var dangerousPaths = []string{"/", "/home", "/Users", "/etc", "/var", "/tmp", "C:\\", "C:\\Users"}

var mcpConfigFiles = []string{
	"mcp.json",
	".claude/settings.json",
	".claude/settings.local.json",
	"claude_desktop_config.json",
}

type mcpConfig struct {
	MCPServers map[string]serverConfig `json:"mcpServers"`
}

type serverConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type probe001 struct{}

func New001() probe.Probe {
	return &probe001{}
}

func (p *probe001) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "MCP-001",
		Name:        "Overly Broad Filesystem Access",
		Category:    probe.CategoryMCP,
		Severity:    probe.SeverityHigh,
		Description: "Detects MCP servers with filesystem access scoped to root or other overly broad paths",
		Tags:        []string{"mcp"},
	}
}

func (p *probe001) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	var findings []probe.Finding

	for _, cfgFile := range mcpConfigFiles {
		fullPath := filepath.Join(target.Path, cfgFile)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		var cfg mcpConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}

		for name, server := range cfg.MCPServers {
			for _, arg := range server.Args {
				for _, dangerous := range dangerousPaths {
					if arg == dangerous {
						findings = append(findings, probe.Finding{
							ProbeID:     "MCP-001",
							ProbeName:   "Overly Broad Filesystem Access",
							Category:    probe.CategoryMCP,
							Severity:    probe.SeverityHigh,
							Description: "MCP server '" + name + "' has filesystem access to " + arg,
							Location:    probe.Location{File: cfgFile},
							Fixable:     true,
							Remediation: "Scope filesystem access to the project directory only",
						})
					}
				}
			}
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
