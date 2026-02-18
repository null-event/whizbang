package scan

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/null-event/whizbang/internal/probe"
)

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * 1000000000, // 10s
	}
}

func tryGET(ctx context.Context, client *http.Client, baseURL string, paths []string) (*http.Response, string, error) {
	for _, path := range paths {
		url := strings.TrimRight(baseURL, "/") + path
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return resp, path, nil
		}
		resp.Body.Close()
	}
	return nil, "", nil
}

func readBody(resp *http.Response, maxBytes int64) string {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return ""
	}
	return string(body)
}

// SCAN-MCP-001: Exposed MCP SSE endpoints
type scanMCP001 struct{}

func NewMCP001() probe.Probe { return &scanMCP001{} }

func (p *scanMCP001) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "SCAN-MCP-001",
		Name:        "Exposed MCP SSE Endpoint",
		Category:    probe.CategoryScanMCP,
		Severity:    probe.SeverityHigh,
		Description: "Detects publicly accessible MCP Server-Sent Events endpoints",
		Tags:        []string{"mcp", "network"},
	}
}

func (p *scanMCP001) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	client := newHTTPClient()
	ssePaths := []string{"/sse", "/mcp/sse", "/events", "/mcp/events"}

	resp, path, err := tryGET(ctx, client, target.URL, ssePaths)
	if err != nil || resp == nil {
		return nil, nil
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") || resp.StatusCode == http.StatusOK {
		return []probe.Finding{{
			ProbeID:     "SCAN-MCP-001",
			ProbeName:   "Exposed MCP SSE Endpoint",
			Category:    probe.CategoryScanMCP,
			Severity:    probe.SeverityHigh,
			Description: "MCP SSE endpoint publicly accessible at " + path,
			Location:    probe.Location{URL: target.URL + path},
			Remediation: "Restrict SSE endpoint access with authentication or bind to localhost only",
		}}, nil
	}
	return nil, nil
}

func (p *scanMCP001) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}
func (p *scanMCP001) CanFix() bool { return false }

// SCAN-MCP-002: MCP tools listing accessible without auth
type scanMCP002 struct{}

func NewMCP002() probe.Probe { return &scanMCP002{} }

func (p *scanMCP002) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "SCAN-MCP-002",
		Name:        "MCP Tools Listing Exposed",
		Category:    probe.CategoryScanMCP,
		Severity:    probe.SeverityHigh,
		Description: "Detects MCP tools listing accessible without authentication",
		Tags:        []string{"mcp", "network"},
	}
}

func (p *scanMCP002) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	client := newHTTPClient()
	toolPaths := []string{"/tools", "/mcp/tools", "/api/tools", "/v1/tools"}

	resp, path, err := tryGET(ctx, client, target.URL, toolPaths)
	if err != nil || resp == nil {
		return nil, nil
	}

	body := readBody(resp, 4096)
	if strings.Contains(body, "tools") || strings.Contains(body, "name") {
		return []probe.Finding{{
			ProbeID:     "SCAN-MCP-002",
			ProbeName:   "MCP Tools Listing Exposed",
			Category:    probe.CategoryScanMCP,
			Severity:    probe.SeverityHigh,
			Description: "MCP tools listing accessible without authentication at " + path,
			Location:    probe.Location{URL: target.URL + path},
			Remediation: "Require authentication for tools listing endpoint",
		}}, nil
	}
	return nil, nil
}

func (p *scanMCP002) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}
func (p *scanMCP002) CanFix() bool { return false }

// SCAN-MCP-003: Server version/capability disclosure
type scanMCP003 struct{}

func NewMCP003() probe.Probe { return &scanMCP003{} }

func (p *scanMCP003) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "SCAN-MCP-003",
		Name:        "MCP Server Version Disclosure",
		Category:    probe.CategoryScanMCP,
		Severity:    probe.SeverityMedium,
		Description: "Detects MCP server version and capability information disclosure",
		Tags:        []string{"mcp", "network"},
	}
}

func (p *scanMCP003) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	client := newHTTPClient()
	var findings []probe.Finding

	// Check Server header on root
	rootPaths := []string{"/", "/mcp", "/api", "/health"}
	resp, path, err := tryGET(ctx, client, target.URL, rootPaths)
	if err != nil || resp == nil {
		return nil, nil
	}

	body := readBody(resp, 4096)

	// Check for version info in Server header
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" && (strings.Contains(strings.ToLower(serverHeader), "mcp") ||
		strings.Contains(strings.ToLower(serverHeader), "version")) {
		findings = append(findings, probe.Finding{
			ProbeID:     "SCAN-MCP-003",
			ProbeName:   "MCP Server Version Disclosure",
			Category:    probe.CategoryScanMCP,
			Severity:    probe.SeverityMedium,
			Description: "Server header discloses version info: " + serverHeader,
			Location:    probe.Location{URL: target.URL + path},
			Remediation: "Remove or genericize the Server header to avoid version disclosure",
		})
	}

	// Check for version/capabilities in response body
	if strings.Contains(body, "version") && strings.Contains(body, "capabilities") {
		findings = append(findings, probe.Finding{
			ProbeID:     "SCAN-MCP-003",
			ProbeName:   "MCP Capability Disclosure",
			Category:    probe.CategoryScanMCP,
			Severity:    probe.SeverityMedium,
			Description: "Server capabilities and version publicly disclosed at " + path,
			Location:    probe.Location{URL: target.URL + path},
			Remediation: "Restrict capability/version endpoints to authenticated requests only",
		})
	}

	return findings, nil
}

func (p *scanMCP003) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}
func (p *scanMCP003) CanFix() bool { return false }
