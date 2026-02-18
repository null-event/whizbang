package scan

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/null-event/whizbang/internal/probe"
)

var responseKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[a-zA-Z0-9_-]{20,}`),
	regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{20,}`),
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20,}`),
	regexp.MustCompile(`xoxb-[a-zA-Z0-9-]+`),
	regexp.MustCompile(`(?i)["']?(?:api[_-]?key|secret[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']([a-zA-Z0-9_/+=-]{16,})["']`),
}

// SCAN-KEY-001: API keys present in HTTP responses
type scanKEY001 struct{}

func NewKEY001() probe.Probe { return &scanKEY001{} }

func (p *scanKEY001) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "SCAN-KEY-001",
		Name:        "API Keys in Responses",
		Category:    probe.CategoryScanKey,
		Severity:    probe.SeverityCritical,
		Description: "Detects API keys or tokens present in HTTP response bodies",
		Tags:        []string{"network"},
	}
}

func (p *scanKEY001) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	client := newHTTPClient()
	var findings []probe.Finding

	checkPaths := []string{"/", "/health", "/status", "/api", "/config", "/info"}

	for _, path := range checkPaths {
		url := strings.TrimRight(target.URL, "/") + path
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode >= 400 {
			resp.Body.Close()
			continue
		}

		body := readBody(resp, 8192)

		for _, pattern := range responseKeyPatterns {
			if pattern.MatchString(body) {
				findings = append(findings, probe.Finding{
					ProbeID:     "SCAN-KEY-001",
					ProbeName:   "API Key in Response",
					Category:    probe.CategoryScanKey,
					Severity:    probe.SeverityCritical,
					Description: "API key or token found in HTTP response at " + path,
					Location:    probe.Location{URL: target.URL + path},
					Remediation: "Remove API keys from HTTP responses; use server-side environment variables instead",
				})
				break
			}
		}
	}

	return findings, nil
}

func (p *scanKEY001) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}
func (p *scanKEY001) CanFix() bool { return false }

// SCAN-KEY-002: Auth headers reflected in responses
type scanKEY002 struct{}

func NewKEY002() probe.Probe { return &scanKEY002{} }

func (p *scanKEY002) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "SCAN-KEY-002",
		Name:        "Auth Headers Reflected",
		Category:    probe.CategoryScanKey,
		Severity:    probe.SeverityHigh,
		Description: "Detects authorization headers being reflected or logged in HTTP responses",
		Tags:        []string{"network"},
	}
}

func (p *scanKEY002) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	client := newHTTPClient()

	// Send a request with a canary auth header
	canary := "Bearer whizbang-scan-canary-token-12345"
	url := strings.TrimRight(target.URL, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Authorization", canary)

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}

	body := readBody(resp, 8192)

	// Check if the canary token appears in the response
	if strings.Contains(body, "whizbang-scan-canary-token-12345") {
		return []probe.Finding{{
			ProbeID:     "SCAN-KEY-002",
			ProbeName:   "Auth Headers Reflected",
			Category:    probe.CategoryScanKey,
			Severity:    probe.SeverityHigh,
			Description: "Authorization header is reflected in HTTP response body",
			Location:    probe.Location{URL: target.URL},
			Remediation: "Ensure authorization headers are never included in response bodies or logs",
		}}, nil
	}

	// Also check for generic auth reflection patterns
	authIndicators := []string{"authorization", "bearer", "x-api-key"}
	bodyLower := strings.ToLower(body)
	for _, indicator := range authIndicators {
		if strings.Contains(bodyLower, indicator) && strings.Contains(bodyLower, "request_headers") {
			return []probe.Finding{{
				ProbeID:     "SCAN-KEY-002",
				ProbeName:   "Auth Headers Reflected",
				Category:    probe.CategoryScanKey,
				Severity:    probe.SeverityHigh,
				Description: "HTTP response appears to reflect request authorization headers",
				Location:    probe.Location{URL: target.URL},
				Remediation: "Remove request header reflection from API responses",
			}}, nil
		}
	}

	return nil, nil
}

func (p *scanKEY002) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}
func (p *scanKEY002) CanFix() bool { return false }
