package scan

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/null-event/whizbang/internal/probe"
)

// SCAN-NET-001: Services bound to 0.0.0.0
type scanNET001 struct{}

func NewNET001() probe.Probe { return &scanNET001{} }

func (p *scanNET001) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "SCAN-NET-001",
		Name:        "Wildcard Network Binding",
		Category:    probe.CategoryScanNet,
		Severity:    probe.SeverityHigh,
		Description: "Detects services bound to 0.0.0.0 instead of localhost",
		Tags:        []string{"network"},
	}
}

func (p *scanNET001) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	client := newHTTPClient()
	var findings []probe.Finding

	// Check common info endpoints for binding information
	checkPaths := []string{"/", "/health", "/status", "/info", "/api"}

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

		body := readBody(resp, 4096)
		bodyLower := strings.ToLower(body)

		// Look for 0.0.0.0 binding indicators in response
		if strings.Contains(bodyLower, "0.0.0.0") {
			findings = append(findings, probe.Finding{
				ProbeID:     "SCAN-NET-001",
				ProbeName:   "Wildcard Network Binding",
				Category:    probe.CategoryScanNet,
				Severity:    probe.SeverityHigh,
				Description: "Service appears bound to 0.0.0.0 (all interfaces) based on response at " + path,
				Location:    probe.Location{URL: target.URL + path},
				Remediation: "Bind service to 127.0.0.1 instead of 0.0.0.0 to restrict to localhost only",
			})
			break // One finding is enough
		}
	}

	return findings, nil
}

func (p *scanNET001) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) { return nil, nil }
func (p *scanNET001) CanFix() bool                                                       { return false }

// SCAN-NET-002: TLS/certificate issues
type scanNET002 struct{}

func NewNET002() probe.Probe { return &scanNET002{} }

func (p *scanNET002) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "SCAN-NET-002",
		Name:        "TLS Certificate Issues",
		Category:    probe.CategoryScanNet,
		Severity:    probe.SeverityHigh,
		Description: "Detects TLS certificate issues or missing HTTPS on agent endpoints",
		Tags:        []string{"network"},
	}
}

func (p *scanNET002) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	var findings []probe.Finding

	// Check if the target is using plain HTTP
	if strings.HasPrefix(target.URL, "http://") {
		findings = append(findings, probe.Finding{
			ProbeID:     "SCAN-NET-002",
			ProbeName:   "No TLS",
			Category:    probe.CategoryScanNet,
			Severity:    probe.SeverityHigh,
			Description: "Service is using plain HTTP without TLS encryption",
			Location:    probe.Location{URL: target.URL},
			Remediation: "Enable HTTPS with a valid TLS certificate",
		})
		return findings, nil
	}

	// For HTTPS targets, verify the certificate
	if strings.HasPrefix(target.URL, "https://") {
		tlsClient := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
			},
		}

		url := strings.TrimRight(target.URL, "/") + "/"
		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			return nil, nil
		}

		_, err = tlsClient.Do(req)
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "certificate") || strings.Contains(errMsg, "x509") || strings.Contains(errMsg, "tls") {
				findings = append(findings, probe.Finding{
					ProbeID:     "SCAN-NET-002",
					ProbeName:   "TLS Certificate Issue",
					Category:    probe.CategoryScanNet,
					Severity:    probe.SeverityHigh,
					Description: "TLS certificate validation failed: " + errMsg,
					Location:    probe.Location{URL: target.URL},
					Remediation: "Install a valid TLS certificate from a trusted certificate authority",
				})
			}
		}
	}

	return findings, nil
}

func (p *scanNET002) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) { return nil, nil }
func (p *scanNET002) CanFix() bool                                                       { return false }
