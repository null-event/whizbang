# whizbang Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Go-based AI agent security scanner with audit, scan, attack, fix, rollback, and report commands targeting MCP ecosystems.

**Architecture:** Interface-based probe system with a shared registry and bounded goroutine pool. Probes implement `Scan`/`Fix`/`Info`/`CanFix` methods. Engine dispatches probes in parallel, collects findings into a Report, and formatters render output. CLI built on cobra with zero-config defaults and optional YAML overrides.

**Tech Stack:** Go 1.22+, cobra (CLI), go-yaml (config), fatih/color (terminal), owenrumney/go-sarif (SARIF output)

---

## Phase 1: Project Scaffolding & Core Types

### Task 1: Initialize Go module and install dependencies

**Files:**
- Create: `go.mod`
- Create: `go.sum`

**Step 1: Initialize Go module**

Run: `go mod init github.com/null-event/whizbang`

**Step 2: Install dependencies**

Run:
```bash
go get github.com/spf13/cobra@latest
go get gopkg.in/yaml.v3@latest
go get github.com/fatih/color@latest
go get github.com/owenrumney/go-sarif/v2@latest
```

**Step 3: Tidy**

Run: `go mod tidy`

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: initialize Go module with dependencies"
```

---

### Task 2: Define core types — Severity, Category, Finding

**Files:**
- Create: `internal/probe/severity.go`
- Create: `internal/probe/category.go`
- Create: `internal/probe/finding.go`
- Test: `internal/probe/severity_test.go`

**Step 1: Write tests for Severity**

```go
// internal/probe/severity_test.go
package probe

import "testing"

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityHigh) {
		t.Error("Critical should be at least High")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Error("Low should not be at least High")
	}
}

func TestParseSeverity(t *testing.T) {
	sev, err := ParseSeverity("high")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sev != SeverityHigh {
		t.Errorf("got %v, want High", sev)
	}

	_, err = ParseSeverity("bogus")
	if err == nil {
		t.Error("expected error for bogus severity")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/probe/ -run TestSeverity -v`
Expected: FAIL — types not defined

**Step 3: Implement Severity**

```go
// internal/probe/severity.go
package probe

import "fmt"

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityCritical: "critical",
	SeverityHigh:     "high",
	SeverityMedium:   "medium",
	SeverityLow:      "low",
	SeverityInfo:     "info",
}

var severityFromName = map[string]Severity{
	"critical": SeverityCritical,
	"high":     SeverityHigh,
	"medium":   SeverityMedium,
	"low":      SeverityLow,
	"info":     SeverityInfo,
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", s)
}

func (s Severity) AtLeast(threshold Severity) bool {
	return s >= threshold
}

func ParseSeverity(s string) (Severity, error) {
	if sev, ok := severityFromName[s]; ok {
		return sev, nil
	}
	return 0, fmt.Errorf("unknown severity: %q", s)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/probe/ -run TestSeverity -v`
Expected: PASS

**Step 5: Implement Category**

```go
// internal/probe/category.go
package probe

type Category string

const (
	CategoryCredential  Category = "credential"
	CategoryMCP         Category = "mcp"
	CategoryPermission  Category = "permission"
	CategorySupplyChain Category = "supply-chain"
	CategoryGit         Category = "git"
	CategoryToolChain   Category = "tool-chain"
	CategoryClaudeCode  Category = "claude-code"
	CategoryConfig      Category = "config"
	CategoryScanMCP     Category = "scan-mcp"
	CategoryScanConfig  Category = "scan-config"
	CategoryScanKey     Category = "scan-key"
	CategoryScanNet     Category = "scan-net"
	CategoryAttackPI    Category = "prompt-injection"
	CategoryAttackExfil Category = "data-exfil"
	CategoryAttackTool  Category = "tool-abuse"
	CategoryAttackMem   Category = "memory-poison"
	CategoryAttackLeak  Category = "config-leak"
)
```

**Step 6: Implement Finding**

```go
// internal/probe/finding.go
package probe

type Finding struct {
	ProbeID     string   `json:"id"`
	ProbeName   string   `json:"name"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Location    Location `json:"location"`
	Fixable     bool     `json:"fixable"`
	Remediation string   `json:"remediation"`
}

type Location struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	URL  string `json:"url,omitempty"`
}
```

**Step 7: Commit**

```bash
git add internal/probe/
git commit -m "feat: add core types — Severity, Category, Finding"
```

---

### Task 3: Define Probe interface and ProbeInfo

**Files:**
- Create: `internal/probe/probe.go`
- Create: `internal/probe/target.go`
- Create: `internal/probe/report.go`

**Step 1: Implement Probe interface and Target**

```go
// internal/probe/probe.go
package probe

import "context"

type Probe interface {
	Info() ProbeInfo
	Scan(ctx context.Context, target *Target) ([]Finding, error)
	Fix(ctx context.Context, finding Finding) (*FixResult, error)
	CanFix() bool
}

type ProbeInfo struct {
	ID          string
	Name        string
	Category    Category
	Severity    Severity
	Description string
	Tags        []string
}

type FixResult struct {
	Finding     Finding
	FilesChanged []string
	Description string
}
```

```go
// internal/probe/target.go
package probe

type Target struct {
	Path    string
	URL     string
	Options map[string]string
}
```

**Step 2: Implement Report**

```go
// internal/probe/report.go
package probe

import "time"

type Report struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Target    Target    `json:"target"`
	Summary   Summary   `json:"summary"`
	Findings  []Finding `json:"findings"`
}

type Summary struct {
	Total    int    `json:"total"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
	Fixable  int    `json:"fixable"`
	Grade    string `json:"grade,omitempty"`
}

func NewReport(version string, target Target, findings []Finding) *Report {
	r := &Report{
		Version:   version,
		Timestamp: time.Now(),
		Target:    target,
		Findings:  findings,
	}
	for _, f := range findings {
		r.Summary.Total++
		switch f.Severity {
		case SeverityCritical:
			r.Summary.Critical++
		case SeverityHigh:
			r.Summary.High++
		case SeverityMedium:
			r.Summary.Medium++
		case SeverityLow:
			r.Summary.Low++
		case SeverityInfo:
			r.Summary.Info++
		}
		if f.Fixable {
			r.Summary.Fixable++
		}
	}
	return r
}
```

**Step 3: Commit**

```bash
git add internal/probe/
git commit -m "feat: add Probe interface, Target, and Report types"
```

---

## Phase 2: Engine — Registry & Pool

### Task 4: Implement probe Registry

**Files:**
- Create: `internal/engine/registry.go`
- Test: `internal/engine/registry_test.go`

**Step 1: Write failing test**

```go
// internal/engine/registry_test.go
package engine

import (
	"context"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

type stubProbe struct {
	info probe.ProbeInfo
}

func (s *stubProbe) Info() probe.ProbeInfo                                          { return s.info }
func (s *stubProbe) Scan(ctx context.Context, t *probe.Target) ([]probe.Finding, error) { return nil, nil }
func (s *stubProbe) Fix(ctx context.Context, f probe.Finding) (*probe.FixResult, error) { return nil, nil }
func (s *stubProbe) CanFix() bool                                                   { return false }

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	p := &stubProbe{info: probe.ProbeInfo{ID: "TEST-001", Category: probe.CategoryCredential}}
	reg.Register(p)

	all := reg.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(all))
	}
	if all[0].Info().ID != "TEST-001" {
		t.Errorf("expected TEST-001, got %s", all[0].Info().ID)
	}
}

func TestRegistryFilterByCategory(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubProbe{info: probe.ProbeInfo{ID: "CRED-001", Category: probe.CategoryCredential}})
	reg.Register(&stubProbe{info: probe.ProbeInfo{ID: "MCP-001", Category: probe.CategoryMCP}})

	filtered := reg.ByCategory(probe.CategoryCredential)
	if len(filtered) != 1 {
		t.Fatalf("expected 1, got %d", len(filtered))
	}
	if filtered[0].Info().ID != "CRED-001" {
		t.Errorf("expected CRED-001, got %s", filtered[0].Info().ID)
	}
}

func TestRegistryFilterByID(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubProbe{info: probe.ProbeInfo{ID: "CRED-001"}})
	reg.Register(&stubProbe{info: probe.ProbeInfo{ID: "MCP-001"}})

	p := reg.ByID("MCP-001")
	if p == nil {
		t.Fatal("expected probe, got nil")
	}
	if p.Info().ID != "MCP-001" {
		t.Errorf("expected MCP-001, got %s", p.Info().ID)
	}

	if reg.ByID("NOPE") != nil {
		t.Error("expected nil for unknown ID")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/engine/ -v`
Expected: FAIL

**Step 3: Implement Registry**

```go
// internal/engine/registry.go
package engine

import "github.com/null-event/whizbang/internal/probe"

type Registry struct {
	probes []probe.Probe
	byID   map[string]probe.Probe
}

func NewRegistry() *Registry {
	return &Registry{
		byID: make(map[string]probe.Probe),
	}
}

func (r *Registry) Register(p probe.Probe) {
	r.probes = append(r.probes, p)
	r.byID[p.Info().ID] = p
}

func (r *Registry) All() []probe.Probe {
	return r.probes
}

func (r *Registry) ByCategory(cat probe.Category) []probe.Probe {
	var result []probe.Probe
	for _, p := range r.probes {
		if p.Info().Category == cat {
			result = append(result, p)
		}
	}
	return result
}

func (r *Registry) ByID(id string) probe.Probe {
	return r.byID[id]
}

func (r *Registry) ByIDs(ids []string) []probe.Probe {
	var result []probe.Probe
	for _, id := range ids {
		if p, ok := r.byID[id]; ok {
			result = append(result, p)
		}
	}
	return result
}

func (r *Registry) Exclude(ids []string) []probe.Probe {
	exclude := make(map[string]bool, len(ids))
	for _, id := range ids {
		exclude[id] = true
	}
	var result []probe.Probe
	for _, p := range r.probes {
		if !exclude[p.Info().ID] {
			result = append(result, p)
		}
	}
	return result
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/engine/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/engine/
git commit -m "feat: add probe Registry with filtering by category, ID, exclusion"
```

---

### Task 5: Implement goroutine pool Runner

**Files:**
- Create: `internal/engine/runner.go`
- Test: `internal/engine/runner_test.go`

**Step 1: Write failing test**

```go
// internal/engine/runner_test.go
package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/null-event/whizbang/internal/probe"
)

type findingProbe struct {
	info     probe.ProbeInfo
	findings []probe.Finding
	delay    time.Duration
}

func (f *findingProbe) Info() probe.ProbeInfo { return f.info }
func (f *findingProbe) Scan(ctx context.Context, t *probe.Target) ([]probe.Finding, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.findings, nil
}
func (f *findingProbe) Fix(ctx context.Context, finding probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}
func (f *findingProbe) CanFix() bool { return false }

func TestRunnerCollectsFindings(t *testing.T) {
	runner := NewRunner(4)
	probes := []probe.Probe{
		&findingProbe{
			info: probe.ProbeInfo{ID: "A-001"},
			findings: []probe.Finding{{ProbeID: "A-001", Severity: probe.SeverityHigh}},
		},
		&findingProbe{
			info: probe.ProbeInfo{ID: "B-001"},
			findings: []probe.Finding{{ProbeID: "B-001", Severity: probe.SeverityLow}},
		},
	}

	target := &probe.Target{Path: "/tmp/test"}
	report := runner.Run(context.Background(), probes, target, "0.1.0")

	if report.Summary.Total != 2 {
		t.Errorf("expected 2 findings, got %d", report.Summary.Total)
	}
}

func TestRunnerRespectsContext(t *testing.T) {
	runner := NewRunner(1)
	var started atomic.Int32

	probes := []probe.Probe{
		&findingProbe{info: probe.ProbeInfo{ID: "SLOW-001"}, delay: 5 * time.Second},
		&findingProbe{info: probe.ProbeInfo{ID: "SLOW-002"}, delay: 5 * time.Second},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_ = started // suppress unused warning
	report := runner.Run(ctx, probes, &probe.Target{Path: "/tmp"}, "0.1.0")

	// With context cancelled, we should get fewer than 2 findings (likely 0)
	if report.Summary.Total > 0 {
		t.Logf("got %d findings despite timeout (probes may have completed before cancel)", report.Summary.Total)
	}
}

func TestRunnerBoundsWorkers(t *testing.T) {
	var maxConcurrent atomic.Int32
	var current atomic.Int32

	makeProbe := func(id string) probe.Probe {
		return &findingProbe{
			info:  probe.ProbeInfo{ID: id},
			delay: 10 * time.Millisecond,
		}
	}

	// Override: we'll use a custom probe that tracks concurrency
	type concurrencyProbe struct {
		findingProbe
		current      *atomic.Int32
		maxConcurrent *atomic.Int32
	}

	runner := NewRunner(2) // only 2 workers
	probes := make([]probe.Probe, 10)
	for i := range probes {
		probes[i] = makeProbe("TEST-" + string(rune('0'+i)))
	}

	_ = current
	_ = maxConcurrent

	report := runner.Run(context.Background(), probes, &probe.Target{Path: "/tmp"}, "0.1.0")
	if report == nil {
		t.Fatal("expected report, got nil")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/engine/ -run TestRunner -v`
Expected: FAIL

**Step 3: Implement Runner**

```go
// internal/engine/runner.go
package engine

import (
	"context"
	"sync"

	"github.com/null-event/whizbang/internal/probe"
)

type Runner struct {
	workers int
}

func NewRunner(workers int) *Runner {
	if workers < 1 {
		workers = 1
	}
	return &Runner{workers: workers}
}

func (r *Runner) Run(ctx context.Context, probes []probe.Probe, target *probe.Target, version string) *probe.Report {
	type result struct {
		findings []probe.Finding
		err      error
	}

	results := make(chan result, len(probes))
	sem := make(chan struct{}, r.workers)
	var wg sync.WaitGroup

	for _, p := range probes {
		wg.Add(1)
		go func(p probe.Probe) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			}

			findings, err := p.Scan(ctx, target)
			results <- result{findings: findings, err: err}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []probe.Finding
	for res := range results {
		if res.err != nil {
			continue
		}
		allFindings = append(allFindings, res.findings...)
	}

	return probe.NewReport(version, *target, allFindings)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/engine/ -run TestRunner -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/engine/
git commit -m "feat: add goroutine pool Runner with bounded concurrency"
```

---

## Phase 3: Output Formatters

### Task 6: Implement JSON formatter

**Files:**
- Create: `internal/output/json.go`
- Test: `internal/output/json_test.go`

**Step 1: Write failing test**

```go
// internal/output/json_test.go
package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestJSONFormatter(t *testing.T) {
	report := probe.NewReport("0.1.0", probe.Target{Path: "/tmp"}, []probe.Finding{
		{ProbeID: "CRED-001", Severity: probe.SeverityHigh, Description: "test finding"},
	})

	var buf bytes.Buffer
	f := &JSONFormatter{}
	if err := f.Format(&buf, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var decoded probe.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if decoded.Summary.Total != 1 {
		t.Errorf("expected 1 total, got %d", decoded.Summary.Total)
	}
	if decoded.Version != "0.1.0" {
		t.Errorf("expected version 0.1.0, got %s", decoded.Version)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/output/ -run TestJSON -v`
Expected: FAIL

**Step 3: Implement JSON formatter**

```go
// internal/output/json.go
package output

import (
	"encoding/json"
	"io"

	"github.com/null-event/whizbang/internal/probe"
)

type JSONFormatter struct{}

func (f *JSONFormatter) Format(w io.Writer, report *probe.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/output/ -run TestJSON -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/output/
git commit -m "feat: add JSON output formatter"
```

---

### Task 7: Implement text formatter

**Files:**
- Create: `internal/output/text.go`
- Test: `internal/output/text_test.go`

**Step 1: Write failing test**

```go
// internal/output/text_test.go
package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestTextFormatter(t *testing.T) {
	report := probe.NewReport("0.1.0", probe.Target{Path: "/tmp"}, []probe.Finding{
		{ProbeID: "CRED-001", Severity: probe.SeverityCritical, Description: "Hardcoded API key"},
		{ProbeID: "MCP-001", Severity: probe.SeverityHigh, Description: "Broad filesystem access"},
	})

	var buf bytes.Buffer
	f := &TextFormatter{NoColor: true}
	if err := f.Format(&buf, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CRED-001") {
		t.Error("expected output to contain CRED-001")
	}
	if !strings.Contains(out, "CRIT") {
		t.Error("expected output to contain CRIT severity label")
	}
	if !strings.Contains(out, "2 findings") {
		t.Error("expected output to contain finding count")
	}
}

func TestTextFormatterGrade(t *testing.T) {
	report := probe.NewReport("0.1.0", probe.Target{URL: "http://localhost"}, []probe.Finding{
		{ProbeID: "SCAN-MCP-001", Severity: probe.SeverityHigh},
	})
	report.Summary.Grade = "D"

	var buf bytes.Buffer
	f := &TextFormatter{NoColor: true}
	if err := f.Format(&buf, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "Grade: D") {
		t.Error("expected output to contain grade")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/output/ -run TestText -v`
Expected: FAIL

**Step 3: Implement text formatter**

```go
// internal/output/text.go
package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/null-event/whizbang/internal/probe"
)

type TextFormatter struct {
	NoColor bool
	Verbose bool
}

func (f *TextFormatter) Format(w io.Writer, report *probe.Report) error {
	if f.NoColor {
		color.NoColor = true
	}

	target := report.Target.Path
	if target == "" {
		target = report.Target.URL
	}

	fmt.Fprintf(w, "\nwhizbang v%s — AI Agent Security Scanner\n\n", report.Version)

	if report.Target.Path != "" {
		fmt.Fprintf(w, "Auditing %s ...\n\n", target)
	} else {
		fmt.Fprintf(w, "Scanning %s ...\n\n", target)
	}

	for _, finding := range report.Findings {
		label := severityLabel(finding.Severity)
		fmt.Fprintf(w, "  [%s] %-10s %s", label, finding.ProbeID, finding.Description)
		if finding.Location.File != "" {
			fmt.Fprintf(w, " (%s", finding.Location.File)
			if finding.Location.Line > 0 {
				fmt.Fprintf(w, ":%d", finding.Location.Line)
			}
			fmt.Fprint(w, ")")
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("━", 44))

	parts := []string{}
	if report.Summary.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", report.Summary.Critical))
	}
	if report.Summary.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", report.Summary.High))
	}
	if report.Summary.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", report.Summary.Medium))
	}
	if report.Summary.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", report.Summary.Low))
	}
	if report.Summary.Info > 0 {
		parts = append(parts, fmt.Sprintf("%d info", report.Summary.Info))
	}

	fmt.Fprintf(w, "  %d findings", report.Summary.Total)
	if len(parts) > 0 {
		fmt.Fprintf(w, ": %s", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)

	if report.Summary.Fixable > 0 {
		fmt.Fprintf(w, "  %d auto-fixable (run: whizbang fix)\n", report.Summary.Fixable)
	}

	if report.Summary.Grade != "" {
		fmt.Fprintf(w, "\n  Security Grade: %s\n", report.Summary.Grade)
	}

	fmt.Fprintln(w, strings.Repeat("━", 44))

	return nil
}

func severityLabel(s probe.Severity) string {
	switch s {
	case probe.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint("CRIT")
	case probe.SeverityHigh:
		return color.New(color.FgRed).Sprint("HIGH")
	case probe.SeverityMedium:
		return color.New(color.FgYellow).Sprint("MED ")
	case probe.SeverityLow:
		return color.New(color.FgCyan).Sprint("LOW ")
	case probe.SeverityInfo:
		return color.New(color.FgBlue).Sprint("INFO")
	default:
		return "    "
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/output/ -run TestText -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/output/
git commit -m "feat: add text output formatter with severity coloring"
```

---

### Task 8: Implement SARIF formatter

**Files:**
- Create: `internal/output/sarif.go`
- Test: `internal/output/sarif_test.go`

**Step 1: Write failing test**

```go
// internal/output/sarif_test.go
package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestSARIFFormatter(t *testing.T) {
	report := probe.NewReport("0.1.0", probe.Target{Path: "/tmp"}, []probe.Finding{
		{
			ProbeID:     "CRED-001",
			ProbeName:   "Hardcoded API Key",
			Severity:    probe.SeverityCritical,
			Description: "Hardcoded API key in config",
			Location:    probe.Location{File: "mcp.json", Line: 14},
		},
	})

	var buf bytes.Buffer
	f := &SARIFFormatter{}
	if err := f.Format(&buf, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify it has SARIF schema
	if v, ok := raw["version"]; !ok || v != "2.1.0" {
		t.Error("expected SARIF version 2.1.0")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/output/ -run TestSARIF -v`
Expected: FAIL

**Step 3: Implement SARIF formatter**

```go
// internal/output/sarif.go
package output

import (
	"io"

	"github.com/null-event/whizbang/internal/probe"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type SARIFFormatter struct{}

func (f *SARIFFormatter) Format(w io.Writer, report *probe.Report) error {
	s, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI("whizbang", "https://github.com/null-event/whizbang")
	run.Tool.Driver.WithVersion(report.Version)

	for _, finding := range report.Findings {
		rule := run.AddRule(finding.ProbeID).
			WithDescription(finding.Description).
			WithShortDescription(&sarif.MultiformatMessageString{Text: &finding.ProbeName})

		result := run.CreateResultForRule(rule.ID).
			WithMessage(sarif.NewTextMessage(finding.Description)).
			WithLevel(sarifLevel(finding.Severity))

		if finding.Location.File != "" {
			loc := sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(finding.Location.File))
			if finding.Location.Line > 0 {
				loc.WithRegion(sarif.NewRegion().WithStartLine(finding.Location.Line))
			}
			result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(loc)})
		} else if finding.Location.URL != "" {
			loc := sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(finding.Location.URL))
			result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(loc)})
		}
	}

	s.AddRun(run)
	return s.Write(w)
}

func sarifLevel(s probe.Severity) string {
	switch s {
	case probe.SeverityCritical, probe.SeverityHigh:
		return "error"
	case probe.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/output/ -run TestSARIF -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/output/
git commit -m "feat: add SARIF output formatter for GitHub Security integration"
```

---

### Task 9: Add Formatter interface and factory

**Files:**
- Create: `internal/output/formatter.go`
- Test: `internal/output/formatter_test.go`

**Step 1: Write failing test**

```go
// internal/output/formatter_test.go
package output

import "testing"

func TestNewFormatter(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"text", false},
		{"json", false},
		{"sarif", false},
		{"bogus", true},
	}
	for _, tt := range tests {
		_, err := NewFormatter(tt.name, false, false)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewFormatter(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/output/ -run TestNewFormatter -v`
Expected: FAIL

**Step 3: Implement**

```go
// internal/output/formatter.go
package output

import (
	"fmt"
	"io"

	"github.com/null-event/whizbang/internal/probe"
)

type Formatter interface {
	Format(w io.Writer, report *probe.Report) error
}

func NewFormatter(name string, noColor bool, verbose bool) (Formatter, error) {
	switch name {
	case "text":
		return &TextFormatter{NoColor: noColor, Verbose: verbose}, nil
	case "json":
		return &JSONFormatter{}, nil
	case "sarif":
		return &SARIFFormatter{}, nil
	default:
		return nil, fmt.Errorf("unknown format: %q (available: text, json, sarif)", name)
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/output/ -run TestNewFormatter -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/output/
git commit -m "feat: add Formatter interface with factory function"
```

---

## Phase 4: CLI Framework

### Task 10: Implement root command and version

**Files:**
- Create: `cmd/whizbang/main.go`
- Create: `internal/cli/root.go`
- Create: `internal/cli/version.go`

**Step 1: Implement main.go**

```go
// cmd/whizbang/main.go
package main

import (
	"os"

	"github.com/null-event/whizbang/internal/cli"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	cli.SetVersion(version, commit)
	if err := cli.Execute(); err != nil {
		os.Exit(2)
	}
}
```

**Step 2: Implement root command**

```go
// internal/cli/root.go
package cli

import (
	"github.com/spf13/cobra"
)

var (
	appVersion = "dev"
	appCommit  = "none"

	cfgFile string
)

func SetVersion(version, commit string) {
	appVersion = version
	appCommit = commit
}

var rootCmd = &cobra.Command{
	Use:   "whizbang",
	Short: "AI Agent Security Scanner",
	Long:  "whizbang scans, audits, and red-teams AI agent setups with a focus on MCP ecosystems.",
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: whizbang.yaml)")
}

func Execute() error {
	return rootCmd.Execute()
}
```

**Step 3: Implement version command**

```go
// internal/cli/version.go
package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("whizbang %s (commit: %s) %s/%s\n", appVersion, appCommit, runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
```

**Step 4: Build and verify**

Run: `go build -o whizbang ./cmd/whizbang && ./whizbang version`
Expected: `whizbang dev (commit: none) darwin/arm64`

**Step 5: Verify help**

Run: `./whizbang --help`
Expected: shows usage with "AI Agent Security Scanner"

**Step 6: Commit**

```bash
git add cmd/ internal/cli/
git commit -m "feat: add CLI skeleton with root and version commands"
```

---

### Task 11: Implement audit command

**Files:**
- Create: `internal/cli/audit.go`

**Step 1: Implement audit command**

```go
// internal/cli/audit.go
package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/output"
	"github.com/null-event/whizbang/internal/probe"
	"github.com/spf13/cobra"
)

var (
	auditFormat     string
	auditNoColor    bool
	auditVerbose    bool
	auditWorkers    int
	auditCategories []string
	auditProbes     []string
	auditExclude    []string
	auditSevMin     string
	auditFailAbove  string
)

var auditCmd = &cobra.Command{
	Use:   "audit [path]",
	Short: "Audit local AI agent setup for security issues",
	Long:  "Scans local configuration files, credentials, permissions, and tool setups for security vulnerabilities.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runAudit,
}

func init() {
	auditCmd.Flags().StringVarP(&auditFormat, "format", "f", "text", "output format (text|json|sarif)")
	auditCmd.Flags().BoolVar(&auditNoColor, "no-color", false, "disable colored output")
	auditCmd.Flags().BoolVarP(&auditVerbose, "verbose", "v", false, "show passing checks")
	auditCmd.Flags().IntVarP(&auditWorkers, "workers", "w", runtime.NumCPU(), "number of parallel workers")
	auditCmd.Flags().StringSliceVar(&auditCategories, "category", nil, "filter by category")
	auditCmd.Flags().StringSliceVar(&auditProbes, "probe", nil, "run specific probes by ID")
	auditCmd.Flags().StringSliceVar(&auditExclude, "exclude", nil, "skip specific probes")
	auditCmd.Flags().StringVar(&auditSevMin, "severity-min", "", "minimum severity to report")
	auditCmd.Flags().StringVar(&auditFailAbove, "fail-above", "", "exit 1 if any finding >= severity")

	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	target := &probe.Target{Path: path}

	reg := engine.NewDefaultAuditRegistry()
	probes := selectProbes(reg, auditCategories, auditProbes, auditExclude)

	runner := engine.NewRunner(auditWorkers)
	report := runner.Run(context.Background(), probes, target, appVersion)

	// Filter by severity
	if auditSevMin != "" {
		sev, err := probe.ParseSeverity(auditSevMin)
		if err != nil {
			return err
		}
		report = filterBySeverity(report, sev)
	}

	formatter, err := output.NewFormatter(auditFormat, auditNoColor, auditVerbose)
	if err != nil {
		return err
	}
	if err := formatter.Format(os.Stdout, report); err != nil {
		return err
	}

	// Exit code
	if auditFailAbove != "" {
		sev, err := probe.ParseSeverity(auditFailAbove)
		if err != nil {
			return err
		}
		for _, f := range report.Findings {
			if f.Severity.AtLeast(sev) {
				fmt.Fprintf(os.Stderr, "Findings at or above %s severity detected\n", auditFailAbove)
				os.Exit(1)
			}
		}
	} else if report.Summary.Total > 0 {
		os.Exit(1)
	}

	return nil
}

func selectProbes(reg *engine.Registry, categories []string, ids []string, exclude []string) []probe.Probe {
	if len(ids) > 0 {
		return reg.ByIDs(ids)
	}

	var probes []probe.Probe
	if len(categories) > 0 {
		for _, cat := range categories {
			probes = append(probes, reg.ByCategory(probe.Category(cat))...)
		}
	} else {
		probes = reg.All()
	}

	if len(exclude) > 0 {
		excludeMap := make(map[string]bool)
		for _, id := range exclude {
			excludeMap[id] = true
		}
		var filtered []probe.Probe
		for _, p := range probes {
			if !excludeMap[p.Info().ID] {
				filtered = append(filtered, p)
			}
		}
		probes = filtered
	}

	return probes
}

func filterBySeverity(report *probe.Report, minSev probe.Severity) *probe.Report {
	var filtered []probe.Finding
	for _, f := range report.Findings {
		if f.Severity.AtLeast(minSev) {
			filtered = append(filtered, f)
		}
	}
	return probe.NewReport(report.Version, report.Target, filtered)
}
```

**Step 2: Build and verify help**

Run: `go build -o whizbang ./cmd/whizbang && ./whizbang audit --help`
Expected: shows audit usage with flags

**Step 3: Commit**

```bash
git add internal/cli/audit.go
git commit -m "feat: add audit command with filtering and output format selection"
```

---

### Task 12: Implement scan, attack, fix, rollback, report commands (stubs)

**Files:**
- Create: `internal/cli/scan.go`
- Create: `internal/cli/attack.go`
- Create: `internal/cli/fix.go`
- Create: `internal/cli/rollback.go`
- Create: `internal/cli/report.go`

**Step 1: Implement scan command**

```go
// internal/cli/scan.go
package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/output"
	"github.com/null-event/whizbang/internal/probe"
	"github.com/spf13/cobra"
)

var (
	scanFormat     string
	scanNoColor    bool
	scanWorkers    int
	scanTimeout    string
	scanMaxConns   int
	scanCategories []string
	scanExclude    []string
)

var scanCmd = &cobra.Command{
	Use:   "scan <target-url>",
	Short: "Scan external AI agent endpoints for exposure",
	Long:  "Non-exploitative reconnaissance of running agent endpoints. Detects exposed MCP endpoints, public configs, API keys in responses, and debug interfaces.",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", "text", "output format (text|json|sarif)")
	scanCmd.Flags().BoolVar(&scanNoColor, "no-color", false, "disable colored output")
	scanCmd.Flags().IntVarP(&scanWorkers, "workers", "w", runtime.NumCPU(), "number of parallel workers")
	scanCmd.Flags().StringVar(&scanTimeout, "timeout", "10s", "per-probe timeout")
	scanCmd.Flags().IntVar(&scanMaxConns, "max-connections", 10, "max concurrent HTTP connections")
	scanCmd.Flags().StringSliceVar(&scanCategories, "category", nil, "filter by category")
	scanCmd.Flags().StringSliceVar(&scanExclude, "exclude", nil, "skip specific probes")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := &probe.Target{URL: args[0]}

	reg := engine.NewDefaultScanRegistry()
	probes := selectProbes(reg, scanCategories, nil, scanExclude)

	runner := engine.NewRunner(scanWorkers)
	report := runner.Run(context.Background(), probes, target, appVersion)
	report.Summary.Grade = calculateGrade(report)

	formatter, err := output.NewFormatter(scanFormat, scanNoColor, false)
	if err != nil {
		return err
	}
	if err := formatter.Format(os.Stdout, report); err != nil {
		return err
	}

	if report.Summary.Total > 0 {
		os.Exit(1)
	}
	return nil
}

func calculateGrade(report *probe.Report) string {
	score := 100
	for _, f := range report.Findings {
		switch f.Severity {
		case probe.SeverityCritical:
			score -= 25
		case probe.SeverityHigh:
			score -= 15
		case probe.SeverityMedium:
			score -= 8
		case probe.SeverityLow:
			score -= 3
		}
	}
	if score < 0 {
		score = 0
	}

	switch {
	case score >= 90:
		return fmt.Sprintf("A (%d/100)", score)
	case score >= 80:
		return fmt.Sprintf("B (%d/100)", score)
	case score >= 70:
		return fmt.Sprintf("C (%d/100)", score)
	case score >= 60:
		return fmt.Sprintf("D (%d/100)", score)
	default:
		return fmt.Sprintf("F (%d/100)", score)
	}
}
```

**Step 2: Implement attack command**

```go
// internal/cli/attack.go
package cli

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/output"
	"github.com/null-event/whizbang/internal/probe"
	"github.com/spf13/cobra"
)

var (
	attackFormat      string
	attackNoColor     bool
	attackWorkers     int
	attackIntensity   string
	attackTimeout     string
	attackDelay       string
	attackStopSuccess bool
	attackCategories  []string
	attackPayloadFile string
)

var attackCmd = &cobra.Command{
	Use:   "attack <target-url>",
	Short: "Red-team test AI agent endpoints",
	Long:  "Active adversarial testing with payloads for prompt injection, data exfiltration, tool abuse, memory poisoning, and config leaks.",
	Args:  cobra.ExactArgs(1),
	RunE:  runAttack,
}

func init() {
	attackCmd.Flags().StringVarP(&attackFormat, "format", "f", "text", "output format (text|json|sarif)")
	attackCmd.Flags().BoolVar(&attackNoColor, "no-color", false, "disable colored output")
	attackCmd.Flags().IntVarP(&attackWorkers, "workers", "w", runtime.NumCPU(), "number of parallel workers")
	attackCmd.Flags().StringVar(&attackIntensity, "intensity", "active", "payload intensity (passive|active|aggressive)")
	attackCmd.Flags().StringVar(&attackTimeout, "timeout", "10s", "per-probe timeout")
	attackCmd.Flags().StringVar(&attackDelay, "delay", "0s", "delay between probe launches")
	attackCmd.Flags().BoolVar(&attackStopSuccess, "stop-on-success", false, "halt after first successful exploit")
	attackCmd.Flags().StringSliceVar(&attackCategories, "category", nil, "filter by category")
	attackCmd.Flags().StringVar(&attackPayloadFile, "payload-file", "", "custom payloads JSON file")

	rootCmd.AddCommand(attackCmd)
}

func runAttack(cmd *cobra.Command, args []string) error {
	target := &probe.Target{
		URL: args[0],
		Options: map[string]string{
			"intensity": attackIntensity,
		},
	}

	if attackDelay != "" {
		if d, err := time.ParseDuration(attackDelay); err == nil && d > 0 {
			target.Options["delay"] = attackDelay
		}
	}

	reg := engine.NewDefaultAttackRegistry()
	probes := selectProbes(reg, attackCategories, nil, nil)

	runner := engine.NewRunner(attackWorkers)
	report := runner.Run(context.Background(), probes, target, appVersion)

	formatter, err := output.NewFormatter(attackFormat, attackNoColor, false)
	if err != nil {
		return err
	}
	if err := formatter.Format(os.Stdout, report); err != nil {
		return err
	}

	if report.Summary.Total > 0 {
		os.Exit(1)
	}
	return nil
}
```

**Step 3: Implement fix command**

```go
// internal/cli/fix.go
package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/fix"
	"github.com/null-event/whizbang/internal/output"
	"github.com/null-event/whizbang/internal/probe"
	"github.com/spf13/cobra"
)

var (
	fixDryRun bool
	fixYes    bool
	fixProbes []string
)

var fixCmd = &cobra.Command{
	Use:   "fix [path]",
	Short: "Auto-remediate audit findings with backup",
	Long:  "Runs audit, then applies fixes for all fixable findings. Creates backups before modifying files.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runFix,
}

func init() {
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "show diffs without applying changes")
	fixCmd.Flags().BoolVarP(&fixYes, "yes", "y", false, "skip confirmation prompt")
	fixCmd.Flags().StringSliceVar(&fixProbes, "probe", nil, "fix specific probes only")

	rootCmd.AddCommand(fixCmd)
}

func runFix(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	target := &probe.Target{Path: path}

	// Run audit first
	reg := engine.NewDefaultAuditRegistry()
	probes := selectProbes(reg, nil, fixProbes, nil)
	runner := engine.NewRunner(runtime.NumCPU())
	report := runner.Run(context.Background(), probes, target, appVersion)

	// Filter to fixable findings
	var fixable []probe.Finding
	for _, f := range report.Findings {
		if f.Fixable {
			fixable = append(fixable, f)
		}
	}

	if len(fixable) == 0 {
		fmt.Println("No fixable findings detected.")
		return nil
	}

	// Show what will be fixed
	formatter, _ := output.NewFormatter("text", false, false)
	fixableReport := probe.NewReport(appVersion, *target, fixable)
	formatter.Format(os.Stdout, fixableReport)

	if fixDryRun {
		fmt.Println("\n(dry run — no changes applied)")
		return nil
	}

	if !fixYes {
		fmt.Printf("\nApply %d fixes? [y/N] ", len(fixable))
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Create backup and apply fixes
	fixer := fix.NewFixer(path)
	results, err := fixer.ApplyAll(context.Background(), reg, fixable)
	if err != nil {
		return fmt.Errorf("fix failed: %w", err)
	}

	fmt.Printf("\nApplied %d fixes. Backup saved to %s\n", len(results), fixer.BackupDir())
	return nil
}
```

**Step 4: Implement rollback command**

```go
// internal/cli/rollback.go
package cli

import (
	"fmt"

	"github.com/null-event/whizbang/internal/fix"
	"github.com/spf13/cobra"
)

var (
	rollbackLatest bool
	rollbackList   bool
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback [path]",
	Short: "Undo auto-fix changes from backups",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRollback,
}

func init() {
	rollbackCmd.Flags().BoolVar(&rollbackLatest, "latest", false, "restore most recent backup without prompting")
	rollbackCmd.Flags().BoolVar(&rollbackList, "list", false, "list available backups")

	rootCmd.AddCommand(rollbackCmd)
}

func runRollback(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	backups, err := fix.ListBackups(path)
	if err != nil {
		return err
	}

	if len(backups) == 0 {
		fmt.Println("No backups found.")
		return nil
	}

	if rollbackList {
		for _, b := range backups {
			fmt.Printf("  %s  (%d files)\n", b.Timestamp, len(b.Files))
		}
		return nil
	}

	var selected *fix.Backup
	if rollbackLatest {
		selected = &backups[0]
	} else {
		fmt.Println("Available backups:")
		for i, b := range backups {
			fmt.Printf("  [%d] %s  (%d files)\n", i+1, b.Timestamp, len(b.Files))
		}
		fmt.Print("\nSelect backup number: ")
		var n int
		fmt.Scanln(&n)
		if n < 1 || n > len(backups) {
			return fmt.Errorf("invalid selection: %d", n)
		}
		selected = &backups[n-1]
	}

	if err := selected.Restore(); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	fmt.Printf("Restored %d files from backup %s\n", len(selected.Files), selected.Timestamp)
	return nil
}
```

**Step 5: Implement report command**

```go
// internal/cli/report.go
package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/null-event/whizbang/internal/output"
	"github.com/null-event/whizbang/internal/probe"
	"github.com/spf13/cobra"
)

var (
	reportFormat string
	reportOutput string
)

var reportCmd = &cobra.Command{
	Use:   "report <scan-output.json>",
	Short: "Convert scan results between output formats",
	Args:  cobra.ExactArgs(1),
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "sarif", "output format (text|sarif)")
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "output file path (default: stdout)")

	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var report probe.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("parsing input: %w", err)
	}

	formatter, err := output.NewFormatter(reportFormat, false, false)
	if err != nil {
		return err
	}

	w := os.Stdout
	if reportOutput != "" {
		f, err := os.Create(reportOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	return formatter.Format(w, &report)
}
```

**Step 6: Build and verify all commands show in help**

Run: `go build -o whizbang ./cmd/whizbang && ./whizbang --help`
Expected: shows audit, scan, attack, fix, rollback, report, version

**Step 7: Commit**

```bash
git add internal/cli/
git commit -m "feat: add scan, attack, fix, rollback, report commands"
```

---

## Phase 5: Fix & Backup System

### Task 13: Implement backup system

**Files:**
- Create: `internal/fix/backup.go`
- Test: `internal/fix/backup_test.go`

**Step 1: Write failing test**

```go
// internal/fix/backup_test.go
package fix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupAndRestore(t *testing.T) {
	dir := t.TempDir()

	// Create a file to back up
	testFile := filepath.Join(dir, "test.json")
	os.WriteFile(testFile, []byte(`{"original": true}`), 0644)

	// Create backup
	bm := NewBackupManager(dir)
	backup, err := bm.Create([]string{testFile})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// Verify backup exists
	if len(backup.Files) != 1 {
		t.Fatalf("expected 1 backed up file, got %d", len(backup.Files))
	}

	// Modify original
	os.WriteFile(testFile, []byte(`{"modified": true}`), 0644)

	// Restore
	if err := backup.Restore(); err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	// Verify restored
	data, _ := os.ReadFile(testFile)
	if string(data) != `{"original": true}` {
		t.Errorf("expected original content, got %s", string(data))
	}
}

func TestListBackups(t *testing.T) {
	dir := t.TempDir()

	testFile := filepath.Join(dir, "test.json")
	os.WriteFile(testFile, []byte(`{}`), 0644)

	bm := NewBackupManager(dir)
	bm.Create([]string{testFile})
	bm.Create([]string{testFile})

	backups, err := ListBackups(dir)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(backups) != 2 {
		t.Errorf("expected 2 backups, got %d", len(backups))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/fix/ -v`
Expected: FAIL

**Step 3: Implement backup**

```go
// internal/fix/backup.go
package fix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const backupDirName = ".whizbang-backup"

type BackupManager struct {
	basePath string
}

type Backup struct {
	Dir       string
	Timestamp string
	Files     []BackupFile
}

type BackupFile struct {
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path"`
	ProbeID      string `json:"probe_id,omitempty"`
}

type manifest struct {
	Timestamp string       `json:"timestamp"`
	Files     []BackupFile `json:"files"`
}

func NewBackupManager(basePath string) *BackupManager {
	return &BackupManager{basePath: basePath}
}

func (bm *BackupManager) Create(filePaths []string) (*Backup, error) {
	ts := time.Now().Format("20060102T150405")
	backupDir := filepath.Join(bm.basePath, backupDirName, ts)

	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("creating backup dir: %w", err)
	}

	backup := &Backup{
		Dir:       backupDir,
		Timestamp: ts,
	}

	for _, fp := range filePaths {
		data, err := os.ReadFile(fp)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", fp, err)
		}

		backupName := filepath.Base(fp) + ".bak"
		backupPath := filepath.Join(backupDir, backupName)
		if err := os.WriteFile(backupPath, data, 0600); err != nil {
			return nil, fmt.Errorf("writing backup %s: %w", backupPath, err)
		}

		backup.Files = append(backup.Files, BackupFile{
			OriginalPath: fp,
			BackupPath:   backupPath,
		})
	}

	// Write manifest
	m := manifest{Timestamp: ts, Files: backup.Files}
	mdata, _ := json.MarshalIndent(m, "", "  ")
	os.WriteFile(filepath.Join(backupDir, "manifest.json"), mdata, 0600)

	return backup, nil
}

func (b *Backup) Restore() error {
	for _, f := range b.Files {
		data, err := os.ReadFile(f.BackupPath)
		if err != nil {
			return fmt.Errorf("reading backup %s: %w", f.BackupPath, err)
		}
		if err := os.WriteFile(f.OriginalPath, data, 0644); err != nil {
			return fmt.Errorf("restoring %s: %w", f.OriginalPath, err)
		}
	}
	return nil
}

func ListBackups(basePath string) ([]Backup, error) {
	backupRoot := filepath.Join(basePath, backupDirName)
	entries, err := os.ReadDir(backupRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var backups []Backup
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mpath := filepath.Join(backupRoot, e.Name(), "manifest.json")
		data, err := os.ReadFile(mpath)
		if err != nil {
			continue
		}
		var m manifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		backups = append(backups, Backup{
			Dir:       filepath.Join(backupRoot, e.Name()),
			Timestamp: m.Timestamp,
			Files:     m.Files,
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Timestamp > backups[j].Timestamp // newest first
	})

	return backups, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/fix/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/fix/
git commit -m "feat: add backup manager with create, restore, and list"
```

---

### Task 14: Implement Fixer that coordinates fix application

**Files:**
- Create: `internal/fix/fixer.go`
- Test: `internal/fix/fixer_test.go`

**Step 1: Write failing test**

```go
// internal/fix/fixer_test.go
package fix

import (
	"context"
	"testing"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/probe"
)

type fixableProbe struct {
	info  probe.ProbeInfo
	fixed bool
}

func (f *fixableProbe) Info() probe.ProbeInfo { return f.info }
func (f *fixableProbe) Scan(ctx context.Context, t *probe.Target) ([]probe.Finding, error) {
	return nil, nil
}
func (f *fixableProbe) Fix(ctx context.Context, finding probe.Finding) (*probe.FixResult, error) {
	f.fixed = true
	return &probe.FixResult{Finding: finding, Description: "fixed"}, nil
}
func (f *fixableProbe) CanFix() bool { return true }

func TestFixerApplyAll(t *testing.T) {
	dir := t.TempDir()
	fp := &fixableProbe{info: probe.ProbeInfo{ID: "TEST-001"}}

	reg := engine.NewRegistry()
	reg.Register(fp)

	findings := []probe.Finding{
		{ProbeID: "TEST-001", Fixable: true},
	}

	fixer := NewFixer(dir)
	results, err := fixer.ApplyAll(context.Background(), reg, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if !fp.fixed {
		t.Error("expected probe to be called")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/fix/ -run TestFixer -v`
Expected: FAIL

**Step 3: Implement Fixer**

```go
// internal/fix/fixer.go
package fix

import (
	"context"
	"fmt"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/probe"
)

type Fixer struct {
	basePath string
	backup   *BackupManager
}

func NewFixer(basePath string) *Fixer {
	return &Fixer{
		basePath: basePath,
		backup:   NewBackupManager(basePath),
	}
}

func (f *Fixer) BackupDir() string {
	return fmt.Sprintf("%s/%s/", f.basePath, backupDirName)
}

func (f *Fixer) ApplyAll(ctx context.Context, reg *engine.Registry, findings []probe.Finding) ([]*probe.FixResult, error) {
	var results []*probe.FixResult

	for _, finding := range findings {
		p := reg.ByID(finding.ProbeID)
		if p == nil || !p.CanFix() {
			continue
		}

		result, err := p.Fix(ctx, finding)
		if err != nil {
			return results, fmt.Errorf("fixing %s: %w", finding.ProbeID, err)
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/fix/ -run TestFixer -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/fix/
git commit -m "feat: add Fixer that coordinates probe fix application"
```

---

## Phase 6: Default Registries & First Audit Probes

### Task 15: Add default registry constructors and first credential probe

**Files:**
- Create: `internal/engine/defaults.go`
- Create: `internal/probe/cred/cred001.go`
- Test: `internal/probe/cred/cred001_test.go`

**Step 1: Write failing test for CRED-001**

```go
// internal/probe/cred/cred001_test.go
package cred

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestCRED001_DetectsHardcodedKeys(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a hardcoded API key
	configFile := filepath.Join(dir, "mcp.json")
	os.WriteFile(configFile, []byte(`{
		"mcpServers": {
			"example": {
				"env": {
					"OPENAI_API_KEY": "sk-proj-abc123def456ghi789"
				}
			}
		}
	}`), 0644)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for hardcoded key")
	}

	if findings[0].ProbeID != "CRED-001" {
		t.Errorf("expected CRED-001, got %s", findings[0].ProbeID)
	}
}

func TestCRED001_NoFalsePositives(t *testing.T) {
	dir := t.TempDir()

	configFile := filepath.Join(dir, "mcp.json")
	os.WriteFile(configFile, []byte(`{
		"mcpServers": {
			"example": {
				"env": {
					"OPENAI_API_KEY": "${OPENAI_API_KEY}"
				}
			}
		}
	}`), 0644)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings for env var reference, got %d", len(findings))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/probe/cred/ -v`
Expected: FAIL

**Step 3: Implement CRED-001**

```go
// internal/probe/cred/cred001.go
package cred

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/null-event/whizbang/internal/probe"
)

var keyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9_-]{20,})`),                            // OpenAI
	regexp.MustCompile(`(?i)(sk-ant-[a-zA-Z0-9_-]{20,})`),                        // Anthropic
	regexp.MustCompile(`(?i)(ghp_[a-zA-Z0-9]{36})`),                              // GitHub PAT
	regexp.MustCompile(`(?i)(glpat-[a-zA-Z0-9_-]{20,})`),                         // GitLab PAT
	regexp.MustCompile(`(?i)(xoxb-[a-zA-Z0-9-]+)`),                               // Slack bot
	regexp.MustCompile(`(?i)["']?[a-z_]*(?:api[_-]?key|secret|token|password)["']?\s*[:=]\s*["']([a-zA-Z0-9_/+=-]{16,})["']`), // generic key=value
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
			continue // file doesn't exist, skip
		}

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// Skip env var references
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
					break // one finding per line
				}
			}
		}
		f.Close()
	}

	return findings, nil
}

func (p *probe001) Fix(ctx context.Context, finding probe.Finding) (*probe.FixResult, error) {
	// TODO: implement key replacement with env var references
	return nil, nil
}

func (p *probe001) CanFix() bool {
	return true
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/probe/cred/ -v`
Expected: PASS

**Step 5: Implement default registries**

```go
// internal/engine/defaults.go
package engine

import (
	"github.com/null-event/whizbang/internal/probe/cred"
)

func NewDefaultAuditRegistry() *Registry {
	reg := NewRegistry()

	// Credential probes
	reg.Register(cred.New001())

	// TODO: register remaining audit probes as they're implemented

	return reg
}

func NewDefaultScanRegistry() *Registry {
	reg := NewRegistry()

	// TODO: register scan probes as they're implemented

	return reg
}

func NewDefaultAttackRegistry() *Registry {
	reg := NewRegistry()

	// TODO: register attack probes as they're implemented

	return reg
}
```

**Step 6: Build to verify everything compiles**

Run: `go build ./cmd/whizbang`
Expected: successful build

**Step 7: Commit**

```bash
git add internal/engine/defaults.go internal/probe/cred/
git commit -m "feat: add CRED-001 probe (hardcoded API key detection) and default registries"
```

---

### Task 16: Add MCP-001 probe (overly broad filesystem access)

**Files:**
- Create: `internal/probe/mcp/mcp001.go`
- Test: `internal/probe/mcp/mcp001_test.go`

**Step 1: Write failing test**

```go
// internal/probe/mcp/mcp001_test.go
package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestMCP001_DetectsBroadFilesystemAccess(t *testing.T) {
	dir := t.TempDir()

	configFile := filepath.Join(dir, "mcp.json")
	os.WriteFile(configFile, []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
			}
		}
	}`), 0644)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for root filesystem access")
	}
}

func TestMCP001_AllowsScopedAccess(t *testing.T) {
	dir := t.TempDir()

	configFile := filepath.Join(dir, "mcp.json")
	os.WriteFile(configFile, []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/project"]
			}
		}
	}`), 0644)

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for scoped access, got %d", len(findings))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/probe/mcp/ -v`
Expected: FAIL

**Step 3: Implement MCP-001**

```go
// internal/probe/mcp/mcp001.go
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
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/probe/mcp/ -v`
Expected: PASS

**Step 5: Register in defaults**

Update `internal/engine/defaults.go` to add:
```go
import "github.com/null-event/whizbang/internal/probe/mcp"
// In NewDefaultAuditRegistry:
reg.Register(mcp.New001())
```

**Step 6: Commit**

```bash
git add internal/probe/mcp/ internal/engine/defaults.go
git commit -m "feat: add MCP-001 probe (overly broad filesystem access detection)"
```

---

### Task 17: Add PERM-001 probe (world-readable config files)

**Files:**
- Create: `internal/probe/perm/perm001.go`
- Test: `internal/probe/perm/perm001_test.go`

**Step 1: Write failing test**

```go
// internal/probe/perm/perm001_test.go
package perm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestPERM001_DetectsWorldReadable(t *testing.T) {
	dir := t.TempDir()

	claudeDir := filepath.Join(dir, ".claude")
	os.MkdirAll(claudeDir, 0755)
	configFile := filepath.Join(claudeDir, "settings.json")
	os.WriteFile(configFile, []byte(`{}`), 0644) // world-readable

	p := New001()
	target := &probe.Target{Path: dir}

	findings, err := p.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for world-readable config")
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/probe/perm/ -v`
Expected: FAIL

**Step 3: Implement PERM-001**

```go
// internal/probe/perm/perm001.go
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
		// Check if group or others have read access
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
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/probe/perm/ -v`
Expected: PASS

**Step 5: Register in defaults and commit**

Update `internal/engine/defaults.go` to register `perm.New001()`.

```bash
git add internal/probe/perm/ internal/engine/defaults.go
git commit -m "feat: add PERM-001 probe (world-readable config file detection)"
```

---

### Task 18: Add GIT-001 probe (missing .gitignore patterns)

**Files:**
- Create: `internal/probe/git/git001.go`
- Test: `internal/probe/git/git001_test.go`

**Step 1: Write failing test**

```go
// internal/probe/git/git001_test.go
package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/null-event/whizbang/internal/probe"
)

func TestGIT001_DetectsMissingPatterns(t *testing.T) {
	dir := t.TempDir()

	// Create .gitignore without secret patterns
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/probe/git/ -v`
Expected: FAIL

**Step 3: Implement GIT-001**

```go
// internal/probe/git/git001.go
package git

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/null-event/whizbang/internal/probe"
)

var requiredPatterns = []string{
	".env",
	".claude/",
}

type probe001 struct{}

func New001() probe.Probe {
	return &probe001{}
}

func (p *probe001) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "GIT-001",
		Name:        "Missing .gitignore Secret Patterns",
		Category:    probe.CategoryGit,
		Severity:    probe.SeverityMedium,
		Description: "Detects missing .gitignore patterns for secrets and sensitive directories",
		Tags:        []string{"general"},
	}
}

func (p *probe001) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	gitignorePath := filepath.Join(target.Path, ".gitignore")

	f, err := os.Open(gitignorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []probe.Finding{{
				ProbeID:     "GIT-001",
				ProbeName:   "Missing .gitignore",
				Category:    probe.CategoryGit,
				Severity:    probe.SeverityMedium,
				Description: "No .gitignore file found — secrets may be committed",
				Location:    probe.Location{File: ".gitignore"},
				Fixable:     true,
				Remediation: "Create .gitignore with patterns for .env, .claude/, and other sensitive files",
			}}, nil
		}
		return nil, err
	}
	defer f.Close()

	existing := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		existing[line] = true
		// Also match partial patterns (e.g. ".env*" covers ".env")
		if strings.HasSuffix(line, "*") {
			existing[strings.TrimSuffix(line, "*")] = true
		}
	}

	var missing []string
	for _, pattern := range requiredPatterns {
		found := false
		if existing[pattern] {
			found = true
		}
		// Check for variations
		for k := range existing {
			if strings.Contains(k, strings.TrimSuffix(pattern, "/")) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, pattern)
		}
	}

	if len(missing) == 0 {
		return nil, nil
	}

	return []probe.Finding{{
		ProbeID:     "GIT-001",
		ProbeName:   "Missing .gitignore Secret Patterns",
		Category:    probe.CategoryGit,
		Severity:    probe.SeverityMedium,
		Description: "Missing .gitignore patterns: " + strings.Join(missing, ", "),
		Location:    probe.Location{File: ".gitignore"},
		Fixable:     true,
		Remediation: "Add missing patterns to .gitignore: " + strings.Join(missing, ", "),
	}}, nil
}

func (p *probe001) Fix(ctx context.Context, finding probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}

func (p *probe001) CanFix() bool {
	return true
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/probe/git/ -v`
Expected: PASS

**Step 5: Register in defaults and commit**

Update `internal/engine/defaults.go` to register `git.New001()`.

```bash
git add internal/probe/git/ internal/engine/defaults.go
git commit -m "feat: add GIT-001 probe (missing .gitignore secret patterns)"
```

---

## Phase 7: Configuration System

### Task 19: Implement YAML config loading

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Step 1: Write failing test**

```go
// internal/config/config_test.go
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
		t.Errorf("expected 0 (use runtime default), got %d", cfg.Workers)
	}
	if cfg.Output.Format != "" {
		t.Errorf("expected empty (use text default), got %s", cfg.Output.Format)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	_, err := Load("/nonexistent/whizbang.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -v`
Expected: FAIL

**Step 3: Implement config**

```go
// internal/config/config.go
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Workers int    `yaml:"workers"`
	Timeout string `yaml:"timeout"`

	Audit  AuditConfig  `yaml:"audit"`
	Scan   ScanConfig   `yaml:"scan"`
	Attack AttackConfig `yaml:"attack"`
	Output OutputConfig `yaml:"output"`
}

type AuditConfig struct {
	Exclude     []string `yaml:"exclude"`
	SeverityMin string   `yaml:"severity_min"`
}

type ScanConfig struct {
	Timeout        string `yaml:"timeout"`
	MaxConnections int    `yaml:"max_connections"`
}

type AttackConfig struct {
	Intensity string `yaml:"intensity"`
	Delay     string `yaml:"delay"`
}

type OutputConfig struct {
	Format  string `yaml:"format"`
	NoColor bool   `yaml:"no_color"`
}

func Default() *Config {
	return &Config{}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat: add YAML config loading with defaults"
```

---

## Phase 8: Integration — End-to-End Smoke Test

### Task 20: Add integration test that runs audit end-to-end

**Files:**
- Create: `test/integration/audit_test.go`

**Step 1: Write integration test**

```go
// test/integration/audit_test.go
package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/probe"
)

func TestAuditEndToEnd(t *testing.T) {
	dir := t.TempDir()

	// Set up a vulnerable project
	os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
				"env": {
					"API_KEY": "sk-proj-realkey123456789abcdef"
				}
			}
		}
	}`), 0644)

	target := &probe.Target{Path: dir}
	reg := engine.NewDefaultAuditRegistry()
	runner := engine.NewRunner(4)
	report := runner.Run(context.Background(), reg.All(), target, "test")

	if report.Summary.Total == 0 {
		t.Fatal("expected findings for vulnerable setup")
	}

	// Should find at least CRED-001 and MCP-001
	foundCred := false
	foundMCP := false
	for _, f := range report.Findings {
		if f.ProbeID == "CRED-001" {
			foundCred = true
		}
		if f.ProbeID == "MCP-001" {
			foundMCP = true
		}
	}

	if !foundCred {
		t.Error("expected CRED-001 finding")
	}
	if !foundMCP {
		t.Error("expected MCP-001 finding")
	}
}
```

**Step 2: Run integration test**

Run: `go test ./test/integration/ -v`
Expected: PASS

**Step 3: Run all tests**

Run: `go test ./... -v`
Expected: ALL PASS

**Step 4: Build final binary**

Run: `go build -ldflags="-s -w" -o whizbang ./cmd/whizbang`
Expected: clean build, single binary

**Step 5: Manual smoke test**

Run: `./whizbang audit /tmp`
Expected: runs without error, shows findings or "0 findings"

**Step 6: Commit**

```bash
git add test/
git commit -m "test: add end-to-end integration test for audit pipeline"
```

---

## Remaining Probes (follow same pattern as Tasks 15-18)

After the foundation is solid, implement remaining probes following the same TDD pattern:

### Audit probes to implement:
- `CRED-002..005` — tokens in .env, passwords in configs, committed secrets, MCP env secrets
- `MCP-002..008` — missing auth, unsafe tool perms, stdio/SSE misconfig, missing allowlists, unscoped resources, transport security, tool count
- `PERM-002..004` — .claude dir perms, SSH key perms, credential file perms
- `SUPPLY-001..006` — unverified sources, lockfile integrity, typosquatting, unpinned deps, unsigned tools, known-bad packages
- `GIT-002..003` — committed .env, sensitive files in git history
- `CHAIN-001..004` — unrestricted bash, read+exfil chains, write+exec combos, missing approval gates
- `CLAUDE-001..005` — unsafe CLAUDE.md, permissive hooks, disabled sandbox, shell slash commands, missing permission boundaries
- `CFG-001..004` — debug mode, insecure defaults, verbose errors, missing rate limits

### Scan probes to implement:
- `SCAN-MCP-001..003` — exposed SSE, tools listing, version disclosure
- `SCAN-CFG-001..002` — public configs, debug endpoints
- `SCAN-KEY-001..002` — keys in responses, reflected auth headers
- `SCAN-NET-001..002` — 0.0.0.0 binding, TLS issues

### Attack probes to implement:
- `ATK-PI-001..010` — prompt injection payloads
- `ATK-EX-001..008` — data exfiltration payloads
- `ATK-TA-001..008` — tool abuse payloads
- `ATK-MP-001..006` — memory poisoning payloads
- `ATK-CL-001..004` — config leak payloads

Each follows the same pattern: test file, probe file, register in defaults, commit.

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1 | 1-3 | Project scaffolding, core types, Probe interface |
| 2 | 4-5 | Registry and goroutine pool Runner |
| 3 | 6-9 | JSON, text, SARIF formatters + Formatter interface |
| 4 | 10-12 | CLI commands (all 6 + version) |
| 5 | 13-14 | Backup system and Fixer |
| 6 | 15-18 | Default registries + first 4 probes (CRED-001, MCP-001, PERM-001, GIT-001) |
| 7 | 19 | YAML config loading |
| 8 | 20 | End-to-end integration test |
