# whizbang Design Document

**Date:** 2026-02-17
**Status:** Approved

## Overview

whizbang is a Go-based AI agent security scanner focused on MCP ecosystems. It provides local static analysis, external endpoint reconnaissance, and active red-team testing in a single static binary with no runtime dependencies.

Inspired by [hackmyagent](https://github.com/opena2a-org/hackmyagent) (Node.js/TypeScript), whizbang reimplements the concept in Go with goroutine-based parallelism, an expanded probe set, and new modules for tool-use chain analysis and memory/RAG poisoning detection.

## Use Cases

- **Developer tool** — local scanning during development
- **CI/CD gate** — pipeline check that blocks deployments on findings
- **Red team tool** — active probing of AI agent endpoints

## CLI Commands

### `whizbang audit [path]`

Local static analysis of agent configurations, credentials, permissions, and tool setups. Defaults to current directory.

Flags:
- `--category` — filter by probe category
- `--severity-min` — minimum severity to report
- `--probe` — run specific probes by ID
- `--exclude` — skip specific probes
- `--format` — text|json|sarif
- `--verbose` — show passing checks
- `--no-color` — strip ANSI codes
- `--workers N` — goroutine pool size
- `--fail-above <severity>` — CI exit code threshold

### `whizbang scan <target-url>`

External reconnaissance of running agent endpoints. Non-exploitative network probing. Detects exposed MCP SSE/tools endpoints, public configs, API keys in responses, debug interfaces. Outputs a security grade (A-F).

Flags: same filtering/format flags plus `--timeout`, `--max-connections`.

### `whizbang attack <target-url>`

Active red-team exploitation of agent endpoints with adversarial payloads.

Flags:
- `--category` — prompt-injection|tool-abuse|data-exfil|memory-poison|config-leak
- `--intensity` — passive|active|aggressive
- `--timeout`, `--delay` — timing controls
- `--stop-on-success` — halt after first successful exploit
- `--payload-file` — custom payloads JSON
- `--format` — text|json|sarif

### `whizbang fix [path]`

Auto-remediate audit findings with backup. Runs audit internally, applies fixes for fixable findings.

Flags:
- `--dry-run` — show unified diffs without applying
- `--probe` — fix specific probes only
- `--yes` — skip confirmation prompt

### `whizbang rollback [path]`

Restore files from `.whizbang-backup/`.

Flags:
- `--latest` — restore most recent without prompting
- `--list` — show available backups

### `whizbang report <scan-output.json>`

Convert JSON scan results to other formats.

Flags:
- `--format` — sarif|text
- `--output` — file path

### Global Flags

- `--config <path>` — optional YAML config file
- `--version` — print version info

## Architecture

### Project Structure

```
whizbang/
├── cmd/whizbang/
│   └── main.go
├── internal/
│   ├── cli/                # cobra command definitions
│   │   ├── root.go
│   │   ├── audit.go
│   │   ├── scan.go
│   │   ├── attack.go
│   │   ├── fix.go
│   │   ├── rollback.go
│   │   └── report.go
│   ├── engine/             # probe orchestration + goroutine pool
│   │   ├── pool.go
│   │   ├── runner.go
│   │   └── registry.go
│   ├── probe/              # probe interface + implementations
│   │   ├── probe.go        # interface definition
│   │   ├── finding.go      # finding/severity types
│   │   ├── cred/           # credential scanning
│   │   ├── mcp/            # MCP config checks
│   │   ├── perm/           # file permission checks
│   │   ├── supply/         # supply chain checks
│   │   ├── git/            # git hygiene checks
│   │   ├── chain/          # tool-use chain analysis
│   │   ├── claude/         # Claude Code checks
│   │   ├── config/         # config checks
│   │   ├── scan/           # external recon probes
│   │   ├── attack/         # red-team payloads
│   │   └── memory/         # memory/RAG poisoning
│   ├── fix/                # auto-remediation
│   │   ├── fixer.go
│   │   └── backup.go
│   └── output/             # formatters
│       ├── text.go
│       ├── json.go
│       └── sarif.go
├── go.mod
└── go.sum
```

### Probe Interface

```go
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
    Severity    Severity   // Critical, High, Medium, Low, Info
    Description string
    Tags        []string
}

type Target struct {
    Path    string
    URL     string
    Options map[string]string
}
```

### Goroutine Pool

Bounded worker pool using semaphore pattern. Default size: `runtime.NumCPU()`.

```go
type Engine struct {
    workers  int
    registry *Registry
}

func (e *Engine) RunProbes(ctx context.Context, probes []Probe, target *Target) *Report
```

- Audit probes: fully parallel, no shared state
- Scan probes: parallel with shared `http.Client` and connection pooling
- Attack probes: parallel with optional `--delay` between launches, `--stop-on-success` cancels via context
- Fix operations: sequential to avoid file mutation conflicts
- Per-probe timeouts: 30s audit, 10s network (configurable via `--timeout`)

### Progress Reporting

Interactive progress line on stderr when TTY detected:

```
[14/39] Running MCP-003 ... ██████████░░░░░░ 36%
```

Suppressed for non-TTY (CI) or `--format json`.

## Probe Inventory

### Audit Probes (~39)

| Category | IDs | Count | Checks |
|----------|-----|-------|--------|
| Credential | CRED-001..005 | 5 | Hardcoded API keys, tokens, passwords, committed .env files, secrets in MCP configs |
| MCP Config | MCP-001..008 | 8 | Broad filesystem access, missing transport auth, unsafe tool permissions, unscoped resources |
| Permission | PERM-001..004 | 4 | World-readable configs, permissive .claude/ dirs, SSH key perms, credential file perms |
| Supply Chain | SUPPLY-001..006 | 6 | Unverified MCP sources, missing lockfile integrity, typosquatting, unpinned deps |
| Git Hygiene | GIT-001..003 | 3 | Missing .gitignore patterns, committed .env, sensitive files in history |
| Tool-Use Chain | CHAIN-001..004 | 4 | Unrestricted bash access, read+exfil chains, write+exec combos, missing approval gates |
| Claude Code | CLAUDE-001..005 | 5 | Unsafe CLAUDE.md instructions, permissive hooks, disabled sandbox, shell-access slash commands |
| Config | CFG-001..004 | 4 | Insecure defaults, debug mode, verbose errors, missing rate limiting |

### Scan Probes (~9)

| ID | Checks |
|----|--------|
| SCAN-MCP-001 | Exposed MCP SSE endpoints |
| SCAN-MCP-002 | MCP tools listing accessible without auth |
| SCAN-MCP-003 | Server version/capability disclosure |
| SCAN-CFG-001 | Public config files accessible via HTTP |
| SCAN-CFG-002 | Debug/diagnostic endpoints responding |
| SCAN-KEY-001 | API keys in HTTP responses |
| SCAN-KEY-002 | Auth headers reflected in responses |
| SCAN-NET-001 | Services bound to 0.0.0.0 |
| SCAN-NET-002 | TLS/certificate issues |

Security grade: A (90-100), B (80-89), C (70-79), D (60-69), F (<60).

### Attack Probes (~36)

| Category | IDs | Count | Tests |
|----------|-----|-------|-------|
| Prompt Injection | ATK-PI-001..010 | 10 | System prompt override, instruction injection via tool output, indirect injection via files, role confusion, delimiter attacks |
| Data Exfiltration | ATK-EX-001..008 | 8 | System prompt extraction, tool listing extraction, config disclosure, conversation history leakage |
| Tool Abuse | ATK-TA-001..008 | 8 | Unauthorized file access, command injection via tool args, path traversal, symlink attacks |
| Memory Poisoning | ATK-MP-001..006 | 6 | Persistent instruction injection, RAG contamination, conversation history manipulation, CLAUDE.md injection |
| Config Leak | ATK-CL-001..004 | 4 | Server config extraction, env variable disclosure, internal endpoint discovery, capability enumeration |

### Severity Levels

- **Critical** — immediate exploitation risk (exposed keys, RCE vectors)
- **High** — significant security gap (no auth on MCP, unrestricted tools)
- **Medium** — defense-in-depth issue (permissive permissions, missing gitignore)
- **Low** — best practice violation (verbose errors, missing rate limits)
- **Info** — informational finding (version disclosure, capability listing)

## Auto-Fix & Backup

### Fix Flow

audit -> findings -> filter fixable -> confirm -> backup -> apply -> verify

### Fixable Probes (v1)

| Probe | Fix Action |
|-------|-----------|
| CRED-001 | Replace hardcoded keys with `${ENV_VAR}` references |
| GIT-001 | Create/append .gitignore with secret patterns |
| GIT-002 | Create/append .gitignore for .env files |
| PERM-001..003 | chmod to restrictive permissions (600/700) |
| MCP-001 | Scope filesystem access to project directory |
| MCP-002 | Add transport auth stubs to MCP server config |
| CFG-001 | Disable debug mode in config files |

### Backup Structure

```
.whizbang-backup/
└── 2026-02-17T193045/
    ├── manifest.json
    ├── mcp.json.bak
    └── ...
```

manifest.json tracks timestamp, findings fixed, and files modified. Rollback restores from manifest.

### Dry Run

`whizbang fix --dry-run` outputs unified diffs to stdout without modifying files.

## Output Formats

### Text

Colored terminal output with severity indicators, finding counts, and fixability hints. Security grade for scan results.

### JSON

Structured report with version, timestamp, target, summary (counts by severity, fixable count, grade), and findings array.

### SARIF

SARIF v2.1.0 for GitHub Security tab. Findings map to result objects with ruleId, level, locations, and message.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings (or all below threshold) |
| 1 | Findings present above threshold |
| 2 | Runtime error |

## Configuration

### Precedence

CLI flags > config file > defaults

### Zero-Config Default

Works out of the box. No config file required.

### Optional whizbang.yaml

```yaml
workers: 8
timeout: 45s

audit:
  exclude: [PERM-003, CFG-001]
  severity_min: medium

scan:
  timeout: 15s
  max_connections: 20

attack:
  intensity: active
  delay: 500ms

output:
  format: json
  no_color: false
```

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| cobra | CLI framework |
| go-yaml | YAML config parsing |
| fatih/color | Terminal color output |
| owenrumney/go-sarif | SARIF report generation |

Everything else is Go stdlib: net/http, os, regexp, crypto, encoding/json.

## Build

```bash
go build -ldflags="-s -w -X main.version=0.1.0 -X main.commit=$(git rev-parse --short HEAD)" -o whizbang ./cmd/whizbang
```

Single static binary. Cross-compile with GOOS/GOARCH. No CGO.
