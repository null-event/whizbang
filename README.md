<p align="center">
  <img src="assets/whizbang-mascot.svg" alt="whizbang mascot" width="300" />
</p>

# whizbang

AI agent security scanner. Audits local configurations, scans remote endpoints, and red-teams AI agent deployments with a focus on MCP ecosystems.

Single static binary. No runtime dependencies. Parallel probe execution via goroutine pools.

## Install

```bash
go install github.com/null-event/whizbang/cmd/whizbang@latest
```

Or build from source:

```bash
git clone https://github.com/null-event/whizbang.git
cd whizbang
go build -ldflags "-X main.version=0.1.0 -X main.commit=$(git rev-parse --short HEAD)" -o whizbang ./cmd/whizbang
```

## Commands

### audit

Static analysis of local AI agent configuration files, credentials, permissions, and tool setups.

```bash
whizbang audit                          # audit current directory
whizbang audit /path/to/project         # audit specific path
whizbang audit --format json            # JSON output
whizbang audit --format sarif           # SARIF output (GitHub Security tab)
whizbang audit --category credential    # filter by category
whizbang audit --severity-min high      # only report high+ findings
whizbang audit --exclude CRED-001       # skip specific probes
```

**Probes:** CRED-001 (hardcoded API keys), MCP-001 (overly broad filesystem access), PERM-001 (world-readable configs), GIT-001 (missing .gitignore patterns)

### scan

Non-exploitative reconnaissance of remote AI agent endpoints. Detects exposed services, leaked keys, and misconfigurations.

```bash
whizbang scan https://agent.example.com
whizbang scan https://agent.example.com --format json
whizbang scan https://agent.example.com --category scan-mcp
```

**Probes (9):**
- SCAN-MCP-001..003 — Exposed SSE endpoints, tools listing, version disclosure
- SCAN-CFG-001..002 — Public config files, debug endpoints
- SCAN-KEY-001..002 — API keys in responses, auth header reflection
- SCAN-NET-001..002 — Wildcard binding, TLS issues

### attack

Active adversarial testing with payloads for prompt injection, data exfiltration, tool abuse, memory poisoning, and config leaks.

```bash
whizbang attack https://agent.example.com
whizbang attack https://agent.example.com --intensity aggressive
whizbang attack https://agent.example.com --category prompt-injection
whizbang attack https://agent.example.com --stop-on-success
whizbang attack https://agent.example.com --delay 1s
```

**Probes (36):**
- ATK-PI-001..010 — Prompt injection (direct, indirect, role hijack, encoding bypass, multilingual, nested, context overflow, delimiter, few-shot, social engineering)
- ATK-EX-001..008 — Data exfiltration (system prompt extraction, tool enumeration, conversation history, file content, env variables, internal URLs, schema extraction, cross-context leakage)
- ATK-TA-001..008 — Tool abuse (file read, command injection, path traversal, shell execution, file write, data exfil via tool chain, package installation, env variable read)
- ATK-MP-001..006 — Memory poisoning (persistent instruction injection, RAG contamination, conversation history manipulation, CLAUDE.md injection, memory file poisoning, system prompt override)
- ATK-CL-001..004 — Config leak (server config extraction, env variable disclosure, internal endpoint discovery, capability enumeration)

### fix

Auto-remediate audit findings with backup.

```bash
whizbang fix                    # fix all fixable findings
whizbang fix --dry-run          # preview changes without applying
whizbang fix --yes              # skip confirmation prompt
whizbang fix --probe CRED-001   # fix specific probes only
```

### rollback

Restore files from a previous backup created by `fix`.

```bash
whizbang rollback <backup-id>
```

### report

Convert between output formats.

```bash
whizbang report --input results.json --output results.sarif --format sarif
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | `--format text` | Terminal output with colored severity labels (default) |
| JSON | `--format json` | Machine-readable, CI/CD pipelines |
| SARIF | `--format sarif` | GitHub Security tab integration |

## CI/CD

```yaml
# GitHub Actions
- name: Audit agent config
  run: |
    go install github.com/null-event/whizbang/cmd/whizbang@latest
    whizbang audit --format sarif --no-color > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Configuration

Optional `whizbang.yaml` config file:

```yaml
audit:
  categories: [credential, mcp, permission]
  exclude: [GIT-001]
scan:
  timeout: 15s
  max_connections: 20
attack:
  intensity: active
  delay: 500ms
output:
  format: json
  no_color: true
```

CLI flags always take precedence over config file values.

## Architecture

```
cmd/whizbang/          Entry point
internal/
  cli/                 Cobra commands (audit, scan, attack, fix, rollback, report)
  engine/              Registry, runner (goroutine pool), probe orchestration
  probe/               Core interfaces (Probe, Finding, Target, Report)
    attack/            36 attack probes (PI, EX, TA, MP, CL)
    cred/              Credential probes
    git/               Git security probes
    mcp/               MCP configuration probes
    perm/              Permission probes
    scan/              9 scan probes (MCP, CFG, KEY, NET)
  output/              Formatters (text, JSON, SARIF)
  fix/                 Backup manager, fixer coordinator
  config/              YAML config loading
test/integration/      End-to-end tests
```

## License

MIT
