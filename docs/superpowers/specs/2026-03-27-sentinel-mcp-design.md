# sentinel-mcp Design Spec

**Date:** 2026-03-27
**Status:** Draft
**Author:** digitalghost + Claude

---

## Overview

sentinel-mcp is an MCP server that gives Claude the ability to audit dependencies across all projects for vulnerabilities (CVEs), outdated packages, and license risks. It supports Go, Node.js, and Python ecosystems using a hybrid approach: native CLI tools when available, API-based fallback when they're not.

## Goals

1. Scan any Go, Node.js, or Python project for known vulnerabilities
2. Identify outdated dependencies with staleness classification
3. Detect and classify dependency licenses by risk level
4. Aggregate findings across all projects under configured root directories
5. Create GitHub issues for critical/high-severity findings
6. Work on any machine regardless of which native audit tools are installed

## Non-Goals

- Real-time file watching / continuous monitoring (scan-on-demand only)
- Automated dependency updates (report only, human decides)
- Rust, Java, or other ecosystem support (adapter pattern allows future additions)
- Persistent scan history database (in-memory cache with TTL only)

---

## MCP Tools (9)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `scan_project` | `path: string` | Scan a single project. Returns cached results if fresh, re-scans if stale. |
| `scan_all` | `force?: boolean` | Discover and scan all projects under configured roots. Respects cache TTL unless `force: true`. |
| `get_summary` | none | Cross-project dashboard: total vulns by severity, most outdated deps, license conflicts. |
| `list_vulnerabilities` | `severity?: string, project?: string` | All CVEs across projects, filterable by severity and/or project. |
| `list_outdated` | `staleness?: string, project?: string` | Outdated deps across projects, filterable by staleness level and/or project. |
| `list_licenses` | `risk?: string, project?: string` | All licenses in use, filterable by risk level and/or project. |
| `create_github_issues` | `project: string, severity?: string` | Create GitHub issues for findings at or above severity threshold. Requires `gh` CLI. |
| `check_tool_status` | none | Report which native CLI tools are available and which ecosystems will use fallback mode. |
| `get_config` | none | Return current active configuration. |

---

## Architecture

```
sentinel-mcp/
├── index.js                  # MCP server entry, tool registration
├── lib/
│   ├── config.js             # Config loading (~/.sentinel-mcp/config.json)
│   ├── discovery.js          # Find projects under root dirs
│   ├── cache.js              # Scan result cache with configurable TTL
│   ├── scanner.js            # Orchestrator — runs all adapters on a project
│   ├── osv-client.js         # HTTP client for OSV.dev vulnerability API
│   ├── github-issues.js      # GitHub issue creation via gh CLI
│   └── adapters/
│       ├── node-adapter.js   # npm audit / package.json + lockfile parsing
│       ├── go-adapter.js     # govulncheck / go.sum + go.mod parsing
│       └── python-adapter.js # pip-audit / requirements.txt parsing
├── package.json
└── test.js
```

### Key Design Decisions

- **ES modules** (`"type": "module"`) — matches existing MCP server conventions
- **Adapter pattern** — each ecosystem is an independent module exporting `scanVulns()`, `checkOutdated()`, `detectLicenses()`. Adding a new ecosystem = one new file.
- **Hybrid scanning** — try native CLI tool first, fall back to manifest parsing + API queries
- **No database** — scan results cached in-memory with configurable TTL (default 1 hour)
- **GitHub issues via `gh` CLI** — reuses existing authentication, no separate token needed
- **OSV.dev for vulnerability data** — free, no API key, covers Go, npm, and PyPI

### Dependencies

```json
{
  "@modelcontextprotocol/sdk": "^1.27.1",
  "zod": "^4.3.6"
}
```

No other runtime dependencies. Uses native `fetch()` for HTTP, `child_process` for CLI tools, `fs/promises` for file reading.

---

## Scan Pipeline

For each project directory:

```
detect ecosystem (go.mod? package.json? requirements.txt?)
  │
  ├─ for each detected ecosystem:
  │    │
  │    ├─ vulnerabilities:
  │    │    ├─ try native tool (npm audit / govulncheck / pip-audit)
  │    │    │    ├─ success → parse structured output
  │    │    │    └─ not installed or timeout → fallback: parse lockfile + query OSV.dev
  │    │    └─ no lockfile → skip vuln scan for this ecosystem
  │    │
  │    ├─ outdated:
  │    │    ├─ try native tool (npm outdated / go list -m -u / pip list --outdated)
  │    │    └─ fallback: parse manifest, query registry for latest versions
  │    │
  │    └─ licenses:
  │         └─ parse manifest + query registry metadata
  │
  └─ merge results into unified report
```

### Native Tool → Fallback Matrix

| Ecosystem | Vuln Native | Vuln Fallback | Outdated Native | Outdated Fallback | License |
|-----------|-------------|---------------|-----------------|-------------------|---------|
| Node.js | `npm audit --json` | Parse `package-lock.json` + OSV.dev | `npm outdated --json` | Parse `package.json` + npm registry API | `package.json` license field + npm registry |
| Go | `govulncheck -json ./...` | Parse `go.sum` + OSV.dev | `go list -m -u -json all` | Parse `go.mod` + Go module proxy | Go module proxy `/info` endpoint |
| Python | `pip-audit --format=json` | Parse `requirements.txt` + OSV.dev | `pip list --outdated --format=json` | Parse `requirements.txt` + PyPI JSON API | PyPI JSON API |

---

## Unified Report Format

```js
{
  project: "/home/user/projects/nexus",
  ecosystems: ["go"],
  scannedAt: "2026-03-27T14:30:00.000Z",
  toolMode: { go: "native" },          // or "fallback"
  osvStatus: "ok",                      // "ok" | "unreachable"
  vulnerabilities: [
    {
      id: "GO-2026-0123",
      severity: "high",                 // critical | high | medium | low
      package: "golang.org/x/net",
      installedVersion: "0.17.0",
      fixedVersion: "0.19.0",
      summary: "HTTP/2 rapid reset DoS",
      url: "https://osv.dev/vulnerability/GO-2026-0123"
    }
  ],
  outdated: [
    {
      package: "github.com/spf13/cobra",
      current: "1.7.0",
      latest: "1.8.1",
      staleness: "major",              // major | minor | patch
      behindBy: { major: 1, minor: 1, patch: 0 }
    }
  ],
  licenses: [
    {
      package: "github.com/spf13/cobra",
      license: "Apache-2.0",
      risk: "low"                       // low | medium | high | unknown
    }
  ],
  errors: []                            // any non-fatal errors encountered during scan
}
```

---

## Configuration

**File:** `~/.sentinel-mcp/config.json` (auto-created with defaults on first run)

```json
{
  "roots": ["/home/YOUR_USERNAME/projects"],
  "exclude": [
    "*/node_modules/*",
    "*/vendor/*",
    "*/.git/*",
    "*/testdata/*",
    "*/.worktrees/*"
  ],
  "cache": {
    "ttlMs": 3600000
  },
  "severity": {
    "issueThreshold": "high"
  },
  "licenses": {
    "allowed": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"],
    "flagged": ["GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"]
  },
  "github": {
    "labels": ["security", "dependencies"],
    "dryRun": false
  },
  "timeouts": {
    "cliMs": 30000,
    "apiMs": 15000
  }
}
```

### Configuration Schema (Zod)

All fields are optional with sensible defaults. Config is validated at startup. Invalid config logs a warning and falls back to defaults for invalid fields.

---

## Project Discovery

`discovery.js` walks each configured root directory looking for ecosystem markers:

1. List immediate subdirectories of each root (depth 1 only — does not recurse into nested directories)
2. For each subdirectory, check for: `go.mod`, `package.json`, `requirements.txt`
3. Skip directories matching any `exclude` pattern
4. Return list of `{ path, ecosystems: string[] }` objects

A project can have multiple ecosystems (e.g., a Go backend with a Node.js frontend). Each ecosystem is scanned independently.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Native tool not installed | Fall back to API-based scanning, set `toolMode: "fallback"` |
| Native tool times out | Treat as unavailable, fall back silently, note in `errors` array |
| OSV.dev API unreachable | Return results without vuln data, set `osvStatus: "unreachable"` |
| Registry API unreachable | Skip outdated/license check for that ecosystem, note in `errors` |
| No lockfile found | Skip vuln scan (manifests alone aren't precise enough), still check outdated + licenses |
| `gh` CLI not authenticated | `create_github_issues` returns error telling user to run `gh auth login` |
| Project root doesn't exist | Skip it, include warning in `scan_all` results |
| Malformed manifest | Skip that ecosystem, include parse error in `errors` array |
| Config file missing | Auto-create with defaults |
| Config file invalid | Log warning, use defaults for invalid fields |

**Core principle: never crash, always degrade.** Every failure narrows the report rather than killing the scan. Results always include enough metadata to know what worked and what didn't.

---

## License Risk Classification

| Risk | Licenses | Reasoning |
|------|----------|-----------|
| low | MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unlicense, 0BSD, CC0-1.0 | Permissive — no restrictions on use |
| medium | MPL-2.0, LGPL-2.1-only, LGPL-3.0-only | Weak copyleft — file-level obligations but doesn't infect your project |
| high | GPL-2.0-only, GPL-3.0-only, AGPL-3.0-only | Strong copyleft — may require your project to adopt the same license |
| unknown | Anything else or undetectable | Flagged for manual review |

Users can customize `allowed` and `flagged` lists in config.

---

## GitHub Issue Creation

`create_github_issues` shells out to `gh issue create` for each finding at or above the configured severity threshold.

**Issue format:**
```
Title: [SEVERITY] CVE-XXXX-XXXX in package-name (ecosystem)
Body:
  **Vulnerability:** summary
  **Package:** package-name@installed-version
  **Fixed in:** fixed-version
  **Severity:** high
  **Details:** osv-url

  Found by sentinel-mcp dependency audit.
Labels: security, dependencies
```

**Deduplication:** Before creating, checks existing open issues in the repo for matching CVE ID in the title. Skips if already reported.

**Dry run:** When `github.dryRun: true` in config, returns the list of issues that would be created without actually creating them.

---

## Smoke Test Coverage

Building this project exercises the following Claude Code capabilities:

| Phase | Capabilities Exercised |
|-------|----------------------|
| Design | brainstorming skill, Nexus context, Obsidian search |
| Planning | writing-plans skill |
| Implementation | TDD skill, parallel agent dispatch (3 adapters), Backend Architect agent, Security Engineer agent, Explore agent |
| Quality | verification-before-completion skill, requesting-code-review skill, Code Reviewer agent |
| Integration | Ollama (commit messages, README draft), bootstrap script hook, GitHub MCP (repo creation, issues, PR) |
| Completion | finishing-a-development-branch skill, Nexus notes |

~20 of 22 total capabilities exercised. Docker/Infra MCP not needed (pure Node.js project).
