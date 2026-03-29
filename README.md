# sentinel-mcp

MCP server for multi-project dependency security auditing. Scans Go, Node.js, and Python projects for vulnerabilities, outdated packages, and license risks.

## Tools

| Tool | Description |
|------|-------------|
| `scan_project` | Scan a single project directory |
| `scan_all` | Scan all projects in configured roots |
| `get_summary` | Aggregated summary across all scans |
| `list_vulnerabilities` | List vulnerabilities with severity filtering |
| `list_outdated` | List outdated packages with staleness classification |
| `list_licenses` | List dependencies with license risk assessment |
| `check_tool_status` | Check availability of native audit tools |
| `create_github_issues` | Create GitHub issues from scan results (with dedup) |
| `get_config` | Show current configuration |

## Supported Ecosystems

| Ecosystem | Native Tool | Fallback |
|-----------|------------|----------|
| Go | `govulncheck` | OSV.dev API |
| Node.js | `npm audit` | OSV.dev API |
| Python | `pip-audit` | OSV.dev API |

## Setup

```bash
npm install
```

## Usage

```bash
npm start
```

Configure in Claude Code MCP settings:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "node",
      "args": ["/path/to/sentinel-mcp/index.js"]
    }
  }
}
```

## Configuration

The server auto-discovers projects by looking for `package.json`, `go.mod`, and `pyproject.toml` in configured root directories. Results are cached with configurable TTL.

## Tech Stack

- Node.js (>=18)
- `@modelcontextprotocol/sdk`
- Zod for schema validation
- OSV.dev API for cross-ecosystem vulnerability data
