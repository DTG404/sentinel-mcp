import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { loadConfig } from "./lib/config.js";
import { Cache } from "./lib/cache.js";
import { discoverProjects } from "./lib/discovery.js";
import { Scanner } from "./lib/scanner.js";
import { checkToolAvailability } from "./lib/tool-check.js";
import { createGithubIssues } from "./lib/github-issues.js";

const config = await loadConfig();
const cache = new Cache(config.cache.ttlMs, config.cache.dir);
await cache.warmup();
const scanner = new Scanner(config);

const server = new McpServer({ name: "sentinel", version: "1.0.0" });
server.setResourceRequestHandlers();
server.setPromptRequestHandlers();

// 1. scan_project
server.tool(
  "scan_project",
  "Scan a single project directory for vulnerabilities, outdated packages, and license issues",
  { path: z.string().describe("Absolute path to the project directory") },
  async ({ path }) => {
    let report = cache.get(path);
    if (!report) {
      report = await scanner.scanProject(path);
      await cache.set(path, report);
    }
    return { content: [{ type: "text", text: JSON.stringify(report, null, 2) }] };
  }
);

// 2. scan_all
server.tool(
  "scan_all",
  "Discover and scan all projects under configured roots",
  { force: z.boolean().optional().describe("Force rescan even if cached results exist") },
  async ({ force = false }) => {
    const projects = await discoverProjects(config.roots, config.exclude);
    const reports = [];
    for (const project of projects) {
      let report = force ? null : cache.get(project.path);
      if (!report) {
        report = await scanner.scanProject(project.path);
        await cache.set(project.path, report);
      }
      reports.push(report);
    }
    return { content: [{ type: "text", text: JSON.stringify({ scanned: reports.length, reports }, null, 2) }] };
  }
);

// 3. get_summary
server.tool(
  "get_summary",
  "Get an aggregate summary across all cached scan reports",
  {},
  async () => {
    const projects = await discoverProjects(config.roots, config.exclude);
    const summary = {
      totalProjects: projects.length,
      scannedProjects: 0,
      totalVulnerabilities: 0,
      totalOutdated: 0,
      totalLicenseIssues: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
      byEcosystem: {},
    };

    for (const project of projects) {
      const report = cache.get(project.path);
      if (!report) continue;
      summary.scannedProjects++;
      summary.totalVulnerabilities += report.vulnerabilities.length;
      summary.totalOutdated += report.outdated.length;
      summary.totalLicenseIssues += report.licenses.filter((l) => l.risk === "high" || l.risk === "medium").length;
      for (const vuln of report.vulnerabilities) {
        const sev = vuln.severity ?? "unknown";
        summary.bySeverity[sev] = (summary.bySeverity[sev] ?? 0) + 1;
      }
      for (const eco of report.ecosystems) {
        summary.byEcosystem[eco] = (summary.byEcosystem[eco] ?? 0) + 1;
      }
    }
    return { content: [{ type: "text", text: JSON.stringify(summary, null, 2) }] };
  }
);

// 4. list_vulnerabilities
server.tool(
  "list_vulnerabilities",
  "List vulnerabilities across cached scan reports, optionally filtered by severity and project",
  {
    severity: z.string().optional().describe("Minimum severity level: critical, high, medium, low"),
    project: z.string().optional().describe("Filter to a specific project path"),
  },
  async ({ severity, project }) => {
    const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
    const minLevel = severity ? (SEVERITY_ORDER[severity] ?? 0) : 0;

    const projects = project
      ? [{ path: project }]
      : await discoverProjects(config.roots, config.exclude);

    const vulns = [];
    for (const proj of projects) {
      const report = cache.get(proj.path);
      if (!report) continue;
      for (const v of report.vulnerabilities) {
        if ((SEVERITY_ORDER[v.severity] ?? 0) >= minLevel) {
          vulns.push({ ...v, project: proj.path });
        }
      }
    }
    return { content: [{ type: "text", text: JSON.stringify({ count: vulns.length, vulnerabilities: vulns }, null, 2) }] };
  }
);

// 5. list_outdated
server.tool(
  "list_outdated",
  "List outdated packages across cached scan reports, optionally filtered by staleness and project",
  {
    staleness: z.string().optional().describe("Filter by staleness level: major, minor, patch"),
    project: z.string().optional().describe("Filter to a specific project path"),
  },
  async ({ staleness, project }) => {
    const projects = project
      ? [{ path: project }]
      : await discoverProjects(config.roots, config.exclude);

    const outdated = [];
    for (const proj of projects) {
      const report = cache.get(proj.path);
      if (!report) continue;
      for (const pkg of report.outdated) {
        if (!staleness || pkg.staleness === staleness) {
          outdated.push({ ...pkg, project: proj.path });
        }
      }
    }
    return { content: [{ type: "text", text: JSON.stringify({ count: outdated.length, outdated }, null, 2) }] };
  }
);

// 6. list_licenses
server.tool(
  "list_licenses",
  "List license information across cached scan reports, optionally filtered by risk level and project",
  {
    risk: z.string().optional().describe("Filter by risk level: high, medium, low, unknown"),
    project: z.string().optional().describe("Filter to a specific project path"),
  },
  async ({ risk, project }) => {
    const projects = project
      ? [{ path: project }]
      : await discoverProjects(config.roots, config.exclude);

    const licenses = [];
    for (const proj of projects) {
      const report = cache.get(proj.path);
      if (!report) continue;
      for (const lic of report.licenses) {
        if (!risk || lic.risk === risk) {
          licenses.push({ ...lic, project: proj.path });
        }
      }
    }
    return { content: [{ type: "text", text: JSON.stringify({ count: licenses.length, licenses }, null, 2) }] };
  }
);

// 7. create_github_issues
server.tool(
  "create_github_issues",
  "Create GitHub issues for vulnerabilities found in a project scan",
  {
    project: z.string().describe("Absolute path to the project to create issues for"),
    severity: z.string().optional().describe("Minimum severity threshold: critical, high, medium, low"),
  },
  async ({ project, severity }) => {
    const report = cache.get(project);
    if (!report) {
      return { content: [{ type: "text", text: JSON.stringify({ error: "No cached scan found for project. Run scan_project first." }, null, 2) }] };
    }
    const effectiveConfig = severity
      ? { ...config, severity: { ...config.severity, issueThreshold: severity } }
      : config;
    const result = await createGithubIssues(report, effectiveConfig);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// 8. check_tool_status
server.tool(
  "check_tool_status",
  "Check availability of native security scanning tools (npm, go, govulncheck, pip-audit, gh)",
  {},
  async () => {
    const status = await checkToolAvailability();
    return { content: [{ type: "text", text: JSON.stringify(status, null, 2) }] };
  }
);

// 9. get_config
server.tool(
  "get_config",
  "Return the active sentinel-mcp configuration",
  {},
  async () => {
    return { content: [{ type: "text", text: JSON.stringify(config, null, 2) }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
