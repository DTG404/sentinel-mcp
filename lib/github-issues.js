import { execFile } from "node:child_process";
import { promisify } from "node:util";
const execFileAsync = promisify(execFile);

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

export function filterByThreshold(vulns, threshold) {
  const minLevel = SEVERITY_ORDER[threshold] || 0;
  return vulns.filter((v) => (SEVERITY_ORDER[v.severity] || 0) >= minLevel);
}

export function formatIssue(vuln, ecosystem) {
  const title = `[${vuln.severity.toUpperCase()}] ${vuln.id} in ${vuln.package} (${ecosystem})`;
  const body = `**Vulnerability:** ${vuln.summary}\n**Package:** ${vuln.package}@${vuln.installedVersion}\n**Fixed in:** ${vuln.fixedVersion || "No fix available"}\n**Severity:** ${vuln.severity}\n**Details:** ${vuln.url}\n\nFound by sentinel-mcp dependency audit.`;
  return { title, body };
}

export async function createGithubIssues(report, config) {
  const results = { created: [], skipped: [], errors: [] };

  // Check gh auth
  try {
    await execFileAsync("gh", ["auth", "status"], { timeout: 5000 });
  } catch {
    results.errors.push("gh auth check failed — not authenticated");
    return results;
  }

  const threshold = config?.severity?.issueThreshold ?? "high";
  const dryRun = config?.github?.dryRun ?? false;
  const labels = config?.github?.labels ?? ["security", "dependencies"];

  // Determine ecosystem for each vuln (use report.ecosystems[0] as fallback)
  const filtered = filterByThreshold(report.vulnerabilities ?? [], threshold);

  if (filtered.length === 0) {
    return results;
  }

  // Fetch existing issues to deduplicate
  let existingTitles = new Set();
  try {
    const { stdout } = await execFileAsync(
      "gh",
      ["issue", "list", "--state", "open", "--json", "title", "--limit", "200"],
      { timeout: 10000 }
    );
    const existing = JSON.parse(stdout);
    existingTitles = new Set(existing.map((i) => i.title));
  } catch {
    // If we can't fetch, proceed without dedup
  }

  const ecosystem = (report.ecosystems ?? [])[0] ?? "unknown";

  for (const vuln of filtered) {
    const { title, body } = formatIssue(vuln, ecosystem);

    if (existingTitles.has(title)) {
      results.skipped.push(title);
      continue;
    }

    if (dryRun) {
      results.created.push({ title, dryRun: true });
      continue;
    }

    try {
      const labelArgs = labels.flatMap((l) => ["--label", l]);
      await execFileAsync(
        "gh",
        ["issue", "create", "--title", title, "--body", body, ...labelArgs],
        { timeout: 15000 }
      );
      results.created.push({ title });
    } catch (err) {
      results.errors.push(`Failed to create issue "${title}": ${err.message}`);
    }
  }

  return results;
}
