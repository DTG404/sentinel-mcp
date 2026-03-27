import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { compareSemver, classifyStaleness } from "../versions.js";
import { classifyLicense } from "../licenses.js";

const execFileAsync = promisify(execFile);

export class PythonAdapter {
  constructor(projectPath, timeouts) {
    this._projectPath = projectPath;
    this._timeouts = timeouts;
  }

  async detectEcosystem() {
    try {
      await readFile(join(this._projectPath, "requirements.txt"), "utf8");
      return true;
    } catch {
      return false;
    }
  }

  async parseRequirementsTxt() {
    const raw = await readFile(join(this._projectPath, "requirements.txt"), "utf8");
    const lines = raw.split("\n");
    const deps = [];

    for (const line of lines) {
      const trimmed = line.trim();

      // Skip empty lines, comments, and editable installs
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-e")) continue;

      // Skip other option lines (e.g. -r, --index-url)
      if (trimmed.startsWith("-")) continue;

      // Parse name and version — support ==, >=, <=, ~=, !=
      // We extract the first version constraint's numeric value
      const match = trimmed.match(/^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=)\s*([\d]+\.[\d]+\.?[\d]*)/);
      if (match) {
        const name = match[1].toLowerCase().replace(/_/g, "-");
        const version = match[2];
        deps.push({ name, version });
      } else {
        // No version constraint — still include the package
        const nameMatch = trimmed.match(/^([A-Za-z0-9_\-\.]+)/);
        if (nameMatch) {
          const name = nameMatch[1].toLowerCase().replace(/_/g, "-");
          deps.push({ name, version: null });
        }
      }
    }

    return deps;
  }

  async _tryNativeAudit() {
    try {
      const { stdout } = await execFileAsync(
        "pip-audit",
        ["--format=json", "-r", "requirements.txt"],
        { cwd: this._projectPath, timeout: this._timeouts.cliMs }
      );
      const data = JSON.parse(stdout);
      const vulns = [];

      // pip-audit format: array of { name, version, vulns: [...] }
      if (Array.isArray(data)) {
        for (const pkg of data) {
          for (const vuln of pkg.vulns ?? []) {
            vulns.push({
              id: vuln.id,
              package: pkg.name,
              installedVersion: pkg.version,
              fixedVersion: vuln.fix_versions?.[0] ?? null,
              summary: vuln.description ?? "",
              severity: "unknown",
              references: vuln.aliases ?? [],
            });
          }
        }
      }
      // pip-audit may also return { dependencies: [...] } format
      else if (data.dependencies) {
        for (const pkg of data.dependencies) {
          for (const vuln of pkg.vulns ?? []) {
            vulns.push({
              id: vuln.id,
              package: pkg.name,
              installedVersion: pkg.version,
              fixedVersion: vuln.fix_versions?.[0] ?? null,
              summary: vuln.description ?? "",
              severity: "unknown",
              references: vuln.aliases ?? [],
            });
          }
        }
      }

      return { success: true, vulns };
    } catch (err) {
      // pip-audit exits non-zero when vulnerabilities found — try to parse stdout
      if (err.stdout) {
        try {
          const data = JSON.parse(err.stdout);
          const vulns = [];
          const pkgList = Array.isArray(data) ? data : (data.dependencies ?? []);
          for (const pkg of pkgList) {
            for (const vuln of pkg.vulns ?? []) {
              vulns.push({
                id: vuln.id,
                package: pkg.name,
                installedVersion: pkg.version,
                fixedVersion: vuln.fix_versions?.[0] ?? null,
                summary: vuln.description ?? "",
                severity: "unknown",
                references: vuln.aliases ?? [],
              });
            }
          }
          return { success: true, vulns };
        } catch {
          // Not parseable
        }
      }
      return { success: false, vulns: [] };
    }
  }

  async _tryNativeOutdated() {
    try {
      const { stdout } = await execFileAsync(
        "pip",
        ["list", "--outdated", "--format=json"],
        { cwd: this._projectPath, timeout: this._timeouts.cliMs }
      );
      const data = JSON.parse(stdout);
      const outdated = [];

      // Format: [{ name, version, latest_version, latest_filetype }]
      for (const pkg of data) {
        const behindBy = compareSemver(pkg.version, pkg.latest_version);
        const staleness = classifyStaleness(behindBy);
        outdated.push({
          name: pkg.name,
          current: pkg.version,
          latest: pkg.latest_version,
          staleness,
        });
      }

      return { success: true, outdated };
    } catch {
      return { success: false, outdated: [] };
    }
  }

  async _fetchPypiInfo(packageName) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeouts.apiMs);
    try {
      const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) return null;
      return await response.json();
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async scanVulns(osvClient) {
    const native = await this._tryNativeAudit();
    if (native.success) {
      return { mode: "native", vulns: native.vulns };
    }

    // Fallback: use requirements.txt + OSV API
    let deps;
    try {
      deps = await this.parseRequirementsTxt();
    } catch {
      return { mode: "fallback", vulns: [] };
    }

    const depsWithVersion = deps.filter((d) => d.version !== null);
    if (depsWithVersion.length === 0) {
      return { mode: "fallback", vulns: [] };
    }

    const vulns = await osvClient.queryBatch("PyPI", depsWithVersion);
    return { mode: "fallback", vulns };
  }

  async checkOutdated(licenseConfig) {
    const native = await this._tryNativeOutdated();
    if (native.success) {
      return { mode: "native", outdated: native.outdated };
    }

    // Fallback: use requirements.txt + PyPI API
    let deps;
    try {
      deps = await this.parseRequirementsTxt();
    } catch {
      return { mode: "fallback", outdated: [] };
    }

    const outdated = [];
    for (const dep of deps) {
      if (!dep.version) continue;

      const info = await this._fetchPypiInfo(dep.name);
      if (!info) continue;

      const latest = info.info?.version ?? null;
      if (!latest) continue;

      const behindBy = compareSemver(dep.version, latest);
      const staleness = classifyStaleness(behindBy);
      if (staleness !== "current") {
        outdated.push({ name: dep.name, current: dep.version, latest, staleness });
      }
    }

    return { mode: "fallback", outdated };
  }

  async detectLicenses(licenseConfig) {
    let deps;
    try {
      deps = await this.parseRequirementsTxt();
    } catch {
      return [];
    }

    const results = [];
    for (const dep of deps) {
      const info = await this._fetchPypiInfo(dep.name);
      const license = info?.info?.license ?? null;
      const { risk } = classifyLicense(license, licenseConfig);
      results.push({ package: dep.name, license, risk });
    }
    return results;
  }
}
