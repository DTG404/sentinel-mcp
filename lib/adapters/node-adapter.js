import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { compareSemver, classifyStaleness } from "../versions.js";
import { classifyLicense } from "../licenses.js";

const execFileAsync = promisify(execFile);

export class NodeAdapter {
  constructor(projectPath, timeouts) {
    this._projectPath = projectPath;
    this._timeouts = timeouts;
  }

  async detectEcosystem() {
    try {
      await readFile(join(this._projectPath, "package.json"), "utf8");
      return true;
    } catch {
      return false;
    }
  }

  async parsePackageJson() {
    const raw = await readFile(join(this._projectPath, "package.json"), "utf8");
    const pkg = JSON.parse(raw);

    const dependencies = [];

    for (const [name, range] of Object.entries(pkg.dependencies ?? {})) {
      dependencies.push({ name, range, dev: false });
    }
    for (const [name, range] of Object.entries(pkg.devDependencies ?? {})) {
      dependencies.push({ name, range, dev: true });
    }

    return { dependencies, projectLicense: pkg.license ?? null };
  }

  async parsePackageLock() {
    try {
      const raw = await readFile(join(this._projectPath, "package-lock.json"), "utf8");
      const lock = JSON.parse(raw);

      // v2/v3 format uses "packages" key
      if (!lock.packages) return null;

      const packages = [];
      for (const [key, val] of Object.entries(lock.packages)) {
        // Skip the root entry (empty string key or name-only entry)
        if (!key || key === "") continue;
        // Strip "node_modules/" prefix to get package name
        const name = key.replace(/^node_modules\//, "");
        if (val.version) {
          packages.push({ name, version: val.version });
        }
      }
      return packages;
    } catch {
      return null;
    }
  }

  async _tryNativeAudit() {
    try {
      const { stdout } = await execFileAsync(
        "npm",
        ["audit", "--json"],
        { cwd: this._projectPath, timeout: this._timeouts.cliMs }
      );
      const data = JSON.parse(stdout);

      const vulns = [];

      // npm v7+ format: data.vulnerabilities
      if (data.vulnerabilities) {
        for (const [pkgName, vuln] of Object.entries(data.vulnerabilities)) {
          for (const via of vuln.via ?? []) {
            if (typeof via === "object" && via.source) {
              vulns.push({
                id: String(via.source),
                package: pkgName,
                installedVersion: vuln.version ?? null,
                fixedVersion: vuln.fixAvailable?.version ?? null,
                summary: via.title ?? "",
                severity: via.severity ?? "unknown",
                references: via.url ? [via.url] : [],
              });
            }
          }
        }
      }
      // npm v6 format: data.advisories
      else if (data.advisories) {
        for (const advisory of Object.values(data.advisories)) {
          vulns.push({
            id: String(advisory.id),
            package: advisory.module_name,
            installedVersion: advisory.findings?.[0]?.version ?? null,
            fixedVersion: advisory.patched_versions ?? null,
            summary: advisory.title ?? "",
            severity: advisory.severity ?? "unknown",
            references: advisory.references ? [advisory.references] : [],
          });
        }
      }

      return { success: true, vulns };
    } catch (err) {
      // npm audit exits with non-zero when vulns found — check if we still got JSON
      if (err.stdout) {
        try {
          const data = JSON.parse(err.stdout);
          // Recurse-like: re-parse the successful output
          const vulns = [];
          if (data.vulnerabilities) {
            for (const [pkgName, vuln] of Object.entries(data.vulnerabilities)) {
              for (const via of vuln.via ?? []) {
                if (typeof via === "object" && via.source) {
                  vulns.push({
                    id: String(via.source),
                    package: pkgName,
                    installedVersion: vuln.version ?? null,
                    fixedVersion: vuln.fixAvailable?.version ?? null,
                    summary: via.title ?? "",
                    severity: via.severity ?? "unknown",
                    references: via.url ? [via.url] : [],
                  });
                }
              }
            }
          } else if (data.advisories) {
            for (const advisory of Object.values(data.advisories)) {
              vulns.push({
                id: String(advisory.id),
                package: advisory.module_name,
                installedVersion: advisory.findings?.[0]?.version ?? null,
                fixedVersion: advisory.patched_versions ?? null,
                summary: advisory.title ?? "",
                severity: advisory.severity ?? "unknown",
                references: advisory.references ? [advisory.references] : [],
              });
            }
          }
          return { success: true, vulns };
        } catch {
          // stdout was not valid JSON
        }
      }
      return { success: false, vulns: [] };
    }
  }

  async _tryNativeOutdated() {
    let stdout;
    try {
      const result = await execFileAsync(
        "npm",
        ["outdated", "--json"],
        { cwd: this._projectPath, timeout: this._timeouts.cliMs }
      );
      stdout = result.stdout;
    } catch (err) {
      // npm outdated exits with code 1 when packages are outdated — still parse stdout
      if (err.stdout) {
        stdout = err.stdout;
      } else {
        return { success: false, outdated: [] };
      }
    }

    try {
      const data = JSON.parse(stdout);
      const outdated = [];

      for (const [pkgName, info] of Object.entries(data)) {
        const current = info.current;
        const latest = info.latest;
        const behindBy = compareSemver(current, latest);
        const staleness = classifyStaleness(behindBy);

        outdated.push({
          name: pkgName,
          current,
          latest,
          staleness,
        });
      }

      return { success: true, outdated };
    } catch {
      return { success: false, outdated: [] };
    }
  }

  async _fetchRegistryVersion(packageName) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeouts.apiMs);
    try {
      const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) return null;
      const data = await response.json();
      return data.version ?? null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async _fetchRegistryLicense(packageName) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeouts.apiMs);
    try {
      const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) return null;
      const data = await response.json();
      return data.license ?? null;
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

    // Fallback: use lockfile + OSV API
    const locked = await this.parsePackageLock();
    if (!locked || locked.length === 0) {
      return { mode: "fallback", vulns: [] };
    }

    const vulns = await osvClient.queryBatch("npm", locked);
    return { mode: "fallback", vulns };
  }

  async checkOutdated(licenseConfig) {
    const native = await this._tryNativeOutdated();
    if (native.success) {
      return { mode: "native", outdated: native.outdated };
    }

    // Fallback: use package.json + npm registry
    let parsed;
    try {
      parsed = await this.parsePackageJson();
    } catch {
      return { mode: "fallback", outdated: [] };
    }

    const outdated = [];
    for (const dep of parsed.dependencies) {
      const latest = await this._fetchRegistryVersion(dep.name);
      if (!latest) continue;

      // Extract numeric version from range (strip ^, ~, >=, etc.)
      const currentMatch = dep.range.match(/[\d]+\.[\d]+\.[\d]+/);
      const current = currentMatch ? currentMatch[0] : null;
      if (!current) continue;

      const behindBy = compareSemver(current, latest);
      const staleness = classifyStaleness(behindBy);
      if (staleness !== "current") {
        outdated.push({ name: dep.name, current, latest, staleness });
      }
    }

    return { mode: "fallback", outdated };
  }

  async detectLicenses(licenseConfig) {
    let parsed;
    try {
      parsed = await this.parsePackageJson();
    } catch {
      return [];
    }

    const results = [];
    for (const dep of parsed.dependencies) {
      const license = await this._fetchRegistryLicense(dep.name);
      const { risk } = classifyLicense(license, licenseConfig);
      results.push({ package: dep.name, license, risk });
    }
    return results;
  }
}
