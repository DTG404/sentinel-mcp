import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { compareSemver, classifyStaleness } from "../versions.js";
import { classifyLicense } from "../licenses.js";

const execFileAsync = promisify(execFile);
const CRATES_IO_BASE = "https://crates.io/api/v1/crates";

function stripQuotes(value) {
  const trimmed = value.trim();
  return trimmed.replace(/^"([\s\S]*)"$/, "$1");
}

function extractVersion(value) {
  if (!value) return null;
  const match = value.match(/[0-9]+\.[0-9]+(?:\.[0-9]+)?/);
  return match ? match[0] : null;
}

export class RustAdapter {
  constructor(projectPath, timeouts) {
    this._projectPath = projectPath;
    this._timeouts = timeouts;
    this._lastCratesIoRequestAt = 0;
  }

  async detectEcosystem() {
    try {
      await readFile(join(this._projectPath, "Cargo.toml"), "utf8");
      return true;
    } catch {
      return false;
    }
  }

  async parseCargoToml() {
    const raw = await readFile(join(this._projectPath, "Cargo.toml"), "utf8");
    const lines = raw.split("\n");
    const manifest = {
      package: { name: null, version: null, license: null },
      dependencies: [],
    };

    let section = null;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const sectionMatch = trimmed.match(/^\[(.+)\]$/);
      if (sectionMatch) {
        section = sectionMatch[1];
        continue;
      }

      if (section === "package") {
        const pkgMatch = trimmed.match(/^(name|version|license)\s*=\s*(.+)$/);
        if (pkgMatch) {
          manifest.package[pkgMatch[1]] = stripQuotes(pkgMatch[2]);
        }
        continue;
      }

      const isDependencySection = section === "dependencies" || section === "dev-dependencies";
      if (!isDependencySection) continue;

      const depMatch = trimmed.match(/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
      if (!depMatch) continue;

      const [, name, rawValue] = depMatch;
      let version = null;
      if (rawValue.trim().startsWith("{")) {
        const versionMatch = rawValue.match(/version\s*=\s*"([^"]+)"/);
        version = versionMatch ? versionMatch[1] : null;
      } else {
        version = stripQuotes(rawValue);
      }

      manifest.dependencies.push({
        name,
        version: extractVersion(version),
        constraint: version,
        dev: section === "dev-dependencies",
      });
    }

    return manifest;
  }

  async parseCargoLock() {
    try {
      const raw = await readFile(join(this._projectPath, "Cargo.lock"), "utf8");
      const packages = [];
      const blocks = raw.split("[[package]]").slice(1);
      for (const block of blocks) {
        const nameMatch = block.match(/\nname\s*=\s*"([^"]+)"/);
        const versionMatch = block.match(/\nversion\s*=\s*"([^"]+)"/);
        if (nameMatch && versionMatch) {
          packages.push({ name: nameMatch[1], version: versionMatch[1] });
        }
      }
      return packages;
    } catch {
      return null;
    }
  }

  _parseCargoAuditData(data) {
    const advisories = [
      ...(Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : []),
      ...(Array.isArray(data?.vulnerabilities?.list) ? data.vulnerabilities.list : []),
      ...(Array.isArray(data?.advisories) ? data.advisories : []),
    ];

    return advisories.map((entry) => {
      const advisory = entry.advisory ?? entry;
      const packageName = entry.package?.name ?? entry.package?.package ?? advisory.package ?? "unknown";
      const installedVersion = entry.package?.version ?? entry.versions?.patched?.[0] ?? null;
      const fixedVersion = entry.versions?.patched?.[0] ?? advisory.patched ?? null;
      const aliases = Array.isArray(advisory.aliases) ? advisory.aliases : [];
      return {
        id: advisory.id ?? aliases[0] ?? "unknown",
        package: packageName,
        installedVersion,
        fixedVersion,
        summary: advisory.title ?? advisory.description ?? advisory.summary ?? "",
        severity: advisory.cvss ? classifyLicense(advisory.cvss, { allowed: [], flagged: [] }).risk : "unknown",
        references: Array.isArray(advisory.url) ? advisory.url : [advisory.url].filter(Boolean),
      };
    }).map((vuln) => ({ ...vuln, severity: ["low", "medium", "high", "critical"].includes(vuln.severity) ? vuln.severity : "unknown" }));
  }

  async _tryNativeAudit() {
    try {
      const { stdout } = await execFileAsync(
        "cargo",
        ["audit", "--json"],
        { cwd: this._projectPath, timeout: this._timeouts.cliMs }
      );
      return { success: true, vulns: this._parseCargoAuditData(JSON.parse(stdout)) };
    } catch (err) {
      if (err.stdout) {
        try {
          return { success: true, vulns: this._parseCargoAuditData(JSON.parse(err.stdout)) };
        } catch {
          // ignore
        }
      }
      return { success: false, vulns: [] };
    }
  }

  _parseCargoOutdatedData(data) {
    const packages = Array.isArray(data)
      ? data
      : Array.isArray(data?.dependencies)
        ? data.dependencies
        : Array.isArray(data?.packages)
          ? data.packages
          : [];

    return packages.flatMap((pkg) => {
      const current = pkg.version ?? pkg.project ?? pkg.current;
      const latest = pkg.latest ?? pkg.compat ?? pkg.newest;
      if (!pkg.name || !current || !latest) return [];
      const behindBy = compareSemver(current, latest);
      const staleness = classifyStaleness(behindBy);
      if (staleness === "current") return [];
      return [{ name: pkg.name, current, latest, staleness }];
    });
  }

  async _tryNativeOutdated() {
    try {
      const { stdout } = await execFileAsync(
        "cargo",
        ["outdated", "--format", "json"],
        { cwd: this._projectPath, timeout: this._timeouts.cliMs }
      );
      return { success: true, outdated: this._parseCargoOutdatedData(JSON.parse(stdout)) };
    } catch (err) {
      if (err.stdout) {
        try {
          return { success: true, outdated: this._parseCargoOutdatedData(JSON.parse(err.stdout)) };
        } catch {
          // ignore
        }
      }
      return { success: false, outdated: [] };
    }
  }

  async _tryNativeLicense(licenseConfig) {
    try {
      const { stdout } = await execFileAsync(
        "cargo",
        ["license", "--json"],
        { cwd: this._projectPath, timeout: this._timeouts.cliMs }
      );
      const data = JSON.parse(stdout);
      const licenses = (Array.isArray(data) ? data : []).map((entry) => {
        const license = entry.license ?? null;
        const { risk } = classifyLicense(license, licenseConfig);
        return { package: entry.name, license, risk };
      });
      return { success: true, licenses };
    } catch {
      return { success: false, licenses: [] };
    }
  }

  async _rateLimitCratesIo() {
    const elapsed = Date.now() - this._lastCratesIoRequestAt;
    if (elapsed < 1000) {
      await new Promise((resolve) => setTimeout(resolve, 1000 - elapsed));
    }
    this._lastCratesIoRequestAt = Date.now();
  }

  async _fetchCrateInfo(crateName) {
    await this._rateLimitCratesIo();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeouts.apiMs);
    try {
      const response = await fetch(`${CRATES_IO_BASE}/${encodeURIComponent(crateName)}`, { signal: controller.signal });
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

    const packages = await this.parseCargoLock();
    if (!packages || packages.length === 0) {
      return { mode: "fallback", vulns: [] };
    }

    const vulns = await osvClient.queryBatch("crates.io", packages);
    return { mode: "fallback", vulns };
  }

  async checkOutdated(_licenseConfig) {
    const native = await this._tryNativeOutdated();
    if (native.success) {
      return { mode: "native", outdated: native.outdated };
    }

    let manifest;
    try {
      manifest = await this.parseCargoToml();
    } catch {
      return { mode: "fallback", outdated: [] };
    }

    const locked = await this.parseCargoLock();
    const lockedByName = new Map((locked ?? []).map((pkg) => [pkg.name, pkg.version]));
    const outdated = [];

    for (const dep of manifest.dependencies) {
      const current = lockedByName.get(dep.name) ?? dep.version;
      if (!current) continue;
      const info = await this._fetchCrateInfo(dep.name);
      const latest = info?.crate?.max_stable_version ?? info?.crate?.newest_version ?? null;
      if (!latest) continue;
      const behindBy = compareSemver(current, latest);
      const staleness = classifyStaleness(behindBy);
      if (staleness !== "current") {
        outdated.push({ name: dep.name, current, latest, staleness });
      }
    }

    return { mode: "fallback", outdated };
  }

  async detectLicenses(licenseConfig) {
    const native = await this._tryNativeLicense(licenseConfig);
    if (native.success && native.licenses.length > 0) {
      return native.licenses;
    }

    let manifest;
    try {
      manifest = await this.parseCargoToml();
    } catch {
      return [];
    }

    const license = manifest.package.license ?? null;
    const { risk } = classifyLicense(license, licenseConfig);
    return manifest.package.name ? [{ package: manifest.package.name, license, risk }] : [];
  }
}
