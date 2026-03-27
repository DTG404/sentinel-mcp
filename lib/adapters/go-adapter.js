import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { compareSemver, classifyStaleness } from "../versions.js";
import { classifyLicense } from "../licenses.js";

const execFileAsync = promisify(execFile);

export class GoAdapter {
  constructor(projectPath, timeouts) {
    this._projectPath = projectPath;
    this._timeouts = timeouts;
  }

  async detectEcosystem() {
    try {
      await readFile(join(this._projectPath, "go.mod"), "utf8");
      return true;
    } catch {
      return false;
    }
  }

  async parseGoMod() {
    const raw = await readFile(join(this._projectPath, "go.mod"), "utf8");
    const lines = raw.split("\n");

    let moduleName = "";
    const dependencies = [];
    let inRequireBlock = false;

    for (const line of lines) {
      const trimmed = line.trim();

      // Parse module declaration
      const moduleMatch = trimmed.match(/^module\s+(\S+)/);
      if (moduleMatch) {
        moduleName = moduleMatch[1];
        continue;
      }

      // Detect require block start/end
      if (trimmed === "require (") {
        inRequireBlock = true;
        continue;
      }
      if (inRequireBlock && trimmed === ")") {
        inRequireBlock = false;
        continue;
      }

      // Single-line require
      const singleRequireMatch = trimmed.match(/^require\s+(\S+)\s+(v\S+)/);
      if (singleRequireMatch) {
        const [, name, version] = singleRequireMatch;
        dependencies.push({ name, version, indirect: false });
        continue;
      }

      // Line inside require block
      if (inRequireBlock && trimmed) {
        // Format: "github.com/pkg v1.2.3" or "github.com/pkg v1.2.3 // indirect"
        const depMatch = trimmed.match(/^(\S+)\s+(v\S+)(?:\s+\/\/\s+indirect)?/);
        if (depMatch) {
          const [, name, version] = depMatch;
          const indirect = trimmed.includes("// indirect");
          dependencies.push({ name, version, indirect });
        }
      }
    }

    return { module: moduleName, dependencies };
  }

  async parseGoSum() {
    try {
      const raw = await readFile(join(this._projectPath, "go.sum"), "utf8");
      const lines = raw.split("\n").filter((l) => l.trim());

      // go.sum has two entries per package: hash and go.mod hash
      // Format: "github.com/pkg v1.2.3 h1:abc="
      // We want only the non-go.mod entries and deduplicate
      const seen = new Map();

      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 2) continue;

        const name = parts[0];
        const versionFull = parts[1]; // may be "v1.2.3" or "v1.2.3/go.mod"

        // Skip go.mod hash entries
        if (versionFull.endsWith("/go.mod")) continue;

        const version = versionFull;
        const key = `${name}@${version}`;
        if (!seen.has(key)) {
          seen.set(key, { name, version });
        }
      }

      return Array.from(seen.values());
    } catch {
      return null;
    }
  }

  async _tryNativeVulncheck() {
    try {
      const { stdout } = await execFileAsync(
        "govulncheck",
        ["-json", "./..."],
        { cwd: this._projectPath, timeout: this._timeouts.cliMs }
      );

      // govulncheck outputs newline-delimited JSON objects
      const vulns = [];
      const lines = stdout.split("\n").filter((l) => l.trim());

      for (const line of lines) {
        try {
          const obj = JSON.parse(line);
          // govulncheck emits different message types; we want "vuln" type
          if (obj.vuln) {
            const v = obj.vuln;
            vulns.push({
              id: v.osv?.id ?? v.id ?? "unknown",
              package: v.modules?.[0]?.path ?? "unknown",
              installedVersion: v.modules?.[0]?.found_version ?? null,
              fixedVersion: v.modules?.[0]?.fixed_version ?? null,
              summary: v.osv?.summary ?? "",
              severity: "unknown",
              references: v.osv?.references?.map((r) => r.url).filter(Boolean) ?? [],
            });
          }
        } catch {
          // Skip unparseable lines
        }
      }

      return { success: true, vulns };
    } catch (err) {
      // govulncheck may output JSON to stderr or exit non-zero on vulns
      if (err.stdout) {
        try {
          const vulns = [];
          const lines = err.stdout.split("\n").filter((l) => l.trim());
          for (const line of lines) {
            try {
              const obj = JSON.parse(line);
              if (obj.vuln) {
                const v = obj.vuln;
                vulns.push({
                  id: v.osv?.id ?? v.id ?? "unknown",
                  package: v.modules?.[0]?.path ?? "unknown",
                  installedVersion: v.modules?.[0]?.found_version ?? null,
                  fixedVersion: v.modules?.[0]?.fixed_version ?? null,
                  summary: v.osv?.summary ?? "",
                  severity: "unknown",
                  references: v.osv?.references?.map((r) => r.url).filter(Boolean) ?? [],
                });
              }
            } catch {
              // Skip
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
        "go",
        ["list", "-m", "-u", "-json", "all"],
        { cwd: this._projectPath, timeout: this._timeouts.cliMs }
      );

      // go list -m -u -json outputs concatenated JSON objects, not an array
      // Split on "}\n{" to get individual objects
      const parts = stdout.split(/\}\s*\n\s*\{/);
      const outdated = [];

      for (let i = 0; i < parts.length; i++) {
        let chunk = parts[i];
        // Re-add braces stripped by the split
        if (i > 0) chunk = "{" + chunk;
        if (i < parts.length - 1) chunk = chunk + "}";

        try {
          const mod = JSON.parse(chunk);
          if (!mod.Path || !mod.Version || !mod.Update) continue;

          const behindBy = compareSemver(mod.Version, mod.Update.Version);
          const staleness = classifyStaleness(behindBy);

          outdated.push({
            name: mod.Path,
            current: mod.Version,
            latest: mod.Update.Version,
            staleness,
          });
        } catch {
          // Skip unparseable chunks
        }
      }

      return { success: true, outdated };
    } catch {
      return { success: false, outdated: [] };
    }
  }

  async _fetchGoProxyVersion(modulePath) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeouts.apiMs);
    try {
      // Go module paths need to be lowercased for the proxy URL
      const encodedPath = modulePath.toLowerCase();
      const url = `https://proxy.golang.org/${encodedPath}/@latest`;
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) return null;
      const data = await response.json();
      return data.Version ?? null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  // Go has no standard license API — return null
  async _fetchGoProxyLicense(_modulePath) {
    return null;
  }

  async scanVulns(osvClient) {
    const native = await this._tryNativeVulncheck();
    if (native.success) {
      return { mode: "native", vulns: native.vulns };
    }

    // Fallback: use go.sum + OSV API
    const packages = await this.parseGoSum();
    if (!packages || packages.length === 0) {
      return { mode: "fallback", vulns: [] };
    }

    const vulns = await osvClient.queryBatch("Go", packages);
    return { mode: "fallback", vulns };
  }

  async checkOutdated(licenseConfig) {
    const native = await this._tryNativeOutdated();
    if (native.success) {
      return { mode: "native", outdated: native.outdated };
    }

    // Fallback: use go.mod + Go proxy
    let parsed;
    try {
      parsed = await this.parseGoMod();
    } catch {
      return { mode: "fallback", outdated: [] };
    }

    const outdated = [];
    for (const dep of parsed.dependencies) {
      const latest = await this._fetchGoProxyVersion(dep.name);
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
    let parsed;
    try {
      parsed = await this.parseGoMod();
    } catch {
      return [];
    }

    const results = [];
    for (const dep of parsed.dependencies) {
      const license = await this._fetchGoProxyLicense(dep.name);
      const { risk } = classifyLicense(license, licenseConfig);
      results.push({ package: dep.name, license, risk });
    }
    return results;
  }
}
