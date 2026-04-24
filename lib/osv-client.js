const OSV_API_URL = "https://api.osv.dev/v1/query";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class OsvClient {
  constructor(timeoutMs) {
    this._timeoutMs = timeoutMs;
  }

  buildQuery(ecosystem, packageName, version) {
    return {
      package: { name: packageName, ecosystem },
      version,
    };
  }

  normalizeSeverity(score) {
    if (score === undefined || score === null) return "unknown";
    if (typeof score === "string") {
      const s = score.toUpperCase();
      if (s === "CRITICAL") return "critical";
      if (s === "HIGH") return "high";
      if (s === "MEDIUM" || s === "MODERATE") return "medium";
      if (s === "LOW") return "low";
      return "unknown";
    }
    if (typeof score === "number") {
      if (score >= 9.0) return "critical";
      if (score >= 7.0) return "high";
      if (score >= 4.0) return "medium";
      if (score > 0) return "low";
      return "unknown";
    }
    return "unknown";
  }

  _extractCvssScore(severityArray) {
    if (!Array.isArray(severityArray)) return undefined;
    for (const s of severityArray) {
      if (s.type === "CVSS_V3" || s.type === "CVSS_V2") {
        // Extract base score from CVSS vector string — not straightforward without a lib,
        // but we can check for known high-score patterns or return undefined to let
        // database_specific.severity handle it.
        // Return the score string so parseVulns can use it as string severity.
        return s.score;
      }
    }
    return undefined;
  }

  parseVulns(osvResponse, packageName, installedVersion) {
    const vulns = osvResponse?.vulns;
    if (!Array.isArray(vulns)) return [];

    return vulns.map((vuln) => {
      // Find fixed version from affected ranges
      let fixedVersion = null;
      if (Array.isArray(vuln.affected)) {
        for (const affected of vuln.affected) {
          if (Array.isArray(affected.ranges)) {
            for (const range of affected.ranges) {
              if (Array.isArray(range.events)) {
                for (const event of range.events) {
                  if (event.fixed) {
                    fixedVersion = event.fixed;
                    break;
                  }
                }
              }
              if (fixedVersion) break;
            }
          }
          if (fixedVersion) break;
        }
      }

      // Determine severity
      let severity = "unknown";
      const dbSeverity = vuln.database_specific?.severity;
      if (dbSeverity) {
        severity = this.normalizeSeverity(dbSeverity);
      } else {
        const cvssScore = this._extractCvssScore(vuln.severity);
        if (cvssScore) {
          severity = this.normalizeSeverity(cvssScore);
        }
      }

      // Extract references
      const references = Array.isArray(vuln.references)
        ? vuln.references.map((r) => r.url).filter(Boolean)
        : [];

      return {
        id: vuln.id,
        package: packageName,
        installedVersion,
        fixedVersion,
        summary: vuln.summary ?? "",
        severity,
        references,
      };
    });
  }

  async query(query) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);

    try {
      const response = await fetch(OSV_API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(query),
        signal: controller.signal,
      });

      if (!response.ok) {
        const err = new Error(`OSV API error: ${response.status} ${response.statusText}`);
        err.status = response.status;
        throw err;
      }

      return await response.json();
    } finally {
      clearTimeout(timer);
    }
  }

  async queryWithRetry(query, maxRetries = 3) {
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await this.query(query);
      } catch (err) {
        if ((err.status === 429 || err.status >= 500) && i < maxRetries - 1) {
          const delay = Math.min(1000 * (2 ** i), 10000);
          await sleep(delay);
          continue;
        }
        throw err;
      }
    }
    throw new Error(`OSV API query failed after ${maxRetries} retries`);
  }

  async queryPackage(ecosystem, packageName, version) {
    const body = this.buildQuery(ecosystem, packageName, version);
    const data = await this.queryWithRetry(body);
    return this.parseVulns(data, packageName, version);
  }

  async queryBatch(ecosystem, packages) {
    const results = [];
    for (const pkg of packages) {
      const vulns = await this.queryPackage(ecosystem, pkg.name, pkg.version);
      results.push(...vulns);
    }
    return results;
  }
}
