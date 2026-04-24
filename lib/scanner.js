import { OsvClient } from "./osv-client.js";
import { NodeAdapter } from "./adapters/node-adapter.js";
import { GoAdapter } from "./adapters/go-adapter.js";
import { PythonAdapter } from "./adapters/python-adapter.js";
import { RustAdapter } from "./adapters/rust-adapter.js";

export async function scanProjectsWithConcurrency(projects, scanner, concurrency = 5) {
  const results = [];
  const limit = Math.max(1, concurrency);
  for (let i = 0; i < projects.length; i += limit) {
    const batch = projects.slice(i, i + limit);
    const batchResults = await Promise.all(batch.map((project) => scanner.scanProject(project.path)));
    results.push(...batchResults);
  }
  return results;
}

export class Scanner {
  constructor(config) {
    this._config = config;
    this._osv = new OsvClient(config.timeouts.apiMs);
  }

  _createAdapters(projectPath) {
    return [
      { name: "node", adapter: new NodeAdapter(projectPath, this._config.timeouts) },
      { name: "go", adapter: new GoAdapter(projectPath, this._config.timeouts) },
      { name: "python", adapter: new PythonAdapter(projectPath, this._config.timeouts) },
      { name: "rust", adapter: new RustAdapter(projectPath, this._config.timeouts) },
    ];
  }

  async scanProject(projectPath) {
    const report = {
      project: projectPath, ecosystems: [], scannedAt: new Date().toISOString(),
      toolMode: {}, osvStatus: "ok", vulnerabilities: [], outdated: [], licenses: [], errors: [],
    };

    const adapterResults = await Promise.all(this._createAdapters(projectPath).map(async ({ name, adapter }) => {
      let detected;
      try {
        detected = await adapter.detectEcosystem();
      } catch (err) {
        return { name, errors: [`${name}: detection failed: ${err.message}`] };
      }
      if (!detected) return { name, skipped: true, errors: [] };

      const result = { name, ecosystems: [name], vulns: [], outdated: [], licenses: [], errors: [], toolMode: {} };
      const [vulnResult, outdatedResult, licenseResult] = await Promise.allSettled([
        adapter.scanVulns(this._osv),
        adapter.checkOutdated(this._config.licenses),
        adapter.detectLicenses(this._config.licenses),
      ]);

      if (vulnResult.status === "fulfilled") {
        result.toolMode[name] = vulnResult.value.mode;
        result.vulns = vulnResult.value.vulns;
      } else {
        result.errors.push(`${name}: vuln scan failed: ${vulnResult.reason.message}`);
      }

      if (outdatedResult.status === "fulfilled") {
        result.outdated = outdatedResult.value.outdated;
      } else {
        result.errors.push(`${name}: outdated check failed: ${outdatedResult.reason.message}`);
      }

      if (licenseResult.status === "fulfilled") {
        result.licenses = licenseResult.value;
      } else {
        result.errors.push(`${name}: license detection failed: ${licenseResult.reason.message}`);
      }

      return result;
    }));

    for (const result of adapterResults) {
      if (result.skipped) continue;
      report.ecosystems.push(...(result.ecosystems ?? []));
      report.vulnerabilities.push(...(result.vulns ?? []));
      report.outdated.push(...(result.outdated ?? []));
      report.licenses.push(...(result.licenses ?? []));
      report.errors.push(...(result.errors ?? []));
      Object.assign(report.toolMode, result.toolMode ?? {});
    }
    return report;
  }
}
