import { OsvClient } from "./osv-client.js";
import { NodeAdapter } from "./adapters/node-adapter.js";
import { GoAdapter } from "./adapters/go-adapter.js";
import { PythonAdapter } from "./adapters/python-adapter.js";

export class Scanner {
  constructor(config) {
    this._config = config;
    this._osv = new OsvClient(config.timeouts.apiMs);
  }

  async scanProject(projectPath) {
    const report = {
      project: projectPath, ecosystems: [], scannedAt: new Date().toISOString(),
      toolMode: {}, osvStatus: "ok", vulnerabilities: [], outdated: [], licenses: [], errors: [],
    };

    const adapters = [
      { name: "node", adapter: new NodeAdapter(projectPath, this._config.timeouts) },
      { name: "go", adapter: new GoAdapter(projectPath, this._config.timeouts) },
      { name: "python", adapter: new PythonAdapter(projectPath, this._config.timeouts) },
    ];

    for (const { name, adapter } of adapters) {
      let detected;
      try { detected = await adapter.detectEcosystem(); } catch (err) {
        report.errors.push(`${name}: detection failed: ${err.message}`); continue;
      }
      if (!detected) continue;
      report.ecosystems.push(name);

      try {
        const vulnResult = await adapter.scanVulns(this._osv);
        report.toolMode[name] = vulnResult.mode;
        report.vulnerabilities.push(...vulnResult.vulns);
      } catch (err) { report.errors.push(`${name}: vuln scan failed: ${err.message}`); }

      try {
        const outdatedResult = await adapter.checkOutdated(this._config.licenses);
        report.outdated.push(...outdatedResult.outdated);
      } catch (err) { report.errors.push(`${name}: outdated check failed: ${err.message}`); }

      try {
        const licenseResult = await adapter.detectLicenses(this._config.licenses);
        report.licenses.push(...licenseResult);
      } catch (err) { report.errors.push(`${name}: license detection failed: ${err.message}`); }
    }
    return report;
  }
}
