import { strict as assert } from "node:assert";
import { loadConfig, DEFAULTS } from "./lib/config.js";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (err) {
    console.error(`  FAIL: ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

console.log("\n=== Config Tests ===\n");

await test("DEFAULTS has expected shape", () => {
  assert.ok(Array.isArray(DEFAULTS.roots));
  assert.ok(Array.isArray(DEFAULTS.exclude));
  assert.equal(typeof DEFAULTS.cache.ttlMs, "number");
  assert.equal(typeof DEFAULTS.severity.issueThreshold, "string");
  assert.ok(Array.isArray(DEFAULTS.licenses.allowed));
  assert.ok(Array.isArray(DEFAULTS.licenses.flagged));
  assert.equal(typeof DEFAULTS.github.dryRun, "boolean");
  assert.equal(typeof DEFAULTS.timeouts.cliMs, "number");
  assert.equal(typeof DEFAULTS.timeouts.apiMs, "number");
});

await test("loadConfig returns defaults when no config file exists", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-test-"));
  try {
    const config = await loadConfig(join(dir, "config.json"));
    assert.deepStrictEqual(config.cache, DEFAULTS.cache);
    assert.deepStrictEqual(config.severity, DEFAULTS.severity);
    assert.deepStrictEqual(config.timeouts, DEFAULTS.timeouts);
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("loadConfig merges partial user config with defaults", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-test-"));
  try {
    const configPath = join(dir, "config.json");
    await writeFile(configPath, JSON.stringify({
      roots: ["/custom/path"],
      cache: { ttlMs: 999 }
    }));
    const config = await loadConfig(configPath);
    assert.deepStrictEqual(config.roots, ["/custom/path"]);
    assert.equal(config.cache.ttlMs, 999);
    assert.deepStrictEqual(config.severity, DEFAULTS.severity);
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("loadConfig auto-creates config file when missing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-test-"));
  try {
    const configPath = join(dir, "subdir", "config.json");
    await loadConfig(configPath);
    const { access } = await import("node:fs/promises");
    await access(configPath);
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("loadConfig falls back to defaults on invalid JSON", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-test-"));
  try {
    const configPath = join(dir, "config.json");
    await writeFile(configPath, "not json {{{");
    const config = await loadConfig(configPath);
    assert.deepStrictEqual(config.cache, DEFAULTS.cache);
  } finally {
    await rm(dir, { recursive: true });
  }
});

const { Cache } = await import("./lib/cache.js");

console.log("\n=== Cache Tests ===\n");

await test("cache stores and retrieves scan results", () => {
  const cache = new Cache(60_000);
  const report = { project: "/test", vulnerabilities: [] };
  cache.set("/test", report);
  assert.deepStrictEqual(cache.get("/test"), report);
});

await test("cache returns null for missing keys", () => {
  const cache = new Cache(60_000);
  assert.equal(cache.get("/nonexistent"), null);
});

await test("cache returns null for expired entries", () => {
  const cache = new Cache(1);
  const report = { project: "/test", vulnerabilities: [] };
  cache.set("/test", report);
  cache._entries.get("/test").timestamp = Date.now() - 100;
  assert.equal(cache.get("/test"), null);
});

await test("cache.clear removes all entries", () => {
  const cache = new Cache(60_000);
  cache.set("/a", { project: "/a" });
  cache.set("/b", { project: "/b" });
  cache.clear();
  assert.equal(cache.get("/a"), null);
  assert.equal(cache.get("/b"), null);
});

await test("cache.has returns freshness status", () => {
  const cache = new Cache(60_000);
  assert.equal(cache.has("/test"), false);
  cache.set("/test", { project: "/test" });
  assert.equal(cache.has("/test"), true);
});

const { discoverProjects } = await import("./lib/discovery.js");

console.log("\n=== Discovery Tests ===\n");

await test("discovers Node.js project by package.json", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-disc-"));
  try {
    const proj = join(dir, "my-node-app");
    await mkdir(proj, { recursive: true });
    await writeFile(join(proj, "package.json"), "{}");
    const results = await discoverProjects([dir], []);
    assert.equal(results.length, 1);
    assert.equal(results[0].path, proj);
    assert.ok(results[0].ecosystems.includes("node"));
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("discovers Go project by go.mod", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-disc-"));
  try {
    const proj = join(dir, "my-go-app");
    await mkdir(proj, { recursive: true });
    await writeFile(join(proj, "go.mod"), "module example.com/foo");
    const results = await discoverProjects([dir], []);
    assert.equal(results.length, 1);
    assert.ok(results[0].ecosystems.includes("go"));
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("discovers Python project by requirements.txt", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-disc-"));
  try {
    const proj = join(dir, "my-py-app");
    await mkdir(proj, { recursive: true });
    await writeFile(join(proj, "requirements.txt"), "flask==2.0.0");
    const results = await discoverProjects([dir], []);
    assert.equal(results.length, 1);
    assert.ok(results[0].ecosystems.includes("python"));
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("discovers multi-ecosystem project", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-disc-"));
  try {
    const proj = join(dir, "fullstack");
    await mkdir(proj, { recursive: true });
    await writeFile(join(proj, "go.mod"), "module example.com/foo");
    await writeFile(join(proj, "package.json"), "{}");
    const results = await discoverProjects([dir], []);
    assert.equal(results.length, 1);
    assert.ok(results[0].ecosystems.includes("go"));
    assert.ok(results[0].ecosystems.includes("node"));
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("excludes directories matching exclude patterns", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-disc-"));
  try {
    const proj = join(dir, "node_modules");
    await mkdir(proj, { recursive: true });
    await writeFile(join(proj, "package.json"), "{}");
    const results = await discoverProjects([dir], ["*/node_modules/*", "*/node_modules"]);
    assert.equal(results.length, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("skips non-existent root directories", async () => {
  const results = await discoverProjects(["/nonexistent/path/12345"], []);
  assert.equal(results.length, 0);
});

const { OsvClient } = await import("./lib/osv-client.js");

console.log("\n=== OSV Client Tests ===\n");

await test("OsvClient constructs with timeout", () => {
  const client = new OsvClient(5000);
  assert.equal(client._timeoutMs, 5000);
});

await test("OsvClient.buildQuery creates correct payload for npm", () => {
  const client = new OsvClient(5000);
  const query = client.buildQuery("npm", "lodash", "4.17.20");
  assert.deepStrictEqual(query, { package: { name: "lodash", ecosystem: "npm" }, version: "4.17.20" });
});

await test("OsvClient.buildQuery creates correct payload for Go", () => {
  const client = new OsvClient(5000);
  const query = client.buildQuery("Go", "golang.org/x/net", "0.17.0");
  assert.deepStrictEqual(query, { package: { name: "golang.org/x/net", ecosystem: "Go" }, version: "0.17.0" });
});

await test("OsvClient.buildQuery creates correct payload for PyPI", () => {
  const client = new OsvClient(5000);
  const query = client.buildQuery("PyPI", "flask", "2.0.0");
  assert.deepStrictEqual(query, { package: { name: "flask", ecosystem: "PyPI" }, version: "2.0.0" });
});

await test("OsvClient.normalizeSeverity maps CVSS to levels", () => {
  const client = new OsvClient(5000);
  assert.equal(client.normalizeSeverity(9.5), "critical");
  assert.equal(client.normalizeSeverity(7.5), "high");
  assert.equal(client.normalizeSeverity(5.0), "medium");
  assert.equal(client.normalizeSeverity(2.0), "low");
  assert.equal(client.normalizeSeverity(undefined), "unknown");
});

await test("OsvClient.parseVulns extracts structured data from OSV response", () => {
  const client = new OsvClient(5000);
  const osvResponse = {
    vulns: [{
      id: "GHSA-xxxx-yyyy",
      summary: "Test vulnerability",
      database_specific: { severity: "HIGH" },
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      affected: [{
        package: { name: "lodash", ecosystem: "npm" },
        ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      }],
      references: [{ type: "ADVISORY", url: "https://example.com" }],
    }],
  };
  const vulns = client.parseVulns(osvResponse, "lodash", "4.17.20");
  assert.equal(vulns.length, 1);
  assert.equal(vulns[0].id, "GHSA-xxxx-yyyy");
  assert.equal(vulns[0].package, "lodash");
  assert.equal(vulns[0].installedVersion, "4.17.20");
  assert.equal(vulns[0].fixedVersion, "4.17.21");
  assert.equal(vulns[0].summary, "Test vulnerability");
});

const { compareSemver, classifyStaleness } = await import("./lib/versions.js");

console.log("\n=== Version Tests ===\n");

await test("compareSemver parses major difference", () => {
  const result = compareSemver("1.0.0", "3.2.1");
  assert.deepStrictEqual(result, { major: 2, minor: 2, patch: 1 });
});

await test("compareSemver parses minor difference", () => {
  const result = compareSemver("1.0.0", "1.5.0");
  assert.deepStrictEqual(result, { major: 0, minor: 5, patch: 0 });
});

await test("compareSemver parses patch difference", () => {
  const result = compareSemver("1.2.3", "1.2.7");
  assert.deepStrictEqual(result, { major: 0, minor: 0, patch: 4 });
});

await test("compareSemver handles equal versions", () => {
  const result = compareSemver("2.0.0", "2.0.0");
  assert.deepStrictEqual(result, { major: 0, minor: 0, patch: 0 });
});

await test("compareSemver handles versions with v prefix", () => {
  const result = compareSemver("v1.0.0", "v2.0.0");
  assert.deepStrictEqual(result, { major: 1, minor: 0, patch: 0 });
});

await test("compareSemver handles non-semver gracefully", () => {
  const result = compareSemver("latest", "1.0.0");
  assert.equal(result, null);
});

await test("classifyStaleness returns major for major bumps", () => {
  assert.equal(classifyStaleness({ major: 1, minor: 0, patch: 0 }), "major");
});

await test("classifyStaleness returns minor for minor bumps", () => {
  assert.equal(classifyStaleness({ major: 0, minor: 3, patch: 0 }), "minor");
});

await test("classifyStaleness returns patch for patch bumps", () => {
  assert.equal(classifyStaleness({ major: 0, minor: 0, patch: 2 }), "patch");
});

const { classifyLicense } = await import("./lib/licenses.js");

console.log("\n=== License Tests ===\n");

await test("classifies MIT as low risk", () => {
  assert.equal(classifyLicense("MIT", DEFAULTS.licenses).risk, "low");
});

await test("classifies Apache-2.0 as low risk", () => {
  assert.equal(classifyLicense("Apache-2.0", DEFAULTS.licenses).risk, "low");
});

await test("classifies GPL-3.0-only as high risk", () => {
  assert.equal(classifyLicense("GPL-3.0-only", DEFAULTS.licenses).risk, "high");
});

await test("classifies MPL-2.0 as medium risk", () => {
  assert.equal(classifyLicense("MPL-2.0", DEFAULTS.licenses).risk, "medium");
});

await test("classifies unknown license as unknown risk", () => {
  assert.equal(classifyLicense("Proprietary-Weird", DEFAULTS.licenses).risk, "unknown");
});

await test("classifies null/undefined license as unknown", () => {
  assert.equal(classifyLicense(null, DEFAULTS.licenses).risk, "unknown");
  assert.equal(classifyLicense(undefined, DEFAULTS.licenses).risk, "unknown");
});

const { NodeAdapter } = await import("./lib/adapters/node-adapter.js");

console.log("\n=== Node Adapter Tests ===\n");

await test("NodeAdapter.parsePackageJson extracts dependencies", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-node-"));
  try {
    await writeFile(join(dir, "package.json"), JSON.stringify({
      dependencies: { "lodash": "^4.17.20", "express": "^4.18.0" },
      devDependencies: { "jest": "^29.0.0" },
      license: "MIT",
    }));
    const adapter = new NodeAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    const deps = await adapter.parsePackageJson();
    assert.equal(deps.dependencies.length, 3);
    assert.equal(deps.projectLicense, "MIT");
    assert.ok(deps.dependencies.some((d) => d.name === "lodash"));
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("NodeAdapter.parsePackageLock extracts resolved versions", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-node-"));
  try {
    await writeFile(join(dir, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "test", version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/express": { version: "4.18.2" },
      },
    }));
    const adapter = new NodeAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    const locked = await adapter.parsePackageLock();
    assert.equal(locked.length, 2);
    assert.ok(locked.some((d) => d.name === "lodash" && d.version === "4.17.21"));
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("NodeAdapter.detectEcosystem returns false for non-node projects", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-node-"));
  try {
    const adapter = new NodeAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    assert.equal(await adapter.detectEcosystem(), false);
  } finally {
    await rm(dir, { recursive: true });
  }
});

const { GoAdapter } = await import("./lib/adapters/go-adapter.js");

console.log("\n=== Go Adapter Tests ===\n");

await test("GoAdapter.parseGoMod extracts module dependencies", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-go-"));
  try {
    await writeFile(join(dir, "go.mod"), `module example.com/myapp\n\ngo 1.21\n\nrequire (\n\tgithub.com/spf13/cobra v1.7.0\n\tgolang.org/x/net v0.17.0\n)\n\nrequire (\n\tgithub.com/inconshreveable/mousetrap v1.1.0 // indirect\n)\n`);
    const adapter = new GoAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    const deps = await adapter.parseGoMod();
    assert.equal(deps.module, "example.com/myapp");
    assert.ok(deps.dependencies.some((d) => d.name === "github.com/spf13/cobra" && d.version === "v1.7.0"));
    assert.ok(deps.dependencies.some((d) => d.name === "golang.org/x/net"));
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("GoAdapter.parseGoSum extracts package hashes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-go-"));
  try {
    await writeFile(join(dir, "go.sum"), `github.com/spf13/cobra v1.7.0 h1:abc123=\ngithub.com/spf13/cobra v1.7.0/go.mod h1:def456=\ngolang.org/x/net v0.17.0 h1:ghi789=\ngolang.org/x/net v0.17.0/go.mod h1:jkl012=\n`);
    const adapter = new GoAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    const packages = await adapter.parseGoSum();
    assert.ok(packages.some((p) => p.name === "github.com/spf13/cobra" && p.version === "v1.7.0"));
    assert.ok(packages.some((p) => p.name === "golang.org/x/net" && p.version === "v0.17.0"));
    const cobraEntries = packages.filter((p) => p.name === "github.com/spf13/cobra");
    assert.equal(cobraEntries.length, 1);
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("GoAdapter.detectEcosystem returns false for non-go projects", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-go-"));
  try {
    const adapter = new GoAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    assert.equal(await adapter.detectEcosystem(), false);
  } finally {
    await rm(dir, { recursive: true });
  }
});

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
