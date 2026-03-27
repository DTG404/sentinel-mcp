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

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
