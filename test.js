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

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
