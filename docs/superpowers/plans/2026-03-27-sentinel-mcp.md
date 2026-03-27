# sentinel-mcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a multi-project dependency auditor MCP server that scans Go, Node.js, and Python projects for vulnerabilities, outdated packages, and license risks.

**Architecture:** Hybrid scanner using native CLI tools with API-based fallback. Adapter pattern for ecosystem isolation. In-memory cache with TTL. 9 MCP tools. GitHub issue creation via `gh` CLI.

**Tech Stack:** Node.js (ES modules), @modelcontextprotocol/sdk, zod, native fetch(), child_process

---

### Task 1: Project Scaffolding

**Files:**
- Create: `package.json`
- Create: `index.js` (stub)
- Create: `lib/config.js`
- Create: `test.js` (test runner stub)

- [ ] **Step 1: Create package.json**

```json
{
  "name": "sentinel-mcp",
  "version": "1.0.0",
  "description": "MCP server for multi-project dependency auditing — vulnerabilities, outdated packages, and license risks across Go, Node.js, and Python",
  "type": "module",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "test": "node test.js"
  },
  "license": "MIT",
  "engines": {
    "node": ">=18.0.0"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.27.1",
    "zod": "^4.3.6"
  }
}
```

- [ ] **Step 2: Install dependencies**

Run: `cd /home/digitalghost/projects/sentinel-mcp && npm install`
Expected: `added X packages` with no errors

- [ ] **Step 3: Write failing test for config loading**

Create `test.js`:

```js
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
```

- [ ] **Step 4: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/config.js` does not exist

- [ ] **Step 5: Implement config.js**

Create `lib/config.js`:

```js
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export const DEFAULTS = {
  roots: [join(homedir(), "projects")],
  exclude: [
    "*/node_modules/*",
    "*/vendor/*",
    "*/.git/*",
    "*/testdata/*",
    "*/.worktrees/*",
  ],
  cache: {
    ttlMs: 3_600_000,
  },
  severity: {
    issueThreshold: "high",
  },
  licenses: {
    allowed: ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"],
    flagged: ["GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"],
  },
  github: {
    labels: ["security", "dependencies"],
    dryRun: false,
  },
  timeouts: {
    cliMs: 30_000,
    apiMs: 15_000,
  },
};

const DEFAULT_PATH = join(homedir(), ".sentinel-mcp", "config.json");

function deepMerge(defaults, overrides) {
  const result = { ...defaults };
  for (const key of Object.keys(overrides)) {
    if (
      overrides[key] &&
      typeof overrides[key] === "object" &&
      !Array.isArray(overrides[key]) &&
      defaults[key] &&
      typeof defaults[key] === "object" &&
      !Array.isArray(defaults[key])
    ) {
      result[key] = deepMerge(defaults[key], overrides[key]);
    } else {
      result[key] = overrides[key];
    }
  }
  return result;
}

export async function loadConfig(configPath = DEFAULT_PATH) {
  let userConfig = {};

  try {
    const raw = await readFile(configPath, "utf-8");
    userConfig = JSON.parse(raw);
  } catch (err) {
    if (err.code === "ENOENT") {
      try {
        await mkdir(dirname(configPath), { recursive: true });
        await writeFile(configPath, JSON.stringify(DEFAULTS, null, 2) + "\n");
      } catch {
        // best effort — config directory might not be writable
      }
    }
    // Invalid JSON or other errors: fall back to defaults silently
  }

  return deepMerge(DEFAULTS, userConfig);
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `npm test`
Expected: 5 passed, 0 failed

- [ ] **Step 7: Create index.js stub**

Create `index.js`:

```js
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./lib/config.js";

const config = await loadConfig();
const server = new McpServer({
  name: "sentinel",
  version: "1.0.0",
});

// Tools will be registered here as they are implemented

const transport = new StdioServerTransport();
await server.connect(transport);
```

- [ ] **Step 8: Commit**

```bash
git add package.json package-lock.json index.js lib/config.js test.js
git commit -m "feat: project scaffolding with config loading and defaults"
```

---

### Task 2: Cache Module

**Files:**
- Create: `lib/cache.js`
- Modify: `test.js` (add cache tests)

- [ ] **Step 1: Write failing tests for cache**

Append to `test.js` before the summary line (`console.log(\`\n${passed}...`):

```js
// --- Import cache ---
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
  const cache = new Cache(1); // 1ms TTL
  const report = { project: "/test", vulnerabilities: [] };
  cache.set("/test", report);
  // Force expiry by manipulating internal timestamp
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/cache.js` does not exist

- [ ] **Step 3: Implement cache.js**

Create `lib/cache.js`:

```js
export class Cache {
  constructor(ttlMs) {
    this._ttlMs = ttlMs;
    this._entries = new Map();
  }

  get(key) {
    const entry = this._entries.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > this._ttlMs) {
      this._entries.delete(key);
      return null;
    }
    return entry.value;
  }

  set(key, value) {
    this._entries.set(key, { value, timestamp: Date.now() });
  }

  has(key) {
    return this.get(key) !== null;
  }

  clear() {
    this._entries.clear();
  }

  keys() {
    // Return only non-expired keys
    const result = [];
    for (const key of this._entries.keys()) {
      if (this.has(key)) result.push(key);
    }
    return result;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 10 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/cache.js test.js
git commit -m "feat: add in-memory cache with TTL expiry"
```

---

### Task 3: Project Discovery

**Files:**
- Create: `lib/discovery.js`
- Modify: `test.js` (add discovery tests)

- [ ] **Step 1: Write failing tests for discovery**

Append to `test.js` before the summary line:

```js
// --- Import discovery ---
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/discovery.js` does not exist

- [ ] **Step 3: Implement discovery.js**

Create `lib/discovery.js`:

```js
import { readdir, access } from "node:fs/promises";
import { join, basename } from "node:path";

const ECOSYSTEM_MARKERS = {
  node: "package.json",
  go: "go.mod",
  python: "requirements.txt",
};

function matchesExclude(dirPath, patterns) {
  const name = basename(dirPath);
  return patterns.some((pattern) => {
    // Simple glob matching: support */name/* and */name patterns
    const clean = pattern.replace(/\*/g, "");
    const segment = clean.replace(/\//g, "");
    return name === segment;
  });
}

export async function discoverProjects(roots, exclude) {
  const projects = [];

  for (const root of roots) {
    let entries;
    try {
      entries = await readdir(root, { withFileTypes: true });
    } catch {
      continue; // skip non-existent roots
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const dirPath = join(root, entry.name);

      if (matchesExclude(dirPath, exclude)) continue;

      const ecosystems = [];
      for (const [ecosystem, marker] of Object.entries(ECOSYSTEM_MARKERS)) {
        try {
          await access(join(dirPath, marker));
          ecosystems.push(ecosystem);
        } catch {
          // marker not found — skip this ecosystem
        }
      }

      if (ecosystems.length > 0) {
        projects.push({ path: dirPath, ecosystems });
      }
    }
  }

  return projects;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 16 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/discovery.js test.js
git commit -m "feat: add project discovery with ecosystem detection and exclusion patterns"
```

---

### Task 4: OSV Client

**Files:**
- Create: `lib/osv-client.js`
- Modify: `test.js` (add OSV client tests)

- [ ] **Step 1: Write failing tests for OSV client**

Append to `test.js` before the summary line:

```js
// --- Import OSV client ---
const { OsvClient } = await import("./lib/osv-client.js");

console.log("\n=== OSV Client Tests ===\n");

await test("OsvClient constructs with timeout", () => {
  const client = new OsvClient(5000);
  assert.equal(client._timeoutMs, 5000);
});

await test("OsvClient.buildQuery creates correct payload for npm", () => {
  const client = new OsvClient(5000);
  const query = client.buildQuery("npm", "lodash", "4.17.20");
  assert.deepStrictEqual(query, {
    package: { name: "lodash", ecosystem: "npm" },
    version: "4.17.20",
  });
});

await test("OsvClient.buildQuery creates correct payload for Go", () => {
  const client = new OsvClient(5000);
  const query = client.buildQuery("Go", "golang.org/x/net", "0.17.0");
  assert.deepStrictEqual(query, {
    package: { name: "golang.org/x/net", ecosystem: "Go" },
    version: "0.17.0",
  });
});

await test("OsvClient.buildQuery creates correct payload for PyPI", () => {
  const client = new OsvClient(5000);
  const query = client.buildQuery("PyPI", "flask", "2.0.0");
  assert.deepStrictEqual(query, {
    package: { name: "flask", ecosystem: "PyPI" },
    version: "2.0.0",
  });
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
    vulns: [
      {
        id: "GHSA-xxxx-yyyy",
        summary: "Test vulnerability",
        database_specific: { severity: "HIGH" },
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        affected: [
          {
            package: { name: "lodash", ecosystem: "npm" },
            ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
          },
        ],
        references: [{ type: "ADVISORY", url: "https://example.com" }],
      },
    ],
  };
  const vulns = client.parseVulns(osvResponse, "lodash", "4.17.20");
  assert.equal(vulns.length, 1);
  assert.equal(vulns[0].id, "GHSA-xxxx-yyyy");
  assert.equal(vulns[0].package, "lodash");
  assert.equal(vulns[0].installedVersion, "4.17.20");
  assert.equal(vulns[0].fixedVersion, "4.17.21");
  assert.equal(vulns[0].summary, "Test vulnerability");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/osv-client.js` does not exist

- [ ] **Step 3: Implement osv-client.js**

Create `lib/osv-client.js`:

```js
const OSV_API = "https://api.osv.dev/v1";

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
      const lower = score.toLowerCase();
      if (lower === "critical") return "critical";
      if (lower === "high") return "high";
      if (lower === "moderate" || lower === "medium") return "medium";
      if (lower === "low") return "low";
      return "unknown";
    }
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    if (score > 0) return "low";
    return "unknown";
  }

  _extractCvssScore(severity) {
    if (!Array.isArray(severity)) return undefined;
    for (const entry of severity) {
      if (entry.type === "CVSS_V3" && entry.score) {
        // score can be a CVSS vector string or a number
        if (typeof entry.score === "number") return entry.score;
        // Try to extract base score from vector — last metric group
        // For now, rely on database_specific severity field instead
      }
    }
    return undefined;
  }

  parseVulns(osvResponse, packageName, installedVersion) {
    if (!osvResponse.vulns || osvResponse.vulns.length === 0) return [];

    return osvResponse.vulns.map((vuln) => {
      // Extract fixed version from affected ranges
      let fixedVersion = null;
      if (vuln.affected) {
        for (const affected of vuln.affected) {
          if (affected.ranges) {
            for (const range of affected.ranges) {
              if (range.events) {
                const fixEvent = range.events.find((e) => e.fixed);
                if (fixEvent) {
                  fixedVersion = fixEvent.fixed;
                  break;
                }
              }
            }
          }
          if (fixedVersion) break;
        }
      }

      // Extract severity
      const dbSeverity = vuln.database_specific?.severity;
      const cvssScore = this._extractCvssScore(vuln.severity);
      const severity = cvssScore !== undefined
        ? this.normalizeSeverity(cvssScore)
        : this.normalizeSeverity(dbSeverity);

      // Extract URL
      const advisory = vuln.references?.find((r) => r.type === "ADVISORY");
      const url = advisory?.url || `https://osv.dev/vulnerability/${vuln.id}`;

      return {
        id: vuln.id,
        severity,
        package: packageName,
        installedVersion,
        fixedVersion,
        summary: vuln.summary || vuln.details?.slice(0, 200) || "No description",
        url,
      };
    });
  }

  async queryPackage(ecosystem, packageName, version) {
    const query = this.buildQuery(ecosystem, packageName, version);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);

    try {
      const res = await fetch(`${OSV_API}/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(query),
        signal: controller.signal,
      });

      if (!res.ok) return [];

      const data = await res.json();
      return this.parseVulns(data, packageName, version);
    } catch {
      return []; // network error or timeout — degrade gracefully
    } finally {
      clearTimeout(timer);
    }
  }

  async queryBatch(ecosystem, packages) {
    const results = [];
    // OSV has a batch endpoint but it uses a different format
    // Sequential queries are simpler and good enough for project-scale dependency lists
    for (const { name, version } of packages) {
      const vulns = await this.queryPackage(ecosystem, name, version);
      results.push(...vulns);
    }
    return results;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 22 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/osv-client.js test.js
git commit -m "feat: add OSV.dev client for vulnerability lookups"
```

---

### Task 5: Version Comparison Utility

**Files:**
- Create: `lib/versions.js`
- Modify: `test.js` (add version tests)

- [ ] **Step 1: Write failing tests for version comparison**

Append to `test.js` before the summary line:

```js
// --- Import versions ---
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/versions.js` does not exist

- [ ] **Step 3: Implement versions.js**

Create `lib/versions.js`:

```js
function parse(version) {
  const clean = version.replace(/^v/, "");
  const parts = clean.split(".");
  if (parts.length < 3) return null;
  const [major, minor, patch] = parts.map((p) => parseInt(p, 10));
  if (isNaN(major) || isNaN(minor) || isNaN(patch)) return null;
  return { major, minor, patch };
}

export function compareSemver(current, latest) {
  const c = parse(current);
  const l = parse(latest);
  if (!c || !l) return null;

  return {
    major: l.major - c.major,
    minor: l.minor - c.minor,
    patch: l.patch - c.patch,
  };
}

export function classifyStaleness(behindBy) {
  if (!behindBy) return "unknown";
  if (behindBy.major > 0) return "major";
  if (behindBy.minor > 0) return "minor";
  if (behindBy.patch > 0) return "patch";
  return "current";
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 31 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/versions.js test.js
git commit -m "feat: add semver comparison and staleness classification"
```

---

### Task 6: License Classification

**Files:**
- Create: `lib/licenses.js`
- Modify: `test.js` (add license tests)

- [ ] **Step 1: Write failing tests for license classification**

Append to `test.js` before the summary line:

```js
// --- Import licenses ---
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/licenses.js` does not exist

- [ ] **Step 3: Implement licenses.js**

Create `lib/licenses.js`:

```js
const LOW_RISK = new Set([
  "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
  "Unlicense", "0BSD", "CC0-1.0",
]);

const MEDIUM_RISK = new Set([
  "MPL-2.0", "LGPL-2.1-only", "LGPL-3.0-only", "LGPL-2.1-or-later", "LGPL-3.0-or-later",
]);

const HIGH_RISK = new Set([
  "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
  "GPL-2.0-or-later", "GPL-3.0-or-later", "AGPL-3.0-or-later",
]);

export function classifyLicense(license, licenseConfig) {
  if (!license) return { license: null, risk: "unknown" };

  // Check user-configured lists first
  if (licenseConfig?.flagged?.includes(license)) {
    return { license, risk: "high" };
  }
  if (licenseConfig?.allowed?.includes(license)) {
    return { license, risk: "low" };
  }

  // Fall back to built-in classification
  if (LOW_RISK.has(license)) return { license, risk: "low" };
  if (MEDIUM_RISK.has(license)) return { license, risk: "medium" };
  if (HIGH_RISK.has(license)) return { license, risk: "high" };

  return { license, risk: "unknown" };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 37 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/licenses.js test.js
git commit -m "feat: add license risk classification"
```

---

### Task 7: Node.js Adapter

**Files:**
- Create: `lib/adapters/node-adapter.js`
- Modify: `test.js` (add Node adapter tests)

- [ ] **Step 1: Write failing tests for Node adapter**

Append to `test.js` before the summary line:

```js
// --- Import Node adapter ---
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
        "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" },
        "node_modules/express": { version: "4.18.2", resolved: "https://registry.npmjs.org/express/-/express-4.18.2.tgz" },
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/adapters/node-adapter.js` does not exist

- [ ] **Step 3: Create adapters directory and implement node-adapter.js**

```bash
mkdir -p lib/adapters
```

Create `lib/adapters/node-adapter.js`:

```js
import { readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { compareSemver, classifyStaleness } from "../versions.js";
import { classifyLicense } from "../licenses.js";

const execFileAsync = promisify(execFile);

export class NodeAdapter {
  constructor(projectPath, timeouts) {
    this._path = projectPath;
    this._timeouts = timeouts;
  }

  async detectEcosystem() {
    try {
      await access(join(this._path, "package.json"));
      return true;
    } catch {
      return false;
    }
  }

  async parsePackageJson() {
    const raw = await readFile(join(this._path, "package.json"), "utf-8");
    const pkg = JSON.parse(raw);
    const deps = [];

    for (const [name, range] of Object.entries(pkg.dependencies || {})) {
      deps.push({ name, range, dev: false });
    }
    for (const [name, range] of Object.entries(pkg.devDependencies || {})) {
      deps.push({ name, range, dev: true });
    }

    return { dependencies: deps, projectLicense: pkg.license || null };
  }

  async parsePackageLock() {
    try {
      const raw = await readFile(join(this._path, "package-lock.json"), "utf-8");
      const lock = JSON.parse(raw);
      const packages = [];

      // lockfileVersion 2/3 uses "packages" with node_modules/ prefix
      if (lock.packages) {
        for (const [key, info] of Object.entries(lock.packages)) {
          if (!key || key === "") continue; // skip root
          const name = key.replace(/^node_modules\//, "");
          if (info.version) {
            packages.push({ name, version: info.version });
          }
        }
      }

      return packages;
    } catch {
      return null; // no lockfile
    }
  }

  async _tryNativeAudit() {
    try {
      const { stdout } = await execFileAsync("npm", ["audit", "--json"], {
        cwd: this._path,
        timeout: this._timeouts.cliMs,
      });
      const data = JSON.parse(stdout);
      const vulns = [];

      // npm audit JSON format: advisories or vulnerabilities depending on version
      const advisories = data.advisories || {};
      for (const advisory of Object.values(advisories)) {
        vulns.push({
          id: advisory.cves?.[0] || advisory.github_advisory_id || `npm-${advisory.id}`,
          severity: advisory.severity || "unknown",
          package: advisory.module_name,
          installedVersion: advisory.findings?.[0]?.version || "unknown",
          fixedVersion: advisory.patched_versions || null,
          summary: advisory.title || advisory.overview?.slice(0, 200) || "No description",
          url: advisory.url || `https://www.npmjs.com/advisories/${advisory.id}`,
        });
      }

      // npm v7+ format with "vulnerabilities" key
      if (data.vulnerabilities) {
        for (const [name, info] of Object.entries(data.vulnerabilities)) {
          for (const via of (info.via || [])) {
            if (typeof via === "object") {
              vulns.push({
                id: via.cve?.[0] || via.url?.split("/").pop() || `npm-${name}`,
                severity: via.severity || info.severity || "unknown",
                package: name,
                installedVersion: info.range || "unknown",
                fixedVersion: info.fixAvailable?.version || null,
                summary: via.title || "No description",
                url: via.url || `https://www.npmjs.com/advisories`,
              });
            }
          }
        }
      }

      return { success: true, vulns };
    } catch {
      return { success: false, vulns: [] };
    }
  }

  async _tryNativeOutdated() {
    try {
      // npm outdated returns exit code 1 when there are outdated packages
      const { stdout } = await execFileAsync("npm", ["outdated", "--json"], {
        cwd: this._path,
        timeout: this._timeouts.cliMs,
      }).catch((err) => {
        if (err.stdout) return { stdout: err.stdout };
        throw err;
      });
      const data = JSON.parse(stdout);
      const outdated = [];

      for (const [name, info] of Object.entries(data)) {
        const behindBy = compareSemver(info.current, info.latest);
        if (behindBy && (behindBy.major > 0 || behindBy.minor > 0 || behindBy.patch > 0)) {
          outdated.push({
            package: name,
            current: info.current,
            latest: info.latest,
            staleness: classifyStaleness(behindBy),
            behindBy,
          });
        }
      }

      return { success: true, outdated };
    } catch {
      return { success: false, outdated: [] };
    }
  }

  async _fetchRegistryLicense(packageName) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this._timeouts.apiMs);
      const res = await fetch(`https://registry.npmjs.org/${packageName}/latest`, {
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) return null;
      const data = await res.json();
      return data.license || null;
    } catch {
      return null;
    }
  }

  async _fetchRegistryVersion(packageName) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this._timeouts.apiMs);
      const res = await fetch(`https://registry.npmjs.org/${packageName}/latest`, {
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) return null;
      const data = await res.json();
      return data.version || null;
    } catch {
      return null;
    }
  }

  async scanVulns(osvClient) {
    // Try native first
    const native = await this._tryNativeAudit();
    if (native.success) return { mode: "native", vulns: native.vulns };

    // Fallback: parse lockfile and query OSV
    const locked = await this.parsePackageLock();
    if (!locked) return { mode: "fallback", vulns: [] }; // no lockfile, can't scan

    const vulns = await osvClient.queryBatch(
      "npm",
      locked.map((d) => ({ name: d.name, version: d.version }))
    );
    return { mode: "fallback", vulns };
  }

  async checkOutdated(licenseConfig) {
    // Try native first
    const native = await this._tryNativeOutdated();
    if (native.success) return { mode: "native", outdated: native.outdated };

    // Fallback: parse package.json, query registry
    const { dependencies } = await this.parsePackageJson();
    const outdated = [];

    for (const dep of dependencies) {
      const cleanVersion = dep.range.replace(/^[\^~>=<]+/, "");
      const latest = await this._fetchRegistryVersion(dep.name);
      if (!latest) continue;

      const behindBy = compareSemver(cleanVersion, latest);
      if (behindBy && (behindBy.major > 0 || behindBy.minor > 0 || behindBy.patch > 0)) {
        outdated.push({
          package: dep.name,
          current: cleanVersion,
          latest,
          staleness: classifyStaleness(behindBy),
          behindBy,
        });
      }
    }

    return { mode: "fallback", outdated };
  }

  async detectLicenses(licenseConfig) {
    const { dependencies } = await this.parsePackageJson();
    const licenses = [];

    for (const dep of dependencies) {
      const regLicense = await this._fetchRegistryLicense(dep.name);
      const classified = classifyLicense(regLicense, licenseConfig);
      licenses.push({
        package: dep.name,
        license: classified.license,
        risk: classified.risk,
      });
    }

    return licenses;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 40 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/adapters/node-adapter.js test.js
git commit -m "feat: add Node.js adapter with npm audit native + OSV fallback"
```

---

### Task 8: Go Adapter

**Files:**
- Create: `lib/adapters/go-adapter.js`
- Modify: `test.js` (add Go adapter tests)

- [ ] **Step 1: Write failing tests for Go adapter**

Append to `test.js` before the summary line:

```js
// --- Import Go adapter ---
const { GoAdapter } = await import("./lib/adapters/go-adapter.js");

console.log("\n=== Go Adapter Tests ===\n");

await test("GoAdapter.parseGoMod extracts module dependencies", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-go-"));
  try {
    await writeFile(join(dir, "go.mod"), `module example.com/myapp

go 1.21

require (
\tgithub.com/spf13/cobra v1.7.0
\tgolang.org/x/net v0.17.0
)

require (
\tgithub.com/inconshreveable/mousetrap v1.1.0 // indirect
)
`);
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
    await writeFile(join(dir, "go.sum"), `github.com/spf13/cobra v1.7.0 h1:abc123=
github.com/spf13/cobra v1.7.0/go.mod h1:def456=
golang.org/x/net v0.17.0 h1:ghi789=
golang.org/x/net v0.17.0/go.mod h1:jkl012=
`);
    const adapter = new GoAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    const packages = await adapter.parseGoSum();
    assert.ok(packages.some((p) => p.name === "github.com/spf13/cobra" && p.version === "v1.7.0"));
    assert.ok(packages.some((p) => p.name === "golang.org/x/net" && p.version === "v0.17.0"));
    // Should deduplicate (each module appears twice in go.sum)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/adapters/go-adapter.js` does not exist

- [ ] **Step 3: Implement go-adapter.js**

Create `lib/adapters/go-adapter.js`:

```js
import { readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { compareSemver, classifyStaleness } from "../versions.js";
import { classifyLicense } from "../licenses.js";

const execFileAsync = promisify(execFile);

export class GoAdapter {
  constructor(projectPath, timeouts) {
    this._path = projectPath;
    this._timeouts = timeouts;
  }

  async detectEcosystem() {
    try {
      await access(join(this._path, "go.mod"));
      return true;
    } catch {
      return false;
    }
  }

  async parseGoMod() {
    const raw = await readFile(join(this._path, "go.mod"), "utf-8");
    const lines = raw.split("\n");
    const dependencies = [];
    let module = "";
    let inRequire = false;

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed.startsWith("module ")) {
        module = trimmed.replace("module ", "").trim();
        continue;
      }

      if (trimmed === "require (") {
        inRequire = true;
        continue;
      }

      if (trimmed === ")") {
        inRequire = false;
        continue;
      }

      if (inRequire && trimmed) {
        const parts = trimmed.split(/\s+/);
        if (parts.length >= 2) {
          const indirect = trimmed.includes("// indirect");
          dependencies.push({
            name: parts[0],
            version: parts[1],
            indirect,
          });
        }
      }
    }

    return { module, dependencies };
  }

  async parseGoSum() {
    try {
      const raw = await readFile(join(this._path, "go.sum"), "utf-8");
      const seen = new Set();
      const packages = [];

      for (const line of raw.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        const parts = trimmed.split(/\s+/);
        if (parts.length < 3) continue;

        let name = parts[0];
        let version = parts[1].replace("/go.mod", "");

        const key = `${name}@${version}`;
        if (seen.has(key)) continue;
        seen.add(key);

        packages.push({ name, version });
      }

      return packages;
    } catch {
      return null;
    }
  }

  async _tryNativeVulncheck() {
    try {
      const { stdout } = await execFileAsync("govulncheck", ["-json", "./..."], {
        cwd: this._path,
        timeout: this._timeouts.cliMs,
      });
      const vulns = [];

      // govulncheck JSON output is newline-delimited JSON objects
      for (const line of stdout.split("\n")) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line);
          if (entry.osv) {
            const osv = entry.osv;
            let fixedVersion = null;
            if (osv.affected) {
              for (const aff of osv.affected) {
                for (const range of (aff.ranges || [])) {
                  const fix = range.events?.find((e) => e.fixed);
                  if (fix) { fixedVersion = fix.fixed; break; }
                }
                if (fixedVersion) break;
              }
            }

            vulns.push({
              id: osv.id,
              severity: osv.database_specific?.severity?.toLowerCase() || "unknown",
              package: osv.affected?.[0]?.package?.name || "unknown",
              installedVersion: "see go.mod",
              fixedVersion,
              summary: osv.summary || osv.details?.slice(0, 200) || "No description",
              url: `https://pkg.go.dev/vuln/${osv.id}`,
            });
          }
        } catch {
          // skip non-JSON lines
        }
      }

      return { success: true, vulns };
    } catch {
      return { success: false, vulns: [] };
    }
  }

  async _tryNativeOutdated() {
    try {
      const { stdout } = await execFileAsync("go", ["list", "-m", "-u", "-json", "all"], {
        cwd: this._path,
        timeout: this._timeouts.cliMs,
      });
      const outdated = [];

      // Output is concatenated JSON objects (not an array)
      const objects = stdout.split("\n}\n").filter(Boolean);
      for (let chunk of objects) {
        chunk = chunk.trim();
        if (!chunk.endsWith("}")) chunk += "}";
        try {
          const mod = JSON.parse(chunk);
          if (mod.Update && mod.Version) {
            const current = mod.Version.replace(/^v/, "");
            const latest = mod.Update.Version.replace(/^v/, "");
            const behindBy = compareSemver(current, latest);
            if (behindBy && (behindBy.major > 0 || behindBy.minor > 0 || behindBy.patch > 0)) {
              outdated.push({
                package: mod.Path,
                current: mod.Version,
                latest: mod.Update.Version,
                staleness: classifyStaleness(behindBy),
                behindBy,
              });
            }
          }
        } catch {
          // skip parse errors
        }
      }

      return { success: true, outdated };
    } catch {
      return { success: false, outdated: [] };
    }
  }

  async _fetchGoProxyVersion(modulePath) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this._timeouts.apiMs);
      const res = await fetch(`https://proxy.golang.org/${modulePath}/@latest`, {
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) return null;
      const data = await res.json();
      return data.Version || null;
    } catch {
      return null;
    }
  }

  async _fetchGoProxyLicense(modulePath) {
    // Go modules don't have a standard license API
    // Best effort: check pkg.go.dev or return unknown
    return null;
  }

  async scanVulns(osvClient) {
    const native = await this._tryNativeVulncheck();
    if (native.success) return { mode: "native", vulns: native.vulns };

    // Fallback: parse go.sum and query OSV
    const packages = await this.parseGoSum();
    if (!packages) return { mode: "fallback", vulns: [] };

    const vulns = await osvClient.queryBatch(
      "Go",
      packages.map((p) => ({ name: p.name, version: p.version.replace(/^v/, "") }))
    );
    return { mode: "fallback", vulns };
  }

  async checkOutdated(licenseConfig) {
    const native = await this._tryNativeOutdated();
    if (native.success) return { mode: "native", outdated: native.outdated };

    // Fallback: parse go.mod, query proxy for latest versions
    const { dependencies } = await this.parseGoMod();
    const outdated = [];

    for (const dep of dependencies) {
      if (dep.indirect) continue; // skip indirect deps for fallback
      const latest = await this._fetchGoProxyVersion(dep.name);
      if (!latest) continue;

      const current = dep.version.replace(/^v/, "");
      const latestClean = latest.replace(/^v/, "");
      const behindBy = compareSemver(current, latestClean);
      if (behindBy && (behindBy.major > 0 || behindBy.minor > 0 || behindBy.patch > 0)) {
        outdated.push({
          package: dep.name,
          current: dep.version,
          latest,
          staleness: classifyStaleness(behindBy),
          behindBy,
        });
      }
    }

    return { mode: "fallback", outdated };
  }

  async detectLicenses(licenseConfig) {
    const { dependencies } = await this.parseGoMod();
    const licenses = [];

    for (const dep of dependencies) {
      // Go doesn't have a standard license API — mark as unknown
      // Native go-licenses tool could be used but is rarely installed
      const license = await this._fetchGoProxyLicense(dep.name);
      const classified = classifyLicense(license, licenseConfig);
      licenses.push({
        package: dep.name,
        license: classified.license,
        risk: classified.risk,
      });
    }

    return licenses;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 43 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/adapters/go-adapter.js test.js
git commit -m "feat: add Go adapter with govulncheck native + OSV fallback"
```

---

### Task 9: Python Adapter

**Files:**
- Create: `lib/adapters/python-adapter.js`
- Modify: `test.js` (add Python adapter tests)

- [ ] **Step 1: Write failing tests for Python adapter**

Append to `test.js` before the summary line:

```js
// --- Import Python adapter ---
const { PythonAdapter } = await import("./lib/adapters/python-adapter.js");

console.log("\n=== Python Adapter Tests ===\n");

await test("PythonAdapter.parseRequirementsTxt extracts pinned versions", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-py-"));
  try {
    await writeFile(join(dir, "requirements.txt"), `flask==2.3.0
requests==2.31.0
# this is a comment
numpy>=1.24.0
-e git+https://github.com/foo/bar.git#egg=bar
`);
    const adapter = new PythonAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    const deps = await adapter.parseRequirementsTxt();
    assert.ok(deps.some((d) => d.name === "flask" && d.version === "2.3.0"));
    assert.ok(deps.some((d) => d.name === "requests" && d.version === "2.31.0"));
    assert.ok(deps.some((d) => d.name === "numpy" && d.version === "1.24.0"));
    // Editable installs and comments should be skipped
    assert.ok(!deps.some((d) => d.name === "bar"));
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("PythonAdapter.detectEcosystem returns false for non-python projects", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-py-"));
  try {
    const adapter = new PythonAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    assert.equal(await adapter.detectEcosystem(), false);
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("PythonAdapter.parseRequirementsTxt handles empty file", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-py-"));
  try {
    await writeFile(join(dir, "requirements.txt"), "");
    const adapter = new PythonAdapter(dir, { cliMs: 5000, apiMs: 5000 });
    const deps = await adapter.parseRequirementsTxt();
    assert.equal(deps.length, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/adapters/python-adapter.js` does not exist

- [ ] **Step 3: Implement python-adapter.js**

Create `lib/adapters/python-adapter.js`:

```js
import { readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { compareSemver, classifyStaleness } from "../versions.js";
import { classifyLicense } from "../licenses.js";

const execFileAsync = promisify(execFile);

export class PythonAdapter {
  constructor(projectPath, timeouts) {
    this._path = projectPath;
    this._timeouts = timeouts;
  }

  async detectEcosystem() {
    try {
      await access(join(this._path, "requirements.txt"));
      return true;
    } catch {
      return false;
    }
  }

  async parseRequirementsTxt() {
    const raw = await readFile(join(this._path, "requirements.txt"), "utf-8");
    const deps = [];

    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;

      // Handle ==, >=, ~=, <=, != operators
      const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*([><=!~]+)\s*([0-9][^\s;,#]*)/);
      if (match) {
        deps.push({ name: match[1].toLowerCase(), version: match[3], operator: match[2] });
      }
    }

    return deps;
  }

  async _tryNativeAudit() {
    try {
      const { stdout } = await execFileAsync("pip-audit", ["--format=json", "-r", join(this._path, "requirements.txt")], {
        timeout: this._timeouts.cliMs,
      });
      const data = JSON.parse(stdout);
      const vulns = [];

      for (const entry of (data.dependencies || [])) {
        for (const vuln of (entry.vulns || [])) {
          vulns.push({
            id: vuln.id,
            severity: vuln.fix_versions?.length ? "medium" : "unknown",
            package: entry.name,
            installedVersion: entry.version,
            fixedVersion: vuln.fix_versions?.[0] || null,
            summary: vuln.description || `Vulnerability ${vuln.id}`,
            url: `https://osv.dev/vulnerability/${vuln.id}`,
          });
        }
      }

      return { success: true, vulns };
    } catch {
      return { success: false, vulns: [] };
    }
  }

  async _tryNativeOutdated() {
    try {
      const { stdout } = await execFileAsync("pip", ["list", "--outdated", "--format=json"], {
        timeout: this._timeouts.cliMs,
      });
      const data = JSON.parse(stdout);
      const outdated = [];

      for (const pkg of data) {
        const behindBy = compareSemver(pkg.version, pkg.latest_version);
        if (behindBy && (behindBy.major > 0 || behindBy.minor > 0 || behindBy.patch > 0)) {
          outdated.push({
            package: pkg.name,
            current: pkg.version,
            latest: pkg.latest_version,
            staleness: classifyStaleness(behindBy),
            behindBy,
          });
        }
      }

      return { success: true, outdated };
    } catch {
      return { success: false, outdated: [] };
    }
  }

  async _fetchPypiInfo(packageName) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this._timeouts.apiMs);
      const res = await fetch(`https://pypi.org/pypi/${packageName}/json`, {
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  async scanVulns(osvClient) {
    const native = await this._tryNativeAudit();
    if (native.success) return { mode: "native", vulns: native.vulns };

    // Fallback: parse requirements.txt, query OSV
    const deps = await this.parseRequirementsTxt();
    const vulns = await osvClient.queryBatch(
      "PyPI",
      deps.map((d) => ({ name: d.name, version: d.version }))
    );
    return { mode: "fallback", vulns };
  }

  async checkOutdated(licenseConfig) {
    const native = await this._tryNativeOutdated();
    if (native.success) return { mode: "native", outdated: native.outdated };

    // Fallback: parse requirements.txt, query PyPI
    const deps = await this.parseRequirementsTxt();
    const outdated = [];

    for (const dep of deps) {
      const info = await this._fetchPypiInfo(dep.name);
      if (!info?.info?.version) continue;

      const latest = info.info.version;
      const behindBy = compareSemver(dep.version, latest);
      if (behindBy && (behindBy.major > 0 || behindBy.minor > 0 || behindBy.patch > 0)) {
        outdated.push({
          package: dep.name,
          current: dep.version,
          latest,
          staleness: classifyStaleness(behindBy),
          behindBy,
        });
      }
    }

    return { mode: "fallback", outdated };
  }

  async detectLicenses(licenseConfig) {
    const deps = await this.parseRequirementsTxt();
    const licenses = [];

    for (const dep of deps) {
      const info = await this._fetchPypiInfo(dep.name);
      const license = info?.info?.license || null;
      const classified = classifyLicense(license, licenseConfig);
      licenses.push({
        package: dep.name,
        license: classified.license,
        risk: classified.risk,
      });
    }

    return licenses;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 46 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/adapters/python-adapter.js test.js
git commit -m "feat: add Python adapter with pip-audit native + OSV fallback"
```

---

### Task 10: Scanner Orchestrator

**Files:**
- Create: `lib/scanner.js`
- Modify: `test.js` (add scanner tests)

- [ ] **Step 1: Write failing tests for scanner**

Append to `test.js` before the summary line:

```js
// --- Import scanner ---
const { Scanner } = await import("./lib/scanner.js");

console.log("\n=== Scanner Tests ===\n");

await test("Scanner.scanProject returns report with correct structure", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-scan-"));
  try {
    await writeFile(join(dir, "package.json"), JSON.stringify({
      dependencies: {},
      license: "MIT",
    }));
    const scanner = new Scanner(DEFAULTS);
    const report = await scanner.scanProject(dir);
    assert.equal(report.project, dir);
    assert.ok(Array.isArray(report.ecosystems));
    assert.ok(report.ecosystems.includes("node"));
    assert.ok(Array.isArray(report.vulnerabilities));
    assert.ok(Array.isArray(report.outdated));
    assert.ok(Array.isArray(report.licenses));
    assert.ok(Array.isArray(report.errors));
    assert.ok(report.scannedAt);
    assert.ok(report.toolMode);
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test("Scanner.scanProject handles unknown ecosystems gracefully", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-scan-"));
  try {
    // Empty dir — no ecosystem markers
    const scanner = new Scanner(DEFAULTS);
    const report = await scanner.scanProject(dir);
    assert.equal(report.ecosystems.length, 0);
    assert.equal(report.vulnerabilities.length, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/scanner.js` does not exist

- [ ] **Step 3: Implement scanner.js**

Create `lib/scanner.js`:

```js
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
      project: projectPath,
      ecosystems: [],
      scannedAt: new Date().toISOString(),
      toolMode: {},
      osvStatus: "ok",
      vulnerabilities: [],
      outdated: [],
      licenses: [],
      errors: [],
    };

    const adapters = [
      { name: "node", adapter: new NodeAdapter(projectPath, this._config.timeouts) },
      { name: "go", adapter: new GoAdapter(projectPath, this._config.timeouts) },
      { name: "python", adapter: new PythonAdapter(projectPath, this._config.timeouts) },
    ];

    for (const { name, adapter } of adapters) {
      let detected;
      try {
        detected = await adapter.detectEcosystem();
      } catch (err) {
        report.errors.push(`${name}: detection failed: ${err.message}`);
        continue;
      }

      if (!detected) continue;
      report.ecosystems.push(name);

      // Vulnerabilities
      try {
        const vulnResult = await adapter.scanVulns(this._osv);
        report.toolMode[name] = vulnResult.mode;
        report.vulnerabilities.push(...vulnResult.vulns);
      } catch (err) {
        report.errors.push(`${name}: vuln scan failed: ${err.message}`);
      }

      // Outdated
      try {
        const outdatedResult = await adapter.checkOutdated(this._config.licenses);
        report.outdated.push(...outdatedResult.outdated);
      } catch (err) {
        report.errors.push(`${name}: outdated check failed: ${err.message}`);
      }

      // Licenses
      try {
        const licenseResult = await adapter.detectLicenses(this._config.licenses);
        report.licenses.push(...licenseResult);
      } catch (err) {
        report.errors.push(`${name}: license detection failed: ${err.message}`);
      }
    }

    return report;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 48 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/scanner.js test.js
git commit -m "feat: add scanner orchestrator combining all ecosystem adapters"
```

---

### Task 11: GitHub Issue Creation

**Files:**
- Create: `lib/github-issues.js`
- Modify: `test.js` (add GitHub issues tests)

- [ ] **Step 1: Write failing tests for GitHub issue creation**

Append to `test.js` before the summary line:

```js
// --- Import GitHub issues ---
const { formatIssue, filterByThreshold } = await import("./lib/github-issues.js");

console.log("\n=== GitHub Issues Tests ===\n");

await test("formatIssue creates correct title and body", () => {
  const vuln = {
    id: "CVE-2024-1234",
    severity: "high",
    package: "lodash",
    installedVersion: "4.17.20",
    fixedVersion: "4.17.21",
    summary: "Prototype pollution in lodash",
    url: "https://osv.dev/vulnerability/CVE-2024-1234",
  };
  const issue = formatIssue(vuln, "node");
  assert.ok(issue.title.includes("[HIGH]"));
  assert.ok(issue.title.includes("CVE-2024-1234"));
  assert.ok(issue.title.includes("lodash"));
  assert.ok(issue.body.includes("4.17.20"));
  assert.ok(issue.body.includes("4.17.21"));
  assert.ok(issue.body.includes("sentinel-mcp"));
});

await test("filterByThreshold filters correctly at high threshold", () => {
  const vulns = [
    { id: "a", severity: "critical" },
    { id: "b", severity: "high" },
    { id: "c", severity: "medium" },
    { id: "d", severity: "low" },
  ];
  const filtered = filterByThreshold(vulns, "high");
  assert.equal(filtered.length, 2);
  assert.ok(filtered.some((v) => v.id === "a"));
  assert.ok(filtered.some((v) => v.id === "b"));
});

await test("filterByThreshold filters correctly at medium threshold", () => {
  const vulns = [
    { id: "a", severity: "critical" },
    { id: "b", severity: "high" },
    { id: "c", severity: "medium" },
    { id: "d", severity: "low" },
  ];
  const filtered = filterByThreshold(vulns, "medium");
  assert.equal(filtered.length, 3);
});

await test("filterByThreshold returns all for low threshold", () => {
  const vulns = [
    { id: "a", severity: "critical" },
    { id: "b", severity: "low" },
  ];
  const filtered = filterByThreshold(vulns, "low");
  assert.equal(filtered.length, 2);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/github-issues.js` does not exist

- [ ] **Step 3: Implement github-issues.js**

Create `lib/github-issues.js`:

```js
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

export function filterByThreshold(vulns, threshold) {
  const minLevel = SEVERITY_ORDER[threshold] || 0;
  return vulns.filter((v) => (SEVERITY_ORDER[v.severity] || 0) >= minLevel);
}

export function formatIssue(vuln, ecosystem) {
  const title = `[${vuln.severity.toUpperCase()}] ${vuln.id} in ${vuln.package} (${ecosystem})`;
  const body = `**Vulnerability:** ${vuln.summary}
**Package:** ${vuln.package}@${vuln.installedVersion}
**Fixed in:** ${vuln.fixedVersion || "No fix available"}
**Severity:** ${vuln.severity}
**Details:** ${vuln.url}

Found by sentinel-mcp dependency audit.`;

  return { title, body };
}

async function checkGhAuth() {
  try {
    await execFileAsync("gh", ["auth", "status"]);
    return true;
  } catch {
    return false;
  }
}

async function listExistingIssues(projectPath) {
  try {
    const { stdout } = await execFileAsync("gh", [
      "issue", "list", "--json", "title", "--limit", "200",
    ], { cwd: projectPath });
    const issues = JSON.parse(stdout);
    return new Set(issues.map((i) => i.title));
  } catch {
    return new Set();
  }
}

export async function createGithubIssues(report, config) {
  const authed = await checkGhAuth();
  if (!authed) {
    return { created: [], errors: ["GitHub CLI not authenticated. Run: gh auth login"] };
  }

  const threshold = config.severity?.issueThreshold || "high";
  const labels = config.github?.labels || ["security", "dependencies"];
  const dryRun = config.github?.dryRun || false;

  // Determine ecosystem for each vuln
  const vulnsWithEcosystem = report.vulnerabilities.map((v) => {
    const eco = report.ecosystems.find((e) => {
      if (e === "node" && v.url?.includes("npm")) return true;
      if (e === "go" && (v.id?.startsWith("GO-") || v.url?.includes("pkg.go.dev"))) return true;
      if (e === "python" && v.url?.includes("pypi")) return true;
      return false;
    }) || report.ecosystems[0] || "unknown";
    return { ...v, ecosystem: eco };
  });

  const eligible = filterByThreshold(vulnsWithEcosystem, threshold);

  if (dryRun) {
    return {
      created: eligible.map((v) => formatIssue(v, v.ecosystem)),
      errors: [],
      dryRun: true,
    };
  }

  const existing = await listExistingIssues(report.project);
  const created = [];
  const errors = [];

  for (const vuln of eligible) {
    const issue = formatIssue(vuln, vuln.ecosystem);

    // Deduplication: skip if issue title already exists
    if (existing.has(issue.title)) continue;

    try {
      await execFileAsync("gh", [
        "issue", "create",
        "--title", issue.title,
        "--body", issue.body,
        ...labels.flatMap((l) => ["--label", l]),
      ], { cwd: report.project });
      created.push(issue);
    } catch (err) {
      errors.push(`Failed to create issue for ${vuln.id}: ${err.message}`);
    }
  }

  return { created, errors };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 52 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/github-issues.js test.js
git commit -m "feat: add GitHub issue creation with deduplication and dry-run support"
```

---

### Task 12: Tool Check Status

**Files:**
- Create: `lib/tool-check.js`
- Modify: `test.js` (add tool check tests)

- [ ] **Step 1: Write failing tests for tool check**

Append to `test.js` before the summary line:

```js
// --- Import tool check ---
const { checkToolAvailability } = await import("./lib/tool-check.js");

console.log("\n=== Tool Check Tests ===\n");

await test("checkToolAvailability returns object with all ecosystems", async () => {
  const status = await checkToolAvailability();
  assert.ok("node" in status);
  assert.ok("go" in status);
  assert.ok("python" in status);
  assert.ok("gh" in status);
});

await test("checkToolAvailability reports available/unavailable correctly", async () => {
  const status = await checkToolAvailability();
  // npm should be available since we're running in a Node environment
  assert.equal(status.node.npm.available, true);
  // Each entry has available (boolean) and version or error
  assert.equal(typeof status.node.npm.available, "boolean");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `lib/tool-check.js` does not exist

- [ ] **Step 3: Implement tool-check.js**

Create `lib/tool-check.js`:

```js
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

async function checkTool(command, args) {
  try {
    const { stdout } = await execFileAsync(command, args, { timeout: 5000 });
    return { available: true, version: stdout.trim().split("\n")[0] };
  } catch {
    return { available: false, version: null };
  }
}

export async function checkToolAvailability() {
  const [npm, govulncheck, goCmd, pipAudit, pip, gh] = await Promise.all([
    checkTool("npm", ["--version"]),
    checkTool("govulncheck", ["-version"]),
    checkTool("go", ["version"]),
    checkTool("pip-audit", ["--version"]),
    checkTool("pip", ["--version"]),
    checkTool("gh", ["--version"]),
  ]);

  return {
    node: {
      npm: npm,
      mode: npm.available ? "native" : "fallback",
    },
    go: {
      go: goCmd,
      govulncheck: govulncheck,
      mode: govulncheck.available ? "native" : "fallback",
    },
    python: {
      pip: pip,
      "pip-audit": pipAudit,
      mode: pipAudit.available ? "native" : "fallback",
    },
    gh: gh,
  };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: 54 passed, 0 failed

- [ ] **Step 5: Commit**

```bash
git add lib/tool-check.js test.js
git commit -m "feat: add native tool availability checker"
```

---

### Task 13: Wire Up MCP Server with All 9 Tools

**Files:**
- Modify: `index.js` (register all tools)

- [ ] **Step 1: Implement complete index.js with all 9 tools**

Replace `index.js` with:

```js
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { loadConfig } from "./lib/config.js";
import { Cache } from "./lib/cache.js";
import { discoverProjects } from "./lib/discovery.js";
import { Scanner } from "./lib/scanner.js";
import { checkToolAvailability } from "./lib/tool-check.js";
import { createGithubIssues, filterByThreshold } from "./lib/github-issues.js";

const config = await loadConfig();
const cache = new Cache(config.cache.ttlMs);
const scanner = new Scanner(config);

const server = new McpServer({
  name: "sentinel",
  version: "1.0.0",
});

// --- scan_project ---
server.tool(
  "scan_project",
  "Scan a single project for vulnerabilities, outdated deps, and license issues",
  { path: z.string().describe("Absolute path to the project directory") },
  async ({ path }) => {
    const cached = cache.get(path);
    if (cached) return { content: [{ type: "text", text: JSON.stringify(cached, null, 2) }] };

    const report = await scanner.scanProject(path);
    cache.set(path, report);
    return { content: [{ type: "text", text: JSON.stringify(report, null, 2) }] };
  }
);

// --- scan_all ---
server.tool(
  "scan_all",
  "Discover and scan all projects under configured roots",
  { force: z.boolean().optional().default(false).describe("Force re-scan ignoring cache") },
  async ({ force }) => {
    const projects = await discoverProjects(config.roots, config.exclude);
    const reports = [];

    for (const proj of projects) {
      if (!force) {
        const cached = cache.get(proj.path);
        if (cached) { reports.push(cached); continue; }
      }
      const report = await scanner.scanProject(proj.path);
      cache.set(proj.path, report);
      reports.push(report);
    }

    return { content: [{ type: "text", text: JSON.stringify(reports, null, 2) }] };
  }
);

// --- get_summary ---
server.tool(
  "get_summary",
  "Cross-project summary of vulnerabilities, outdated deps, and license issues",
  {},
  async () => {
    const keys = cache.keys();
    const reports = keys.map((k) => cache.get(k)).filter(Boolean);

    const totalVulns = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    let totalOutdated = 0;
    const licenseRisks = { low: 0, medium: 0, high: 0, unknown: 0 };

    for (const r of reports) {
      for (const v of r.vulnerabilities) totalVulns[v.severity] = (totalVulns[v.severity] || 0) + 1;
      totalOutdated += r.outdated.length;
      for (const l of r.licenses) licenseRisks[l.risk] = (licenseRisks[l.risk] || 0) + 1;
    }

    const summary = {
      projectsScanned: reports.length,
      vulnerabilities: totalVulns,
      outdatedPackages: totalOutdated,
      licenseRisks,
      mostOutdated: reports
        .flatMap((r) => r.outdated.map((o) => ({ ...o, project: r.project })))
        .sort((a, b) => (b.behindBy?.major || 0) - (a.behindBy?.major || 0))
        .slice(0, 10),
    };

    return { content: [{ type: "text", text: JSON.stringify(summary, null, 2) }] };
  }
);

// --- list_vulnerabilities ---
server.tool(
  "list_vulnerabilities",
  "List all known vulnerabilities across projects",
  {
    severity: z.enum(["critical", "high", "medium", "low"]).optional().describe("Filter by minimum severity"),
    project: z.string().optional().describe("Filter by project path"),
  },
  async ({ severity, project }) => {
    const keys = cache.keys();
    let reports = keys.map((k) => cache.get(k)).filter(Boolean);
    if (project) reports = reports.filter((r) => r.project === project);

    let vulns = reports.flatMap((r) =>
      r.vulnerabilities.map((v) => ({ ...v, project: r.project }))
    );
    if (severity) vulns = filterByThreshold(vulns, severity);

    return { content: [{ type: "text", text: JSON.stringify(vulns, null, 2) }] };
  }
);

// --- list_outdated ---
server.tool(
  "list_outdated",
  "List outdated dependencies across projects",
  {
    staleness: z.enum(["major", "minor", "patch"]).optional().describe("Filter by staleness level"),
    project: z.string().optional().describe("Filter by project path"),
  },
  async ({ staleness, project }) => {
    const keys = cache.keys();
    let reports = keys.map((k) => cache.get(k)).filter(Boolean);
    if (project) reports = reports.filter((r) => r.project === project);

    let outdated = reports.flatMap((r) =>
      r.outdated.map((o) => ({ ...o, project: r.project }))
    );

    if (staleness) {
      const levels = { major: 3, minor: 2, patch: 1 };
      const minLevel = levels[staleness] || 0;
      outdated = outdated.filter((o) => (levels[o.staleness] || 0) >= minLevel);
    }

    return { content: [{ type: "text", text: JSON.stringify(outdated, null, 2) }] };
  }
);

// --- list_licenses ---
server.tool(
  "list_licenses",
  "List all licenses in use across projects",
  {
    risk: z.enum(["low", "medium", "high", "unknown"]).optional().describe("Filter by risk level"),
    project: z.string().optional().describe("Filter by project path"),
  },
  async ({ risk, project }) => {
    const keys = cache.keys();
    let reports = keys.map((k) => cache.get(k)).filter(Boolean);
    if (project) reports = reports.filter((r) => r.project === project);

    let licenses = reports.flatMap((r) =>
      r.licenses.map((l) => ({ ...l, project: r.project }))
    );
    if (risk) licenses = licenses.filter((l) => l.risk === risk);

    return { content: [{ type: "text", text: JSON.stringify(licenses, null, 2) }] };
  }
);

// --- create_github_issues ---
server.tool(
  "create_github_issues",
  "Create GitHub issues for vulnerability findings in a project",
  {
    project: z.string().describe("Absolute path to the project directory"),
    severity: z.enum(["critical", "high", "medium", "low"]).optional().describe("Minimum severity threshold"),
  },
  async ({ project, severity }) => {
    const report = cache.get(project);
    if (!report) {
      return { content: [{ type: "text", text: "No scan data for this project. Run scan_project first." }] };
    }

    const overrideConfig = severity
      ? { ...config, severity: { issueThreshold: severity } }
      : config;

    const result = await createGithubIssues(report, overrideConfig);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// --- check_tool_status ---
server.tool(
  "check_tool_status",
  "Report which native CLI tools are available and which ecosystems use fallback mode",
  {},
  async () => {
    const status = await checkToolAvailability();
    return { content: [{ type: "text", text: JSON.stringify(status, null, 2) }] };
  }
);

// --- get_config ---
server.tool(
  "get_config",
  "Return the current active configuration",
  {},
  async () => {
    return { content: [{ type: "text", text: JSON.stringify(config, null, 2) }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
```

- [ ] **Step 2: Run tests to verify nothing broke**

Run: `npm test`
Expected: All tests still pass

- [ ] **Step 3: Verify the server starts without errors**

Run: `echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}},"id":1}' | timeout 3 node index.js 2>/dev/null || true`
Expected: JSON response containing `"name":"sentinel"`

- [ ] **Step 4: Commit**

```bash
git add index.js
git commit -m "feat: wire up MCP server with all 9 tools"
```

---

### Task 14: Integration Test with Real Projects

**Files:**
- Modify: `test.js` (add integration test)

- [ ] **Step 1: Add integration test that scans a real local project**

Append to `test.js` before the summary line:

```js
console.log("\n=== Integration Tests ===\n");

await test("scan_project works on sentinel-mcp itself (node ecosystem)", async () => {
  const scanner2 = new Scanner(DEFAULTS);
  const report = await scanner2.scanProject(process.cwd());
  assert.equal(report.project, process.cwd());
  assert.ok(report.ecosystems.includes("node"));
  assert.ok(report.scannedAt);
  assert.ok(report.toolMode.node === "native" || report.toolMode.node === "fallback");
  // We should have at least our own dependencies detected
  console.log(`    scanned ${report.licenses.length} licenses, ${report.outdated.length} outdated, ${report.vulnerabilities.length} vulns`);
});
```

- [ ] **Step 2: Run tests**

Run: `npm test`
Expected: All tests pass, integration test prints scan summary

- [ ] **Step 3: Commit**

```bash
git add test.js
git commit -m "test: add integration test scanning sentinel-mcp itself"
```

---

### Task 15: Final Push and Cleanup

**Files:**
- No new files

- [ ] **Step 1: Run full test suite**

Run: `npm test`
Expected: All tests pass

- [ ] **Step 2: Push to GitHub**

```bash
git push origin master
```

- [ ] **Step 3: Verify on GitHub**

Run: `gh repo view digitalghost404/sentinel-mcp --web`
Expected: Repository shows all committed files
