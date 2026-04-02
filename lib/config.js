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
  cache: { ttlMs: 3_600_000, dir: join(homedir(), ".sentinel-mcp", "cache") },
  severity: { issueThreshold: "high" },
  licenses: {
    allowed: ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"],
    flagged: ["GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"],
  },
  github: { labels: ["security", "dependencies"], dryRun: false },
  timeouts: { cliMs: 30_000, apiMs: 15_000 },
};

const DEFAULT_PATH = join(homedir(), ".sentinel-mcp", "config.json");

function deepMerge(defaults, overrides) {
  const result = { ...defaults };
  for (const key of Object.keys(overrides)) {
    if (overrides[key] && typeof overrides[key] === "object" && !Array.isArray(overrides[key]) && defaults[key] && typeof defaults[key] === "object" && !Array.isArray(defaults[key])) {
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
      } catch { }
    }
  }
  return deepMerge(DEFAULTS, userConfig);
}
