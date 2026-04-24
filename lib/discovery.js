import { readdir, access } from "node:fs/promises";
import { join } from "node:path";

const ECOSYSTEM_FILES = [
  { file: "package.json", ecosystem: "node" },
  { file: "go.mod", ecosystem: "go" },
  { file: "requirements.txt", ecosystem: "python" },
  { file: "Cargo.toml", ecosystem: "rust" },
];

function matchesExclude(dirPath, excludePatterns) {
  for (const pattern of excludePatterns) {
    // Simple glob matching: support * as wildcard segment
    const regexStr = pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, "[^/]*");
    const regex = new RegExp(`(^|/)${regexStr}(/|$)`);
    if (regex.test(dirPath) || matchSimple(dirPath, pattern)) {
      return true;
    }
  }
  return false;
}

function matchSimple(dirPath, pattern) {
  // Handle patterns like */node_modules or */node_modules/*
  const parts = pattern.split("/");
  const pathParts = dirPath.split("/");

  // Check if the directory name matches the last non-wildcard segment
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part === "*") continue;
    if (pathParts.includes(part)) return true;
  }
  return false;
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function discoverProjects(roots, exclude) {
  const results = [];

  for (const root of roots) {
    let entries;
    try {
      entries = await readdir(root, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const projPath = join(root, entry.name);

      if (matchesExclude(projPath, exclude)) continue;

      const ecosystems = [];
      for (const { file, ecosystem } of ECOSYSTEM_FILES) {
        if (await fileExists(join(projPath, file))) {
          ecosystems.push(ecosystem);
        }
      }

      if (ecosystems.length > 0) {
        results.push({ path: projPath, ecosystems });
      }
    }
  }

  return results;
}
