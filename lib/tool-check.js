import { execFile } from "node:child_process";
import { promisify } from "node:util";
const execFileAsync = promisify(execFile);

async function checkTool(command, args) {
  try {
    const { stdout } = await execFileAsync(command, args, { timeout: 5000 });
    return { available: true, version: stdout.trim().split("\n")[0] };
  } catch { return { available: false, version: null }; }
}

export async function checkToolAvailability() {
  const [npm, govulncheck, goCmd, pipAudit, pip, cargo, cargoAudit, cargoOutdated, cargoLicense, gh] = await Promise.all([
    checkTool("npm", ["--version"]),
    checkTool("govulncheck", ["-version"]),
    checkTool("go", ["version"]),
    checkTool("pip-audit", ["--version"]),
    checkTool("pip", ["--version"]),
    checkTool("cargo", ["--version"]),
    checkTool("cargo", ["audit", "--version"]),
    checkTool("cargo", ["outdated", "--version"]),
    checkTool("cargo", ["license", "--version"]),
    checkTool("gh", ["--version"]),
  ]);
  return {
    node: { npm, mode: npm.available ? "native" : "fallback" },
    go: { go: goCmd, govulncheck, mode: govulncheck.available ? "native" : "fallback" },
    python: { pip, "pip-audit": pipAudit, mode: pipAudit.available ? "native" : "fallback" },
    rust: { cargo, "cargo-audit": cargoAudit, "cargo-outdated": cargoOutdated, "cargo-license": cargoLicense, mode: cargoAudit.available ? "native" : "fallback" },
    gh,
  };
}
