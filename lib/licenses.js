const LOW_RISK = new Set([
  "MIT",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "Unlicense",
  "0BSD",
  "CC0-1.0",
  "BlueOak-1.0.0",
]);

const MEDIUM_RISK = new Set([
  "MPL-2.0",
  "LGPL-2.0-only",
  "LGPL-2.1-only",
  "LGPL-3.0-only",
  "LGPL-2.0-or-later",
  "LGPL-2.1-or-later",
  "LGPL-3.0-or-later",
  "EPL-1.0",
  "EPL-2.0",
  "CDDL-1.0",
  "EUPL-1.2",
]);

const HIGH_RISK = new Set([
  "GPL-2.0-only",
  "GPL-2.0-or-later",
  "GPL-3.0-only",
  "GPL-3.0-or-later",
  "AGPL-1.0-only",
  "AGPL-3.0-only",
  "AGPL-3.0-or-later",
  "SSPL-1.0",
  "BUSL-1.1",
]);

export function classifyLicense(license, licenseConfig) {
  if (!license) return { license, risk: "unknown" };

  // Check user config first
  if (licenseConfig?.flagged?.includes(license)) {
    return { license, risk: "high" };
  }
  if (licenseConfig?.allowed?.includes(license)) {
    return { license, risk: "low" };
  }

  // Fall back to built-in sets
  if (LOW_RISK.has(license)) return { license, risk: "low" };
  if (MEDIUM_RISK.has(license)) return { license, risk: "medium" };
  if (HIGH_RISK.has(license)) return { license, risk: "high" };

  return { license, risk: "unknown" };
}
