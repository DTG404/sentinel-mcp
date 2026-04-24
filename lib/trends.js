function normalizeHistory(history, projectPath, days) {
  const cutoff = Date.now() - (days * 24 * 60 * 60 * 1000);
  return (history ?? [])
    .filter((entry) => !projectPath || entry.project === projectPath)
    .filter((entry) => Date.parse(entry.scannedAt ?? 0) >= cutoff)
    .sort((a, b) => Date.parse(a.scannedAt ?? 0) - Date.parse(b.scannedAt ?? 0));
}

function vulnKey(vuln) {
  return `${vuln.package ?? "unknown"}::${vuln.id ?? "unknown"}`;
}

function outdatedKey(pkg) {
  return pkg.name ?? pkg.package ?? "unknown";
}

function licenseKey(license) {
  return license.package ?? "unknown";
}

export class TrendAnalyzer {
  constructor(cache, configHash = null) {
    this.cache = cache;
    this.configHash = configHash;
  }

  compareScans(projectPath) {
    const history = normalizeHistory(this.cache.getHistory?.(projectPath, this.configHash) ?? [], projectPath, 3650);
    const current = this.cache.get?.(projectPath, this.configHash) ?? history.at(-1) ?? null;
    const previous = history.length >= 2 ? history.at(-2) : null;

    if (!current || !previous) {
      return {
        project: projectPath,
        compared_at: current?.scannedAt ?? null,
        previous_scan_at: previous?.scannedAt ?? null,
        new_vulnerabilities: [],
        resolved_vulnerabilities: [],
        new_outdated: [],
        resolved_outdated: [],
        license_changes: [],
      };
    }

    const currentVulns = new Map((current.vulnerabilities ?? []).map((item) => [vulnKey(item), item]));
    const previousVulns = new Map((previous.vulnerabilities ?? []).map((item) => [vulnKey(item), item]));
    const currentOutdated = new Map((current.outdated ?? []).map((item) => [outdatedKey(item), item]));
    const previousOutdated = new Map((previous.outdated ?? []).map((item) => [outdatedKey(item), item]));
    const currentLicenses = new Map((current.licenses ?? []).map((item) => [licenseKey(item), item]));
    const previousLicenses = new Map((previous.licenses ?? []).map((item) => [licenseKey(item), item]));

    return {
      project: projectPath,
      compared_at: current.scannedAt,
      previous_scan_at: previous.scannedAt,
      new_vulnerabilities: [...currentVulns.entries()]
        .filter(([key]) => !previousVulns.has(key))
        .map(([, item]) => ({ package: item.package, severity: item.severity, id: item.id, introduced: current.scannedAt })),
      resolved_vulnerabilities: [...previousVulns.entries()]
        .filter(([key]) => !currentVulns.has(key))
        .map(([, item]) => ({ package: item.package, severity: item.severity, id: item.id, resolved: current.scannedAt })),
      new_outdated: [...currentOutdated.entries()]
        .filter(([key]) => !previousOutdated.has(key))
        .map(([, item]) => ({ package: item.name, current: item.current, latest: item.latest })),
      resolved_outdated: [...previousOutdated.entries()]
        .filter(([key]) => !currentOutdated.has(key))
        .map(([, item]) => ({ package: item.name })),
      license_changes: [...currentLicenses.entries()]
        .filter(([key, item]) => previousLicenses.has(key) && previousLicenses.get(key).license !== item.license)
        .map(([key, item]) => ({ package: key, old_license: previousLicenses.get(key).license, new_license: item.license })),
    };
  }

  getTrend(projectPath, days = 30) {
    const history = normalizeHistory(this.cache.getHistory?.(projectPath, this.configHash) ?? [], projectPath, days);
    const dataPoints = history.map((entry) => ({
      date: entry.scannedAt,
      vuln_count: (entry.vulnerabilities ?? []).length,
      outdated_count: (entry.outdated ?? []).length,
      critical_count: (entry.vulnerabilities ?? []).filter((item) => item.severity === "critical").length,
      high_count: (entry.vulnerabilities ?? []).filter((item) => item.severity === "high").length,
    }));

    const first = dataPoints[0] ?? { vuln_count: 0, outdated_count: 0 };
    const last = dataPoints.at(-1) ?? { vuln_count: 0, outdated_count: 0 };
    const delta = (last.vuln_count + last.outdated_count) - (first.vuln_count + first.outdated_count);
    const trend = delta > 0 ? "worsening" : delta < 0 ? "improving" : "stable";

    return {
      project: projectPath,
      period: `${days}d`,
      data_points: dataPoints,
      trend,
    };
  }

  getAllTrends(days = 30) {
    const allHistory = normalizeHistory(this.cache.getHistory?.(undefined, this.configHash) ?? [], null, days);
    const grouped = new Map();
    for (const entry of allHistory) {
      const list = grouped.get(entry.project) ?? [];
      list.push(entry);
      grouped.set(entry.project, list);
    }
    return [...grouped.keys()].map((project) => this.getTrend(project, days));
  }
}
