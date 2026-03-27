const SEMVER_RE = /^v?(\d+)\.(\d+)\.(\d+)/;

function parse(version) {
  if (typeof version !== "string") return null;
  const match = version.trim().match(SEMVER_RE);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
  };
}

export function compareSemver(current, latest) {
  const curr = parse(current);
  const lat = parse(latest);
  if (!curr || !lat) return null;

  return {
    major: lat.major - curr.major,
    minor: lat.minor - curr.minor,
    patch: lat.patch - curr.patch,
  };
}

export function classifyStaleness(behindBy) {
  if (!behindBy) return "unknown";
  if (behindBy.major > 0) return "major";
  if (behindBy.minor > 0) return "minor";
  if (behindBy.patch > 0) return "patch";
  if (behindBy.major === 0 && behindBy.minor === 0 && behindBy.patch === 0) return "current";
  return "unknown";
}
