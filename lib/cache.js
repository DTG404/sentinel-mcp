import { readFile, writeFile, readdir, mkdir } from "node:fs/promises";
import { join } from "node:path";

export class Cache {
  constructor(ttlMs, cacheDir) {
    this._ttlMs = ttlMs;
    this._entries = new Map();
    this._cacheDir = cacheDir;
  }

  getConfigHash(config) {
    const relevant = {
      issueThreshold: config?.severity?.issueThreshold ?? null,
      allowed: config?.licenses?.allowed ?? [],
      flagged: config?.licenses?.flagged ?? [],
      roots: config?.roots ?? [],
      exclude: config?.exclude ?? [],
    };
    const json = JSON.stringify(relevant);
    let hash = 0;
    for (let i = 0; i < json.length; i++) {
      hash = ((hash << 5) - hash) + json.charCodeAt(i);
      hash |= 0;
    }
    return String(hash);
  }

  _normalizeEntry(entry) {
    if (!entry) return null;
    return {
      key: entry.key,
      value: entry.value,
      timestamp: entry.timestamp,
      configHash: entry.configHash ?? null,
      history: Array.isArray(entry.history)
        ? entry.history
        : entry.value
          ? [{ timestamp: entry.timestamp, configHash: entry.configHash ?? null, value: entry.value }]
          : [],
    };
  }

  _keyToFile(key) {
    const safe = key.replace(/[^a-zA-Z0-9._-]/g, "_");
    return join(this._cacheDir, safe + ".json");
  }

  async warmup() {
    try {
      await mkdir(this._cacheDir, { recursive: true });
      const files = await readdir(this._cacheDir);
      await Promise.all(
        files
          .filter((f) => f.endsWith(".json"))
          .map(async (file) => {
            try {
              const raw = await readFile(join(this._cacheDir, file), "utf-8");
              const entry = this._normalizeEntry(JSON.parse(raw));
              if (Date.now() - entry.timestamp <= this._ttlMs) {
                this._entries.set(entry.key, entry);
              }
            } catch { }
          })
      );
    } catch { }
  }

  get(key, configHash = null) {
    const entry = this._entries.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > this._ttlMs) {
      this._entries.delete(key);
      return null;
    }
    if (configHash !== null && entry.configHash !== null && entry.configHash !== configHash) {
      return null;
    }
    return entry.value;
  }

  async set(key, value, configHash = null) {
    const previous = this._entries.get(key);
    const history = [
      ...(previous?.history ?? []),
      { timestamp: Date.now(), configHash, value },
    ].sort((a, b) => a.timestamp - b.timestamp);
    const entry = { key, value, timestamp: Date.now(), configHash, history };
    this._entries.set(key, entry);
    try {
      await mkdir(this._cacheDir, { recursive: true });
      await writeFile(this._keyToFile(key), JSON.stringify(entry));
    } catch { }
  }

  has(key, configHash = null) {
    return this.get(key, configHash) !== null;
  }

  clear() {
    this._entries.clear();
  }

  keys() {
    const result = [];
    for (const [key] of this._entries) {
      if (this.get(key) !== null) result.push(key);
    }
    return result;
  }

  getHistory(key, configHash = null) {
    const entries = key === undefined
      ? [...this._entries.values()]
      : [this._entries.get(key)].filter(Boolean);
    return entries
      .flatMap((entry) => entry.history)
      .filter((item) => Date.now() - item.timestamp <= this._ttlMs)
      .filter((item) => configHash === null || item.configHash === null || item.configHash === configHash)
      .map((item) => item.value)
      .sort((a, b) => Date.parse(a.scannedAt ?? 0) - Date.parse(b.scannedAt ?? 0));
  }
}
