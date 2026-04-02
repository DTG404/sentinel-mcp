import { readFile, writeFile, readdir, mkdir } from "node:fs/promises";
import { join } from "node:path";

export class Cache {
  constructor(ttlMs, cacheDir) {
    this._ttlMs = ttlMs;
    this._entries = new Map();
    this._cacheDir = cacheDir;
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
              const entry = JSON.parse(raw);
              if (Date.now() - entry.timestamp <= this._ttlMs) {
                this._entries.set(entry.key, entry);
              }
            } catch { }
          })
      );
    } catch { }
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

  async set(key, value) {
    const entry = { key, value, timestamp: Date.now() };
    this._entries.set(key, entry);
    try {
      await mkdir(this._cacheDir, { recursive: true });
      await writeFile(this._keyToFile(key), JSON.stringify(entry));
    } catch { }
  }

  has(key) {
    return this.get(key) !== null;
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
}
