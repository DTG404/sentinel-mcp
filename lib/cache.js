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
    const result = [];
    for (const [key] of this._entries) {
      if (this.get(key) !== null) {
        result.push(key);
      }
    }
    return result;
  }
}
