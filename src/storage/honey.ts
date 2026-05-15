import { type ResolvedConfig } from '../types';

const HONEY_KEY_PREFIX = 't_';

export class HoneyKeyManager {
  private honeyKeys: Map<string, Set<string>> = new Map();
  private enabled: boolean;

  constructor(private config: ResolvedConfig) {
    this.enabled = config.honeyKeys.count > 0;
  }

  get isEnabled(): boolean {
    return this.enabled;
  }

  get count(): number {
    return this.enabled ? this.config.honeyKeys.count : 0;
  }

  add(backend: string, key: string): void {
    if (!this.enabled) return;
    let set = this.honeyKeys.get(backend);
    if (!set) {
      set = new Set();
      this.honeyKeys.set(backend, set);
    }
    set.add(key);
  }

  remove(backend: string, key: string): void {
    const set = this.honeyKeys.get(backend);
    if (set) {
      set.delete(key);
    }
  }

  isHoney(backend: string, key: string): boolean {
    return this.honeyKeys.get(backend)?.has(key) ?? false;
  }

  generateHoneyKeys(backend: string, existingRealKeys: string[], count: number): string[] {
    if (!this.enabled || count <= 0) return [];
    const generated: string[] = [];
    const excluded = new Set([...existingRealKeys, ...this.allKeys(backend)]);
    for (let i = 0; i < count; i++) {
      let honeyKey: string;
      do {
        honeyKey = `${HONEY_KEY_PREFIX}${this.randomHex(32)}`;
      } while (excluded.has(honeyKey) || generated.includes(honeyKey));
      generated.push(honeyKey);
      excluded.add(honeyKey);
      this.add(backend, honeyKey);
    }
    return generated;
  }

  clearBackend(backend: string): void {
    this.honeyKeys.delete(backend);
  }

  clearAll(): void {
    this.honeyKeys.clear();
  }

  allKeys(backend: string): string[] {
    return [...(this.honeyKeys.get(backend) ?? [])];
  }

  private randomHex(length: number): string {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    let hex = '';
    for (const b of bytes) {
      hex += b.toString(16).padStart(2, '0');
    }
    return hex.slice(0, length);
  }
}
