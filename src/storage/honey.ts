import { type ResolvedConfig } from '../types';

const HONEY_KEY_PREFIX = 't_';

const WORDS_A = ['cache', 'pref', 'data', 'meta', 'config', 'flag', 'info', 'sync'] as const;
const WORDS_B = ['data', 'meta', 'info', 'config', 'state', 'store', 'map', 'cache'] as const;

type NamingStyle = 'snake' | 'camel' | 'kebab';

function detectStyle(aliases: string[]): NamingStyle {
  let snake = 0,
    camel = 0,
    kebab = 0;
  for (const a of aliases) {
    if (a.includes('_')) snake++;
    else if (a.includes('-')) kebab++;
    else if (/[a-z][A-Z]/.test(a)) camel++;
  }
  if (camel > snake && camel > kebab) return 'camel';
  if (kebab > snake) return 'kebab';
  return 'snake';
}

function styledAlias(a: string, b: string, style: NamingStyle): string {
  switch (style) {
    case 'camel': {
      return `${a}${b.charAt(0).toUpperCase()}${b.slice(1)}`;
    }
    case 'kebab': {
      return `${a}-${b}`;
    }
    default: {
      return `${a}_${b}`;
    }
  }
}

export class HoneyKeyManager {
  private honeyKeys: Map<string, Set<string>> = new Map();
  private decoyAliases: Map<string, Map<string, string>> = new Map();
  private decoyCount: Map<string, number> = new Map();
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
    // FIFO eviction: if the per-backend cap is reached, drop the oldest entry
    // (JS Set preserves insertion order, so .values().next().value is oldest).
    const maxPerBackend = this.config.honeyKeys.maxPerBackend ?? 500;
    if (set.size >= maxPerBackend) {
      const oldest = set.values().next().value as string;
      set.delete(oldest);
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

  isDecoyAlias(backend: string, alias: string): boolean {
    return this.decoyAliases.get(backend)?.has(alias) ?? false;
  }

  allDecoyAliases(backend: string): string[] {
    const map = this.decoyAliases.get(backend);
    return map ? [...map.keys()] : [];
  }

  assignDecoyAlias(backend: string, storageKey: string, existingRealAliases: string[]): void {
    if (!this.enabled) return;
    let map = this.decoyAliases.get(backend);
    if (!map) {
      map = new Map();
      this.decoyAliases.set(backend, map);
    }
    const excluded = new Set([...existingRealAliases, ...map.keys()]);

    const index = this.decoyCount.get(backend) ?? 0;
    this.decoyCount.set(backend, index + 1);

    let alias: string;
    if (this.config.honeyKeys.aliasGenerator) {
      const gen = this.config.honeyKeys.aliasGenerator;
      let i = index;
      do {
        alias = gen(i++);
      } while (excluded.has(alias));
    } else {
      alias = this.syntheticAlias(excluded, existingRealAliases);
    }

    map.set(alias, storageKey);
  }

  private syntheticAlias(excluded: Set<string>, realAliases: string[]): string {
    const style = detectStyle(realAliases);
    let alias: string;
    let attempts = 0;
    do {
      // WORDS_A and WORDS_B each have 8 entries; 256 % 8 === 0 so no modulo bias.
      const rands = crypto.getRandomValues(new Uint8Array(2));
      const a = WORDS_A[rands[0]! % WORDS_A.length]!;
      const b = WORDS_B[rands[1]! % WORDS_B.length]!;
      alias = a === b ? styledAlias(a, 'state', style) : styledAlias(a, b, style);
      attempts++;
      if (attempts > 50) {
        const n = crypto.getRandomValues(new Uint16Array(1))[0]!;
        alias = styledAlias('cache', `sync${n % 1000}`, style);
      }
    } while (excluded.has(alias));
    return alias;
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
    this.decoyAliases.delete(backend);
    this.decoyCount.delete(backend);
  }

  clearAll(): void {
    this.honeyKeys.clear();
    this.decoyAliases.clear();
    this.decoyCount.clear();
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
