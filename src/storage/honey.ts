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
      const a = WORDS_A[Math.floor(Math.random() * WORDS_A.length)]!;
      const b = WORDS_B[Math.floor(Math.random() * WORDS_B.length)]!;
      alias = a === b ? styledAlias(a, 'state', style) : styledAlias(a, b, style);
      attempts++;
      if (attempts > 50) {
        alias = styledAlias('cache', `sync${Math.floor(Math.random() * 999)}`, style);
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
