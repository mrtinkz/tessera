import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HoneyKeyManager } from '../../src/storage/honey';
import { resolveConfig } from '../../src/core/config';
import { Tessera } from '../../src/tessera';
import { resetLockout } from '../../src/core/lockout';

function makeManager(count = 3): HoneyKeyManager {
  const config = resolveConfig({ honeyKeys: { count } });
  return new HoneyKeyManager(config);
}

describe('HoneyKeyManager', () => {
  it('isEnabled returns true when count > 0', () => {
    const mgr = makeManager(3);
    expect(mgr.isEnabled).toBe(true);
  });

  it('isEnabled returns false when count is 0', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 0 } });
    const mgr = new HoneyKeyManager(cfg);
    expect(mgr.isEnabled).toBe(false);
  });

  // Covers lines 17-19: count getter
  it('count getter returns honeyKeys.count when enabled', () => {
    const mgr = makeManager(3);
    expect(mgr.count).toBe(3);
  });

  it('count getter returns 0 when disabled', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 0 } });
    const mgr = new HoneyKeyManager(cfg);
    expect(mgr.count).toBe(0);
  });

  it('add() and isHoney() work for a registered key', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_abcdef1234567890abcdef1234567890');
    expect(mgr.isHoney('local', 't_abcdef1234567890abcdef1234567890')).toBe(true);
  });

  it('isHoney() returns false for an unknown key', () => {
    const mgr = makeManager(3);
    expect(mgr.isHoney('local', 't_unknown')).toBe(false);
  });

  it('add() is a no-op when manager is disabled', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 0 } });
    const mgr = new HoneyKeyManager(cfg);
    mgr.add('local', 't_somekey');
    expect(mgr.isHoney('local', 't_somekey')).toBe(false);
  });

  // Covers lines 31-36: remove() when set exists
  it('remove() deletes a previously added honey key', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_aaaa');
    mgr.remove('local', 't_aaaa');
    expect(mgr.isHoney('local', 't_aaaa')).toBe(false);
  });

  // Covers lines 31-36: remove() when set does NOT exist (no-op, should not throw)
  it('remove() is a no-op when the backend has no registered keys', () => {
    const mgr = makeManager(3);
    expect(() => mgr.remove('nonexistent-backend', 't_aaaa')).not.toThrow();
  });

  it('generateHoneyKeys() returns the requested count of keys', () => {
    const mgr = makeManager(3);
    const keys = mgr.generateHoneyKeys('local', [], 3);
    expect(keys).toHaveLength(3);
    expect(keys.every((k) => k.startsWith('t_'))).toBe(true);
  });

  it('generateHoneyKeys() returns [] when disabled', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 0 } });
    const mgr = new HoneyKeyManager(cfg);
    expect(mgr.generateHoneyKeys('local', [], 3)).toHaveLength(0);
  });

  it('generateHoneyKeys() returns [] when count <= 0', () => {
    const mgr = makeManager(3);
    expect(mgr.generateHoneyKeys('local', [], 0)).toHaveLength(0);
  });

  // Covers lines 58-60: clearBackend()
  it('clearBackend() removes all honey keys for the specified backend', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_aaaa');
    mgr.add('local', 't_bbbb');
    mgr.clearBackend('local');
    expect(mgr.isHoney('local', 't_aaaa')).toBe(false);
    expect(mgr.allKeys('local')).toHaveLength(0);
  });

  it('clearBackend() is a no-op for an unknown backend', () => {
    const mgr = makeManager(3);
    expect(() => mgr.clearBackend('unknown')).not.toThrow();
  });

  it('clearAll() removes all honey keys across all backends', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_aaaa');
    mgr.add('session', 't_bbbb');
    mgr.clearAll();
    expect(mgr.isHoney('local', 't_aaaa')).toBe(false);
    expect(mgr.isHoney('session', 't_bbbb')).toBe(false);
  });

  it('allKeys() returns all honey keys for a backend', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_aaaa');
    mgr.add('local', 't_bbbb');
    const keys = mgr.allKeys('local');
    expect(keys).toContain('t_aaaa');
    expect(keys).toContain('t_bbbb');
  });

  it('allKeys() returns [] for an unknown backend', () => {
    const mgr = makeManager(3);
    expect(mgr.allKeys('unknown')).toHaveLength(0);
  });

  it('generateHoneyKeys() excludes existing real keys', () => {
    const mgr = makeManager(5);
    const existing = ['t_existing0000000000000000000000000'];
    const keys = mgr.generateHoneyKeys('local', existing, 2);
    expect(keys.every((k) => !existing.includes(k))).toBe(true);
  });

  it('isDecoyAlias() returns false for a backend with no decoy aliases registered', () => {
    const mgr = makeManager(3);
    expect(mgr.isDecoyAlias('local', 'any-alias')).toBe(false);
  });

  it('allDecoyAliases() returns empty array for a backend with no decoy aliases registered', () => {
    const mgr = makeManager(3);
    expect(mgr.allDecoyAliases('local')).toHaveLength(0);
  });

  it('assignDecoyAlias() creates a decoy alias retrievable via isDecoyAlias', () => {
    const mgr = makeManager(3);
    mgr.generateHoneyKeys('local', [], 1);
    mgr.assignDecoyAlias('local', mgr.allKeys('local')[0]!, []);
    const aliases = mgr.allDecoyAliases('local');
    expect(aliases.length).toBe(1);
    expect(mgr.isDecoyAlias('local', aliases[0]!)).toBe(true);
  });

  it('assignDecoyAlias() uses aliasGenerator when configured', () => {
    const config = resolveConfig({
      honeyKeys: { count: 2, aliasGenerator: (i) => `myapp_custom_${i}` },
    });
    const mgr = new HoneyKeyManager(config);
    mgr.assignDecoyAlias('local', 't_honey1', []);
    expect(mgr.isDecoyAlias('local', 'myapp_custom_0')).toBe(true);
  });

  it('assignDecoyAlias() with aliasGenerator retries when result collides', () => {
    let calls = 0;
    const config = resolveConfig({
      honeyKeys: { count: 2, aliasGenerator: () => (calls++ === 0 ? 'collide' : 'unique_alias') },
    });
    const mgr = new HoneyKeyManager(config);
    mgr.assignDecoyAlias('local', 't_honey1', ['collide']);
    expect(mgr.isDecoyAlias('local', 'unique_alias')).toBe(true);
  });

  it('syntheticAlias() falls back to cache_syncN after 50 failed attempts', () => {
    const mgr = makeManager(3);
    vi.spyOn(Math, 'random').mockReturnValue(0);
    mgr.assignDecoyAlias('local', 't_honey1', ['cache_data']);
    expect(mgr.isDecoyAlias('local', 'cache_sync0')).toBe(true);
    vi.restoreAllMocks();
  });

  it('assignDecoyAlias() generates camelCase alias when existing aliases are camelCase', () => {
    const mgr = makeManager(3);
    mgr.assignDecoyAlias('local', 't_honey1', ['cacheData', 'prefMeta', 'syncInfo']);
    const aliases = mgr.allDecoyAliases('local');
    expect(aliases.length).toBe(1);
    expect(/[a-z][A-Z]/.test(aliases[0]!)).toBe(true);
  });
});

// ── Issue 2: honey key structural indistinguishability ────────────────────────

describe('HoneyKeyManager — storage format matches real entries', () => {
  beforeEach(() => {
    localStorage.clear();
    resetLockout();
  });

  it('honey keys written to localStorage use the same two-blob encryptedMeta.encryptedValue format as real entries', async () => {
    const vault = await Tessera.unlock('246813', { honeyKeys: { count: 3 } });
    // Writing a real key triggers honey key generation in addHoneyKeys()
    await vault.local.setItem('mykey', 'myvalue');

    // Collect all t_-prefixed entries
    const entries: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k?.startsWith('t_')) entries.push(localStorage.getItem(k)!);
    }

    expect(entries.length).toBeGreaterThan(0);
    // Every entry — both real and honey — must have exactly one dot
    for (const raw of entries) {
      const dots = (raw.match(/\./g) ?? []).length;
      expect(dots).toBe(1);
    }
  });

  it('honey key value blobs vary in length (no length-based fingerprinting)', async () => {
    // 5 × Tessera.unlock() ≈ 5 × 1–2 s PBKDF2 — needs extended timeout
    // Unlock multiple times in fresh vaults to collect many honey key entries
    const valueLengths = new Set<number>();

    for (let i = 0; i < 5; i++) {
      localStorage.clear();
      resetLockout();
      const vault = await Tessera.unlock('246813', { honeyKeys: { count: 3 }, debug: true });
      await vault.local.setItem('k', 'v');

      const rawKey = await vault.local.getRawKey!('k');
      for (let j = 0; j < localStorage.length; j++) {
        const storageKey = localStorage.key(j);
        if (storageKey?.startsWith('t_') && storageKey !== rawKey) {
          const raw = localStorage.getItem(storageKey)!;
          valueLengths.add(raw.split('.')[1].length);
        }
      }
    }

    // Across 15 honey key entries (5 vaults × 3 keys) we expect multiple distinct lengths
    expect(valueLengths.size).toBeGreaterThan(1);
  }, 30_000);
});
