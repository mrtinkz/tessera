import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { SessionStorageAdapter } from '../../src/adapters/session-storage';
import { IndexedDbAdapter } from '../../src/adapters/indexed-db';
import { KeySession } from '../../src/core/session';
import { deriveKey, deriveHmacKey, getSalt, encryptWithSalt } from '../../src/core/crypto';
import { resolveConfig } from '../../src/core/config';
import { TesseraEmitter } from '../../src/core/events';
import { SuspicionEngine } from '../../src/core/suspicion';

let session: KeySession;

async function setupSession(): Promise<void> {
  session = new KeySession();
  const salt = await getSalt();
  const key = await deriveKey('246813', salt);
  const hmacKey = await deriveHmacKey('246813', salt);
  session.setKey(key, 900_000);
  session.setHmacKey(hmacKey);
}

describe('SessionStorageAdapter', () => {
  beforeEach(async () => {
    sessionStorage.clear();
    await setupSession();
  });

  afterEach(() => {
    session.reset();
    vi.restoreAllMocks();
  });

  it('should encrypt and decrypt values', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('hello', 'world');
    const value = await adapter.getItem('hello');
    expect(value).toBe('world');
    expect(sessionStorage.getItem('hello')).not.toBe('world');
  });

  it('should return null for missing keys', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    expect(await adapter.getItem('missing')).toBeNull();
  });

  it('should remove items', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('temp', 'val');
    await adapter.removeItem('temp');
    expect(await adapter.getItem('temp')).toBeNull();
  });

  it('should encrypt all keys with name rotation', async () => {
    const adapter = new SessionStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    await adapter.setItem('plain', 'open');
    await adapter.setItem('enc', 'secret');

    const rawKeyPlain = await adapter.getRawKey!('plain');
    const rawKeyEnc = await adapter.getRawKey!('enc');
    expect(sessionStorage.getItem(rawKeyPlain)).not.toBeNull();
    expect(sessionStorage.getItem(rawKeyEnc)).not.toBeNull();
    expect(await adapter.getItem('enc')).toBe('secret');
  });

  it('should clear all items', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('a', '1');
    await adapter.setItem('b', '2');
    await adapter.clear();
    expect(await adapter.getItem('a')).toBeNull();
  });

  it('should list stored keys', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('k1', 'v1');
    const keys = await adapter.keys();
    expect(keys).toContain('k1');
  });

  it('should return null when vault is locked', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('key', 'value');
    session.lock();
    expect(await adapter.getItem('key')).toBeNull();
  });

  // TTL expiry
  it('should return null and remove item when TTL has expired', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('ttl-key', 'val', { ttl: 1 });
    await new Promise((r) => setTimeout(r, 10));
    expect(await adapter.getItem('ttl-key')).toBeNull();
  });

  it('should emit key-expired event on TTL expiry', async () => {
    const events = new TesseraEmitter();
    const adapter = new SessionStorageAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('key-expired', handler);
    await adapter.setItem('ttl-ev', 'data', { ttl: 1 });
    await new Promise((r) => setTimeout(r, 10));
    await adapter.getItem('ttl-ev');
    expect(handler).toHaveBeenCalled();
  });

  // maxReads
  it('should return null when maxReads is exhausted', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('mr-key', 'value', { maxReads: 1 });
    const first = await adapter.getItem('mr-key');
    expect(first).toBe('value');
    const second = await adapter.getItem('mr-key');
    expect(second).toBeNull();
  });

  it('should emit max-reads-reached event', async () => {
    const events = new TesseraEmitter();
    const adapter = new SessionStorageAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('max-reads-reached', handler);
    await adapter.setItem('mr-ev', 'data', { maxReads: 1 });
    await adapter.getItem('mr-ev'); // first read ok
    await adapter.getItem('mr-ev'); // second triggers event
    expect(handler).toHaveBeenCalled();
  });

  // halfLife hard
  it('should return null when halfLife.hard has elapsed', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('hl-hard', 'v', { halfLife: { hard: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    expect(await adapter.getItem('hl-hard')).toBeNull();
  });

  // halfLife soft
  it('should throw RECONFIRMATION_REQUIRED when halfLife.soft has elapsed and no reconfirm key', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('hl-soft', 'v', { halfLife: { soft: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    await expect(adapter.getItem('hl-soft')).rejects.toMatchObject({
      code: 'RECONFIRMATION_REQUIRED',
    });
  });

  it('should emit reconfirmation-required on soft half-life expiry', async () => {
    const events = new TesseraEmitter();
    const adapter = new SessionStorageAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('reconfirmation-required', handler);
    await adapter.setItem('hl-soft-ev', 'v', { halfLife: { soft: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    // getItem now throws after emitting the event
    try {
      await adapter.getItem('hl-soft-ev');
    } catch {
      /* expected RECONFIRMATION_REQUIRED */
    }
    expect(handler).toHaveBeenCalled();
  });

  // Legacy format: no dot in stored value
  it('should decrypt a legacy-format value stored without metadata', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const cryptoKey = session.getKey();
    const legacyEncrypted = await encryptWithSalt(cryptoKey, 'legacy-val');
    const rawKey = await session.rotateKeyName('legacy-key');
    sessionStorage.setItem(rawKey, legacyEncrypted);

    const result = await adapter.getItem('legacy-key');
    expect(result).toBe('legacy-val');
  });

  // Legacy format: corrupt (no dot, not valid ciphertext)
  it('should return null for corrupt legacy-format value', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const rawKey = await session.rotateKeyName('corrupt-legacy');
    sessionStorage.setItem(rawKey, 'NOTVALIDENCRYPTED!!');
    expect(await adapter.getItem('corrupt-legacy')).toBeNull();
  });

  // meta HMAC failure (corrupt meta part before the dot)
  it('should emit hmac-failure and remove item when meta decryption fails', async () => {
    const events = new TesseraEmitter();
    const adapter = new SessionStorageAdapter(resolveConfig({ debug: true }), session, events);
    const handler = vi.fn();
    events.on('hmac-failure', handler);

    await adapter.setItem('meta-corrupt', 'val');
    const rawKey = await adapter.getRawKey!('meta-corrupt');
    const stored = sessionStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    sessionStorage.setItem(rawKey, 'INVALIDBASE64GARBAGE==' + stored.slice(dotIdx));

    const result = await adapter.getItem('meta-corrupt');
    expect(result).toBeNull();
    expect(handler).toHaveBeenCalled();
  });

  // applyOnSuspicion – lock
  it('should lock session when onSuspicion is "lock" and value HMAC fails', async () => {
    const adapter = new SessionStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    await adapter.setItem('sus-lock', 'secure', { onSuspicion: 'lock' });
    const rawKey = await adapter.getRawKey!('sus-lock');
    const stored = sessionStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    sessionStorage.setItem(rawKey, stored.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==');
    await adapter.getItem('sus-lock');
    expect(session.isLocked()).toBe(true);
  });

  // applyOnSuspicion – throw (key intact)
  it('should leave key intact when onSuspicion is "throw" and value HMAC fails', async () => {
    const adapter = new SessionStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    await adapter.setItem('sus-throw', 'secure', { onSuspicion: 'throw' });
    const rawKey = await adapter.getRawKey!('sus-throw');
    const stored = sessionStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    sessionStorage.setItem(rawKey, stored.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==');
    expect(await adapter.getItem('sus-throw')).toBeNull();
    expect(sessionStorage.getItem(rawKey)).not.toBeNull();
  });

  // applyOnSuspicion – wipe (default)
  it('should wipe key when onSuspicion is "wipe" and value HMAC fails', async () => {
    const adapter = new SessionStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    await adapter.setItem('sus-wipe', 'secure', { onSuspicion: 'wipe' });
    const rawKey = await adapter.getRawKey!('sus-wipe');
    const stored = sessionStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    sessionStorage.setItem(rawKey, stored.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==');
    expect(await adapter.getItem('sus-wipe')).toBeNull();
    expect(sessionStorage.getItem(rawKey)).toBeNull();
  });

  // split mode write + read
  it('should write and read in split mode with idb adapter', async () => {
    const config = resolveConfig();
    const events = new TesseraEmitter();
    const idbAdapter = new IndexedDbAdapter(config, session, events);
    const adapter = new SessionStorageAdapter(config, session, events);
    adapter.setIdbAdapter(idbAdapter);

    await adapter.setItem('split-key', 'split-value', { mode: 'split' });
    const result = await adapter.getItem('split-key');
    expect(result).toBe('split-value');
  });

  // claim mode write + read
  it('should write and read in claim mode with idb adapter', async () => {
    const config = resolveConfig();
    const events = new TesseraEmitter();
    const idbAdapter = new IndexedDbAdapter(config, session, events);
    const adapter = new SessionStorageAdapter(config, session, events);
    adapter.setIdbAdapter(idbAdapter);

    await adapter.setItem('claim-key', 'claim-value', { mode: 'claim' });
    const result = await adapter.getItem('claim-key');
    expect(result).toBe('claim-value');
  });

  // Rate limit 1.5x exceeded → getItem returns null (covers session-storage.ts lines 63-70)
  it('should return null when suspicion rate limit is exceeded above 1.5x threshold', async () => {
    const config = resolveConfig({
      suspicion: {
        rateLimit: { callsPerSecond: 2, scorePerExcess: 1 },
        thresholds: { lockdown: 10_000 },
      },
    });
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new SessionStorageAdapter(config, session, events, suspicion);
    await adapter.setItem('rate-ss-key', 'rate-val');

    let finalResult: string | null = null;
    for (let i = 0; i < 5; i++) {
      finalResult = await adapter.getItem('rate-ss-key');
    }
    expect(finalResult).toBeNull();
    suspicion.destroy();
  });

  // honeyManager.isHoney returning true for session → returns null (covers lines 78-80)
  it('should return null and record honey hit when session-storage key is a honey key', async () => {
    const events = new TesseraEmitter();
    const adapter = new SessionStorageAdapter(resolveConfig(), session, events);
    const honeyMgr = {
      isEnabled: false,
      allKeys: () => [] as string[],
      generateHoneyKeys: () => [] as string[],
      isHoney: (_backend: string, _key: string) => true,
      isDecoyAlias: () => false,
      allDecoyAliases: () => [] as string[],
      assignDecoyAlias: () => {},
      remove: () => {},
      clearBackend: () => {},
    };
    adapter.setHoneyManager(honeyMgr);
    await adapter.setItem('honey-ss-test', 'honey-val');
    const result = await adapter.getItem('honey-ss-test');
    expect(result).toBeNull();
  });

  // removeItem: claim mode with idb adapter cleans up the IDB claim (lines 132-134)
  it('should remove the IDB claim when removeItem is called on a claim-mode item', async () => {
    const config = resolveConfig();
    const events = new TesseraEmitter();
    const idbAdapter = new IndexedDbAdapter(config, session, events);
    const adapter = new SessionStorageAdapter(config, session, events);
    adapter.setIdbAdapter(idbAdapter);

    await adapter.setItem('claim-remove', 'claim-val', { mode: 'claim' });
    await adapter.removeItem('claim-remove');
    // After removal, reading the claim returns null
    const result = await adapter.getItem('claim-remove');
    expect(result).toBeNull();
  });

  // split mode returns null without idb
  it('should return null for split mode without an idb adapter', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    // Force a split: prefix into sessionStorage manually
    const rawKey = await session.rotateKeyName('split-no-idb');
    sessionStorage.setItem(rawKey, 'split:SOMEGARBAGEDATA');
    const result = await adapter.getItem('split-no-idb');
    expect(result).toBeNull();
  });

  // readCount NaN branch: inject a metadata with non-finite readCount
  it('should normalise non-finite readCount in metadata', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const cryptoKey = session.getKey();
    const meta = JSON.stringify({
      writeTime: Date.now(),
      readCount: Number.NaN,
      sensitivity: 'low',
      onSuspicion: 'wipe',
    });
    const encMeta = await encryptWithSalt(cryptoKey, meta);
    const encVal = await encryptWithSalt(cryptoKey, 'nan-count-val');
    const rawKey = await session.rotateKeyName('nan-count');
    sessionStorage.setItem(rawKey, `${encMeta}.${encVal}`);
    const result = await adapter.getItem('nan-count');
    expect(result).toBe('nan-count-val');
  });

  // clear() with honeyManager that has clearBackend (covers lines 191-192)
  it('should call clearBackend on honeyManager when clearing', async () => {
    const clearBackendMock = vi.fn();
    const fakeMgr = {
      isEnabled: true,
      allKeys: () => [] as string[],
      generateHoneyKeys: (_b: string, _e: string[], n: number) =>
        Array.from({ length: n }, (_, i) => `h_${i}`),
      isHoney: () => false,
      remove: () => {},
      clearBackend: clearBackendMock,
    };
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    adapter.setHoneyManager(fakeMgr);
    await adapter.clear();
    expect(clearBackendMock).toHaveBeenCalledWith('session');
  });

  // wipeHighSensitivity JSON.parse catch branch (lines 168-169)
  it('should skip items with non-JSON meta during wipeHighSensitivity', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('valid-high', 'val', { sensitivity: 'high' });

    // Inject a t_ prefixed item whose meta is valid ciphertext but not JSON
    const cryptoKey = session.getKey();
    const nonJsonMeta = await encryptWithSalt(cryptoKey, 'NOT-JSON {{{');
    const encVal = await encryptWithSalt(cryptoKey, 'ignored');
    sessionStorage.setItem('t_badfakekeyAAAAAAAAAAAAAAAAAAAA', `${nonJsonMeta}.${encVal}`);

    const wiped: string[] = [];
    await adapter.wipeHighSensitivity(wiped);
    // The valid high-sensitivity item is wiped (non-JSON item is silently skipped)
    expect(wiped.some((w) => w.includes('session:'))).toBe(true);
  });

  // wipeHighSensitivity
  it('should wipe high-sensitivity items via wipeHighSensitivity', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('low', 'lo-val', { sensitivity: 'low' });
    await adapter.setItem('high', 'hi-val', { sensitivity: 'high' });
    const wiped: string[] = [];
    await adapter.wipeHighSensitivity(wiped);
    expect(wiped.some((w) => w.includes('session:'))).toBe(true);
    expect(await adapter.getItem('high')).toBeNull();
    expect(await adapter.getItem('low')).toBe('lo-val');
  });

  // wipeAll: removes every t_ entry regardless of sensitivity or honey status
  it('wipeAll removes all t_ entries including honey and low-sensitivity keys', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');
    const mgr = new HoneyKeyManager(config);
    const adapter = new SessionStorageAdapter(config, session, new TesseraEmitter());
    adapter.setHoneyManager(mgr);

    await adapter.setItem('low-key', 'lo', { sensitivity: 'low' });
    await adapter.setItem('high-key', 'hi', { sensitivity: 'high' });
    expect(mgr.allKeys('session').length).toBe(2);

    const tKeysBefore = Object.keys(sessionStorage).filter((k) => k.startsWith('t_'));
    expect(tKeysBefore.length).toBeGreaterThanOrEqual(3);

    const wiped: string[] = [];
    await adapter.wipeAll(wiped);

    const tKeysAfter = Object.keys(sessionStorage).filter((k) => k.startsWith('t_'));
    expect(tKeysAfter.length).toBe(0);
    expect(wiped.every((w) => w.startsWith('session:'))).toBe(true);
    expect(mgr.allKeys('session').length).toBe(0);
  });

  // cleanOrphanedHoneyKeys: wipes orphaned honey entries, leaves real keys intact
  it('cleanOrphanedHoneyKeys wipes orphaned honey entries but preserves real keys', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');

    // Session 1: write real key + honey keys
    const mgr1 = new HoneyKeyManager(config);
    const adapter1 = new SessionStorageAdapter(config, session, new TesseraEmitter());
    adapter1.setHoneyManager(mgr1);
    await adapter1.setItem('persist', 'still-here', { sensitivity: 'low' });
    const orphanKeys = mgr1.allKeys('session');
    expect(orphanKeys.length).toBe(2);

    // Session 2: fresh manager (simulates page reload)
    const mgr2 = new HoneyKeyManager(config);
    const adapter2 = new SessionStorageAdapter(config, session, new TesseraEmitter());
    adapter2.setHoneyManager(mgr2);

    expect(orphanKeys.every((k) => sessionStorage.getItem(k) !== null)).toBe(true);

    await adapter2.cleanOrphanedHoneyKeys();

    for (const k of orphanKeys) {
      expect(sessionStorage.getItem(k)).toBeNull();
    }
    expect(await adapter2.getItem('persist')).toBe('still-here');
  });

  // cleanOrphanedHoneyKeys: returns immediately when vault is locked
  it('cleanOrphanedHoneyKeys does nothing when vault is locked', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('k', 'v');
    session.lock();
    const tKeysBefore = Object.keys(sessionStorage).filter((k) => k.startsWith('t_'));
    await adapter.cleanOrphanedHoneyKeys();
    const tKeysAfter = Object.keys(sessionStorage).filter((k) => k.startsWith('t_'));
    expect(tKeysAfter).toEqual(tKeysBefore);
  });

  // addHoneyKeys: needed <= 0 branch (honey manager already has enough keys for the backend)
  it('should skip honey key generation when needed count is already satisfied', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');
    const mgr = new HoneyKeyManager(config);
    const adapter = new SessionStorageAdapter(config, session, new TesseraEmitter());
    adapter.setHoneyManager(mgr);

    // First setItem: generates 2 honey keys (needed = 2 - 0 = 2)
    await adapter.setItem('hk-first', 'v1');
    const keysAfterFirst = mgr.allKeys('session').length;
    expect(keysAfterFirst).toBe(2);

    // Second setItem: needed = 2 - 2 = 0 → takes the 'needed <= 0' early return path
    await adapter.setItem('hk-second', 'v2');
    // Honey key count should remain 2 (no new keys generated)
    expect(mgr.allKeys('session').length).toBe(2);
  });

  // claim mode without idb: F-37 fix — now throws UNSUPPORTED_ENV instead of silently skipping
  it('should throw UNSUPPORTED_ENV when claim mode is used without an IDB adapter', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    // F-37: IDB is required for claim mode — throws instead of silently skipping
    await expect(adapter.setItem('claim-no-idb', 'val', { mode: 'claim' })).rejects.toMatchObject({
      code: 'UNSUPPORTED_ENV',
    });
  });

  // getRawKey when locked returns developer key unchanged (covers line 200 true branch)
  it('should return the developer key unchanged from getRawKey when vault is locked', async () => {
    const adapter = new SessionStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    session.lock();
    const result = await adapter.getRawKey!('my-developer-key');
    expect(result).toBe('my-developer-key');
  });

  it('getRawKey throws when debug mode is not enabled', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await expect(adapter.getRawKey!('any-key')).rejects.toThrow('debug mode');
  });

  it('exportItem returns value and metadata without incrementing readCount', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('ss-exp-key', 'ss-exp-value');
    const exported1 = await adapter.exportItem!('ss-exp-key');
    expect(exported1).not.toBeNull();
    expect(exported1!.value).toBe('ss-exp-value');
    expect(exported1!.readCount).toBe(0);
    const exported2 = await adapter.exportItem!('ss-exp-key');
    expect(exported2!.readCount).toBe(0);
  });

  it('exportItem returns null for unknown key', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const result = await adapter.exportItem!('nonexistent-ss-key');
    expect(result).toBeNull();
  });

  it('exportItem returns null when halfLifeSoft has elapsed', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('ss-exp-soft', 'v', { halfLife: { soft: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    const result = await adapter.exportItem!('ss-exp-soft');
    expect(result).toBeNull();
  });

  it('exportItem returns null when maxReads is exhausted', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('ss-exp-mr', 'v', { maxReads: 1 });
    await adapter.getItem('ss-exp-mr');
    const result = await adapter.exportItem!('ss-exp-mr');
    expect(result).toBeNull();
  });

  it('exportItem returns null when halfLife.hard has elapsed', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('ss-exp-hard', 'v', { halfLife: { hard: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    const result = await adapter.exportItem!('ss-exp-hard');
    expect(result).toBeNull();
  });

  it('exportItem returns null when value HMAC is corrupt', async () => {
    const adapter = new SessionStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    await adapter.setItem('ss-exp-corrupt', 'v');
    const rawKey = await adapter.getRawKey!('ss-exp-corrupt');
    const stored = sessionStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    sessionStorage.setItem(rawKey, stored.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==');
    const result = await adapter.exportItem!('ss-exp-corrupt');
    expect(result).toBeNull();
  });

  it('exportItem returns null when meta HMAC is corrupt', async () => {
    const adapter = new SessionStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    await adapter.setItem('ss-exp-meta-corrupt', 'v');
    const rawKey = await adapter.getRawKey!('ss-exp-meta-corrupt');
    const stored = sessionStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    sessionStorage.setItem(rawKey, 'INVALIDBASE64GARBAGE==' + stored.slice(dotIdx));
    const result = await adapter.exportItem!('ss-exp-meta-corrupt');
    expect(result).toBeNull();
  });

  it('exportItem returns null when TTL has expired', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('ss-exp-ttl', 'v', { ttl: 1 });
    await new Promise((r) => setTimeout(r, 10));
    const result = await adapter.exportItem!('ss-exp-ttl');
    expect(result).toBeNull();
  });

  it('exportItem normalises NaN readCount in metadata', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const cryptoKey = session.getKey();
    const meta = JSON.stringify({
      writeTime: Date.now(),
      readCount: Number.NaN,
      sensitivity: 'low',
      onSuspicion: 'wipe',
    });
    const encMeta = await encryptWithSalt(cryptoKey, meta);
    const encVal = await encryptWithSalt(cryptoKey, 'nan-exp-val');
    const rawKey = await session.rotateKeyName('ss-exp-nan-count');
    sessionStorage.setItem(rawKey, `${encMeta}.${encVal}`);
    const result = await adapter.exportItem!('ss-exp-nan-count');
    expect(result).not.toBeNull();
    expect(result!.readCount).toBe(0);
  });

  it('exportItem omits optional fields absent from metadata', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const cryptoKey = session.getKey();
    const meta = JSON.stringify({ writeTime: Date.now(), readCount: 0 });
    const encMeta = await encryptWithSalt(cryptoKey, meta);
    const encVal = await encryptWithSalt(cryptoKey, 'ss-bare-val');
    const rawKey = await session.rotateKeyName('ss-exp-bare');
    sessionStorage.setItem(rawKey, `${encMeta}.${encVal}`);
    const result = await adapter.exportItem!('ss-exp-bare');
    expect(result).not.toBeNull();
    expect(result!.sensitivity).toBeUndefined();
    expect(result!.onSuspicion).toBeUndefined();
    expect(result!.halfLifeSoft).toBeUndefined();
  });

  // handleSplitWrite: F-37 fix — throws UNSUPPORTED_ENV when no IDB adapter set
  it('should throw UNSUPPORTED_ENV when split mode is used without an IDB adapter', async () => {
    const adapter = new SessionStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    // F-37: IDB is required for split mode — throws instead of writing split: prefix
    await expect(adapter.setItem('split-no-idb-2', 'val', { mode: 'split' })).rejects.toMatchObject(
      {
        code: 'UNSUPPORTED_ENV',
      },
    );
  });

  // wipeHighSensitivity: skips split: and ref: prefixed entries (covers lines 148-163)
  it('should skip split: and ref: entries during wipeHighSensitivity', async () => {
    const config = resolveConfig({ debug: true });
    const events = new TesseraEmitter();
    const idbAdapter = new IndexedDbAdapter(config, session, events);
    const adapter = new SessionStorageAdapter(config, session, events);
    adapter.setIdbAdapter(idbAdapter);

    // split-mode item → stored as split:... prefix
    await adapter.setItem('split-wipe', 'split-val', { mode: 'split' });
    // claim-mode item → stored as ref:... prefix
    await adapter.setItem('claim-wipe', 'claim-val', { mode: 'claim' });
    // high-sensitivity direct item → should be wiped
    await adapter.setItem('high-wipe', 'high-val', { sensitivity: 'high' });

    const rawSplitKey = await adapter.getRawKey!('split-wipe');
    const rawClaimKey = await adapter.getRawKey!('claim-wipe');

    const wiped: string[] = [];
    await adapter.wipeHighSensitivity(wiped);

    expect(wiped.some((w) => w.includes('session:'))).toBe(true);
    // split: and ref: entries must survive (skipped by wipeHighSensitivity)
    expect(sessionStorage.getItem(rawSplitKey)).not.toBeNull();
    expect(sessionStorage.getItem(rawClaimKey)).not.toBeNull();
    // high-sensitivity direct item must be gone
    expect(await adapter.getItem('high-wipe')).toBeNull();
  });

  // getItem: storageKey null branch (covers line 73) — session has key but no HMAC key
  it('should return null from getItem when rotateKeyNameSafe returns null (no HMAC key)', async () => {
    const testSession = new KeySession();
    const salt = await getSalt();
    const key = await deriveKey('246813', salt);
    testSession.setKey(key, 900_000);
    // Intentionally no setHmacKey → rotateKeyNameSafe returns null while getKeySafe succeeds

    const adapter = new SessionStorageAdapter(resolveConfig(), testSession, new TesseraEmitter());
    const result = await adapter.getItem('any-key');
    expect(result).toBeNull();
    testSession.reset();
  });

  // buildMeta false branches: low sensitivity has no ttl/maxReads/halfLifeHard defaults
  it('should store and retrieve a low-sensitivity item (no ttl/maxReads/halfLife defaults)', async () => {
    const adapter = new SessionStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('low-sens', 'low-val', { sensitivity: 'low' });
    const result = await adapter.getItem('low-sens');
    expect(result).toBe('low-val');
  });

  // addHoneyKeys: set a honey manager that is enabled with count > 0
  it('should add honey keys when honey manager is enabled', async () => {
    const honeySet = new Set<string>();
    const fakeMgr = {
      isEnabled: true,
      allKeys: (_backend: string) => [] as string[],
      generateHoneyKeys: (_backend: string, _existing: string[], needed: number) => {
        const keys = Array.from({ length: needed }, (_, i) => `honey_${i}`);
        for (const k of keys) honeySet.add(k);
        return keys;
      },
      isHoney: (_backend: string, key: string) => honeySet.has(key),
      isDecoyAlias: () => false,
      allDecoyAliases: () => [] as string[],
      assignDecoyAlias: () => {},
      remove: () => {},
      clearBackend: () => {},
    };
    // Override config to request 2 honey keys
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const adapterWithHoney = new SessionStorageAdapter(config, session, new TesseraEmitter());
    adapterWithHoney.setHoneyManager(fakeMgr);
    await adapterWithHoney.setItem('h-key', 'h-val');
    // Honey keys should appear in sessionStorage
    expect(sessionStorage.getItem('honey_0')).not.toBeNull();
  });

  // getItem with decoy alias triggers honey hit (covers session-storage.ts lines 74-75)
  it('getItem returns null and records honey hit when key is a decoy alias', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');
    const mgr = new HoneyKeyManager(config);
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new SessionStorageAdapter(config, session, events, suspicion);
    adapter.setHoneyManager(mgr);

    await adapter.setItem('real-key', 'real-value');

    const aliases = mgr.allDecoyAliases('session');
    expect(aliases.length).toBeGreaterThan(0);

    let honeyHits = 0;
    events.on('honey-triggered', () => {
      honeyHits++;
    });

    const result = await adapter.getItem(aliases[0]!);
    expect(result).toBeNull();
    expect(honeyHits).toBe(1);
    suspicion.destroy();
  });

  // exportItem with decoy alias triggers honey hit (covers session-storage.ts lines 274-275)
  it('exportItem returns null and records honey hit when alias is a decoy', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');
    const mgr = new HoneyKeyManager(config);
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new SessionStorageAdapter(config, session, events, suspicion);
    adapter.setHoneyManager(mgr);

    await adapter.setItem('real-key', 'real-value');

    const aliases = mgr.allDecoyAliases('session');
    expect(aliases.length).toBeGreaterThan(0);

    let honeyHits = 0;
    events.on('honey-triggered', () => {
      honeyHits++;
    });

    const exported = await adapter.exportItem(aliases[0]!);
    expect(exported).toBeNull();
    expect(honeyHits).toBe(1);
    suspicion.destroy();
  });

  // claim mode + honey keys: writeHoneyKeysInterleaved writes honey entries alongside the claim
  it('claim mode with honey keys writes honey entries in sessionStorage', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const events = new TesseraEmitter();
    const idbAdapter = new IndexedDbAdapter(config, session, events);
    const adapter = new SessionStorageAdapter(config, session, events);
    adapter.setIdbAdapter(idbAdapter);
    const { HoneyKeyManager } = await import('../../src/storage/honey');
    const mgr = new HoneyKeyManager(config);
    adapter.setHoneyManager(mgr);

    await adapter.setItem('claim-ss-key', 'claim-ss-val', { mode: 'claim' });

    expect(await adapter.getItem('claim-ss-key')).toBe('claim-ss-val');
    const honeyKeys = mgr.allKeys('session');
    expect(honeyKeys.length).toBe(2);
  });

  // ── maxValueBytes and onBeforeWrite ──────────────────────────────────────────

  it('throws VALIDATION_ERROR when sessionStorage value exceeds maxValueBytes', async () => {
    const cfg = resolveConfig({ maxValueBytes: 5 });
    const events = new TesseraEmitter();
    const adapter = new SessionStorageAdapter(cfg, session, events);
    const { TesseraErrorCode } = await import('../../src/types');
    await expect(adapter.setItem('k', 'this-is-longer-than-5-bytes')).rejects.toMatchObject({
      code: TesseraErrorCode.VALIDATION_ERROR,
    });
  });

  it('throws VALIDATION_ERROR when onBeforeWrite returns false for sessionStorage', async () => {
    const cfg = resolveConfig({ onBeforeWrite: () => false });
    const events = new TesseraEmitter();
    const adapter = new SessionStorageAdapter(cfg, session, events);
    const { TesseraErrorCode } = await import('../../src/types');
    await expect(adapter.setItem('k', 'v')).rejects.toMatchObject({
      code: TesseraErrorCode.VALIDATION_ERROR,
    });
  });

  it('allows sessionStorage write when onBeforeWrite returns true', async () => {
    const cfg = resolveConfig({ onBeforeWrite: () => true });
    const events = new TesseraEmitter();
    const adapter = new SessionStorageAdapter(cfg, session, events);
    await expect(adapter.setItem('k', 'v')).resolves.not.toThrow();
  });
});
