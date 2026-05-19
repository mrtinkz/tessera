import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { LocalStorageAdapter } from '../../src/adapters/local-storage';
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

describe('LocalStorageAdapter', () => {
  beforeEach(async () => {
    localStorage.clear();
    await setupSession();
  });

  afterEach(() => {
    session.reset();
    vi.restoreAllMocks();
  });

  it('should encrypt and decrypt values', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('hello', 'world');
    const value = await adapter.getItem('hello');
    expect(value).toBe('world');
    // Raw value must be ciphertext, not plaintext
    expect(localStorage.getItem('hello')).not.toBe('world');
  });

  it('should return null for missing keys', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const value = await adapter.getItem('nonexistent');
    expect(value).toBeNull();
  });

  it('should remove items', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('temp', 'data');
    await adapter.removeItem('temp');
    expect(await adapter.getItem('temp')).toBeNull();
  });

  it('should encrypt all keys with name rotation', async () => {
    const config = resolveConfig({ debug: true });
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(config, session, events);
    await adapter.setItem('plain', 'visible');
    await adapter.setItem('secure', 'hidden');

    const rawKeyPlain = await adapter.getRawKey!('plain');
    const rawKeySecure = await adapter.getRawKey!('secure');
    expect(localStorage.getItem(rawKeyPlain)).not.toBeNull();
    expect(localStorage.getItem(rawKeySecure)).not.toBeNull();
    expect(await adapter.getItem('plain')).toBe('visible');
    expect(await adapter.getItem('secure')).toBe('hidden');
  });

  it('should clear all items', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('a', '1');
    await adapter.setItem('b', '2');
    await adapter.clear();
    expect(await adapter.getItem('a')).toBeNull();
    expect(await adapter.getItem('b')).toBeNull();
  });

  it('should list stored keys', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('x', '1');
    await adapter.setItem('y', '2');
    const keys = await adapter.keys();
    expect(keys).toContain('x');
    expect(keys).toContain('y');
  });

  it('should return null when vault is locked', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('key', 'value');
    session.lock();
    const result = await adapter.getItem('key');
    expect(result).toBeNull();
  });

  it('should handle special characters and unicode values', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const data = '{"emoji":"🔐","accents":"café"}';
    await adapter.setItem('data', data);
    expect(await adapter.getItem('data')).toBe(data);
  });

  // TTL expiry: write with 1ms TTL, wait, then read → null
  it('should return null and remove item when TTL has expired', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('ttl-key', 'expires-fast', { ttl: 1 });
    await new Promise((r) => setTimeout(r, 10));
    const result = await adapter.getItem('ttl-key');
    expect(result).toBeNull();
  });

  it('should emit key-expired event on TTL expiry', async () => {
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('key-expired', handler);
    await adapter.setItem('ttl-ev', 'data', { ttl: 1 });
    await new Promise((r) => setTimeout(r, 10));
    await adapter.getItem('ttl-ev');
    expect(handler).toHaveBeenCalled();
  });

  // maxReads: write with maxReads=1, read once (ok), read twice (null)
  it('should return null when maxReads is exhausted', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('mr-key', 'value', { maxReads: 1 });
    const first = await adapter.getItem('mr-key');
    expect(first).toBe('value');
    // After one read the readCount equals maxReads — second read should remove it
    const second = await adapter.getItem('mr-key');
    expect(second).toBeNull();
  });

  it('should emit max-reads-reached event', async () => {
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('max-reads-reached', handler);
    await adapter.setItem('mr-ev', 'data', { maxReads: 1 });
    await adapter.getItem('mr-ev'); // first read: ok, updates readCount to 1
    await adapter.getItem('mr-ev'); // second read: readCount==maxReads → fires event
    expect(handler).toHaveBeenCalled();
  });

  // halfLife hard: set a 1ms hard half-life, wait, then read → null
  it('should return null when halfLife.hard has elapsed', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('hl-hard', 'v', { halfLife: { hard: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    const result = await adapter.getItem('hl-hard');
    expect(result).toBeNull();
  });

  // halfLife soft: set a 1ms soft half-life without a reconfirm key → throws RECONFIRMATION_REQUIRED
  it('should throw RECONFIRMATION_REQUIRED when halfLife.soft has elapsed and no reconfirm key', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('hl-soft', 'v', { halfLife: { soft: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    // no reconfirm key set on session
    await expect(adapter.getItem('hl-soft')).rejects.toMatchObject({
      code: 'RECONFIRMATION_REQUIRED',
    });
  });

  it('should emit reconfirmation-required event on soft half-life', async () => {
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(resolveConfig(), session, events);
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

  // Legacy format: no dot in stored value (old encrypted value only, no metadata)
  it('should decrypt a legacy-format value (no dot separator)', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    // Write a legacy-format value directly using encryptWithSalt (no metadata wrapper)
    const cryptoKey = session.getKey();
    const legacyEncrypted = await encryptWithSalt(cryptoKey, 'legacy-value');
    // Store it at the raw key location
    const rawKey = await session.rotateKeyName('legacy-key');
    localStorage.setItem(rawKey, legacyEncrypted);

    const result = await adapter.getItem('legacy-key');
    expect(result).toBe('legacy-value');
  });

  // Legacy format: decrypt fails (corrupt non-dot value)
  it('should return null for corrupt legacy-format value', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const rawKey = await session.rotateKeyName('corrupt-legacy');
    localStorage.setItem(rawKey, 'NOTVALIDBASE64ORENCRYPTED!!');

    const result = await adapter.getItem('corrupt-legacy');
    expect(result).toBeNull();
  });

  // meta HMAC failure (corrupt meta part before the dot)
  it('should emit hmac-failure and remove item when meta decryption fails', async () => {
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(resolveConfig({ debug: true }), session, events);
    const handler = vi.fn();
    events.on('hmac-failure', handler);

    await adapter.setItem('meta-corrupt', 'val');
    const rawKey = await adapter.getRawKey!('meta-corrupt');
    const stored = localStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    // Corrupt only the meta (before the dot)
    localStorage.setItem(rawKey, 'INVALIDBASE64GARBAGE==' + stored.slice(dotIdx));

    const result = await adapter.getItem('meta-corrupt');
    expect(result).toBeNull();
    expect(handler).toHaveBeenCalled();
  });

  // applyOnSuspicion with 'lock' action
  it('should lock the session when onSuspicion is "lock" and value HMAC fails', async () => {
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(resolveConfig({ debug: true }), session, events);
    // Write a valid item with onSuspicion=lock
    await adapter.setItem('sus-lock', 'secure', { onSuspicion: 'lock' });

    // Corrupt the stored value so decryption fails on the value portion
    const rawKey = await adapter.getRawKey!('sus-lock');
    const stored = localStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    // Replace the value portion with garbage (keep meta intact)
    localStorage.setItem(rawKey, stored.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==');

    await adapter.getItem('sus-lock');
    expect(session.isLocked()).toBe(true);
  });

  // applyOnSuspicion with 'throw' action (key stays, returns null)
  it('should leave key intact when onSuspicion is "throw" and value HMAC fails', async () => {
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(resolveConfig({ debug: true }), session, events);
    await adapter.setItem('sus-throw', 'secure', { onSuspicion: 'throw' });

    const rawKey = await adapter.getRawKey!('sus-throw');
    const stored = localStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    localStorage.setItem(rawKey, stored.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==');

    const result = await adapter.getItem('sus-throw');
    expect(result).toBeNull();
    // Key should still exist in localStorage (not wiped)
    expect(localStorage.getItem(rawKey)).not.toBeNull();
  });

  // applyOnSuspicion with default 'wipe' action
  it('should wipe the key when onSuspicion is "wipe" (default) and value HMAC fails', async () => {
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(resolveConfig({ debug: true }), session, events);
    await adapter.setItem('sus-wipe', 'secure', { onSuspicion: 'wipe' });

    const rawKey = await adapter.getRawKey!('sus-wipe');
    const stored = localStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    localStorage.setItem(rawKey, stored.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==');

    const result = await adapter.getItem('sus-wipe');
    expect(result).toBeNull();
    expect(localStorage.getItem(rawKey)).toBeNull();
  });

  // honeyManager.isHoney() returning true → records honey hit (lines 68-70)
  it('should return null and record honey hit when key is a honey key', async () => {
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(resolveConfig(), session, events);
    const honeyMgr = {
      isEnabled: false,
      allKeys: () => [] as string[],
      generateHoneyKeys: () => [] as string[],
      isHoney: (_backend: string, _key: string) => true, // always a honey key
      isDecoyAlias: () => false,
      allDecoyAliases: () => [] as string[],
      assignDecoyAlias: () => {},
      remove: () => {},
      clearBackend: () => {},
    };
    adapter.setHoneyManager(honeyMgr);

    await adapter.setItem('honey-test', 'honey-val');
    const result = await adapter.getItem('honey-test');
    // With isHoney always returning true, getItem should return null
    expect(result).toBeNull();
  });

  // readCount NaN branch: inject a metadata with non-finite readCount
  it('should normalise non-finite readCount in metadata', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const cryptoKey = session.getKey();
    // Create metadata with NaN readCount
    const meta = JSON.stringify({
      writeTime: Date.now(),
      readCount: Number.NaN,
      sensitivity: 'low',
      onSuspicion: 'wipe',
    });
    const encMeta = await encryptWithSalt(cryptoKey, meta);
    const encVal = await encryptWithSalt(cryptoKey, 'nan-count-val');
    const rawKey = await session.rotateKeyName('nan-count');
    localStorage.setItem(rawKey, `${encMeta}.${encVal}`);

    const result = await adapter.getItem('nan-count');
    // Should return the value (readCount gets normalised to 0)
    expect(result).toBe('nan-count-val');
  });

  // clear() with honeyManager that has clearBackend (covers lines 153-154)
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
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    adapter.setHoneyManager(fakeMgr);
    await adapter.clear();
    expect(clearBackendMock).toHaveBeenCalledWith('local');
  });

  // Rate limit 1.5x exceeded → getItem returns null (covers local-storage.ts lines 56, 58-59)
  it('should return null when suspicion rate limit is exceeded above 1.5x threshold', async () => {
    // Use a very low callsPerSecond limit so we can exceed 1.5x with a few rapid calls
    const config = resolveConfig({
      suspicion: {
        rateLimit: { callsPerSecond: 2, scorePerExcess: 1 },
        thresholds: { lockdown: 10_000 },
      },
    });
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new LocalStorageAdapter(config, session, events, suspicion);
    await adapter.setItem('rate-key', 'rate-val');

    // Make >3 rapid calls (1.5 * 2 = 3, so >3 means 4+ calls) within the 1s window
    let finalResult: string | null = null;
    for (let i = 0; i < 5; i++) {
      finalResult = await adapter.getItem('rate-key');
    }
    // At some point it returns null (when rate exceeds 1.5x limit)
    expect(finalResult).toBeNull();
    suspicion.destroy();
  });

  // wipeHighSensitivity JSON.parse catch branch: write non-JSON meta to storage
  it('should skip items with non-JSON meta in wipeHighSensitivity', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('valid', 'val', { sensitivity: 'high' });

    // Inject a t_ prefixed item with a dot but non-JSON decryptable meta
    // Use encryptWithSalt to produce a valid ciphertext wrapping non-JSON text
    const cryptoKey = session.getKey();
    const nonJsonMeta = await encryptWithSalt(cryptoKey, 'NOT-JSON-AT-ALL {{{');
    const encVal = await encryptWithSalt(cryptoKey, 'ignored');
    localStorage.setItem('t_badfakekeyAAAAAAAAAAAAAAAAAAAA', `${nonJsonMeta}.${encVal}`);

    // wipeHighSensitivity should skip the bad item and still wipe valid ones
    const wiped: string[] = [];
    await adapter.wipeHighSensitivity(wiped);
    // The valid high-sensitivity item is still wiped
    expect(wiped.some((w) => w.includes('session:') || w.includes('local:'))).toBe(true);
  });

  // addHoneyKeys: each set generates `count` new honey keys (cumulative)
  it('should generate new honey keys on every set, accumulating per write', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');
    const mgr = new HoneyKeyManager(config);
    const adapter = new LocalStorageAdapter(config, session, new TesseraEmitter());
    adapter.setHoneyManager(mgr);

    // First setItem: generates 2 honey keys
    await adapter.setItem('hk-first-ls', 'v1');
    expect(mgr.allKeys('local').length).toBe(2);

    // Second setItem: generates 2 more honey keys (cumulative: 4 total)
    await adapter.setItem('hk-second-ls', 'v2');
    expect(mgr.allKeys('local').length).toBe(4);
  });

  // getRawKey returns the developer key unchanged when session is locked
  it('should return the raw developer key unchanged when session is locked', async () => {
    const adapter = new LocalStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    session.lock();
    const result = await adapter.getRawKey!('my-key');
    expect(result).toBe('my-key');
  });

  it('getRawKey throws when debug mode is not enabled', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await expect(adapter.getRawKey!('any-key')).rejects.toThrow('debug mode');
  });

  it('exportItem returns value and metadata without incrementing readCount', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('exp-key', 'exp-value');
    const exported1 = await adapter.exportItem!('exp-key');
    expect(exported1).not.toBeNull();
    expect(exported1!.value).toBe('exp-value');
    expect(exported1!.readCount).toBe(0);
    const exported2 = await adapter.exportItem!('exp-key');
    expect(exported2!.readCount).toBe(0);
  });

  it('exportItem returns null for unknown key', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const result = await adapter.exportItem!('nonexistent-key');
    expect(result).toBeNull();
  });

  it('exportItem returns null when halfLifeSoft has elapsed', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('exp-soft', 'v', { halfLife: { soft: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    const result = await adapter.exportItem!('exp-soft');
    expect(result).toBeNull();
  });

  it('exportItem returns null when maxReads is exhausted', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('exp-mr', 'v', { maxReads: 1 });
    await adapter.getItem('exp-mr');
    const result = await adapter.exportItem!('exp-mr');
    expect(result).toBeNull();
  });

  it('exportItem returns null when halfLife.hard has elapsed', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('exp-hard', 'v', { halfLife: { hard: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    const result = await adapter.exportItem!('exp-hard');
    expect(result).toBeNull();
  });

  it('exportItem returns null when value HMAC is corrupt', async () => {
    const adapter = new LocalStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    await adapter.setItem('exp-corrupt', 'v');
    const rawKey = await adapter.getRawKey!('exp-corrupt');
    const stored = localStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    localStorage.setItem(rawKey, stored.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==');
    const result = await adapter.exportItem!('exp-corrupt');
    expect(result).toBeNull();
  });

  it('exportItem returns null when meta HMAC is corrupt', async () => {
    const adapter = new LocalStorageAdapter(
      resolveConfig({ debug: true }),
      session,
      new TesseraEmitter(),
    );
    await adapter.setItem('exp-meta-corrupt', 'v');
    const rawKey = await adapter.getRawKey!('exp-meta-corrupt');
    const stored = localStorage.getItem(rawKey)!;
    const dotIdx = stored.indexOf('.');
    localStorage.setItem(rawKey, 'INVALIDBASE64GARBAGE==' + stored.slice(dotIdx));
    const result = await adapter.exportItem!('exp-meta-corrupt');
    expect(result).toBeNull();
  });

  it('exportItem returns null when TTL has expired', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('exp-ttl', 'v', { ttl: 1 });
    await new Promise((r) => setTimeout(r, 10));
    const result = await adapter.exportItem!('exp-ttl');
    expect(result).toBeNull();
  });

  it('exportItem normalises NaN readCount in metadata', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const cryptoKey = session.getKey();
    const meta = JSON.stringify({
      writeTime: Date.now(),
      readCount: Number.NaN,
      sensitivity: 'low',
      onSuspicion: 'wipe',
    });
    const encMeta = await encryptWithSalt(cryptoKey, meta);
    const encVal = await encryptWithSalt(cryptoKey, 'nan-exp-val');
    const rawKey = await session.rotateKeyName('exp-nan-count');
    localStorage.setItem(rawKey, `${encMeta}.${encVal}`);
    const result = await adapter.exportItem!('exp-nan-count');
    expect(result).not.toBeNull();
    expect(result!.readCount).toBe(0);
  });

  it('exportItem omits optional fields absent from metadata', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const cryptoKey = session.getKey();
    const meta = JSON.stringify({ writeTime: Date.now(), readCount: 0 });
    const encMeta = await encryptWithSalt(cryptoKey, meta);
    const encVal = await encryptWithSalt(cryptoKey, 'bare-val');
    const rawKey = await session.rotateKeyName('exp-bare');
    localStorage.setItem(rawKey, `${encMeta}.${encVal}`);
    const result = await adapter.exportItem!('exp-bare');
    expect(result).not.toBeNull();
    expect(result!.sensitivity).toBeUndefined();
    expect(result!.onSuspicion).toBeUndefined();
    expect(result!.halfLifeSoft).toBeUndefined();
  });

  // buildMeta false branches: low sensitivity has no ttl/maxReads/halfLifeHard defaults
  it('should store and retrieve a low-sensitivity item (no ttl/maxReads/halfLife defaults)', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('low-sens', 'low-val', { sensitivity: 'low' });
    const result = await adapter.getItem('low-sens');
    expect(result).toBe('low-val');
  });

  // wipeHighSensitivity: items with 'high' sensitivity are removed
  it('should wipe high-sensitivity items via wipeHighSensitivity', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('low', 'lo-val', { sensitivity: 'low' });
    await adapter.setItem('high', 'hi-val', { sensitivity: 'high' });
    const wiped: string[] = [];
    await adapter.wipeHighSensitivity(wiped);
    expect(wiped.some((w) => w.includes('local:'))).toBe(true);
    // High-sensitivity item gone; low still readable
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
    const adapter = new LocalStorageAdapter(config, session, new TesseraEmitter());
    adapter.setHoneyManager(mgr);

    await adapter.setItem('low-key', 'lo', { sensitivity: 'low' });
    await adapter.setItem('high-key', 'hi', { sensitivity: 'high' });
    const honeyKeysBefore = mgr.allKeys('local');
    expect(honeyKeysBefore.length).toBe(4);

    // Confirm all three kinds of t_ entry exist before wipe
    const tKeysBefore = Object.keys(localStorage).filter((k) => k.startsWith('t_'));
    expect(tKeysBefore.length).toBeGreaterThanOrEqual(3); // 2 real + 4 honey

    const wiped: string[] = [];
    await adapter.wipeAll(wiped);

    // No t_ entries remain
    const tKeysAfter = Object.keys(localStorage).filter((k) => k.startsWith('t_'));
    expect(tKeysAfter.length).toBe(0);

    // wiped list contains all removed keys
    expect(wiped.length).toBeGreaterThanOrEqual(3);
    expect(wiped.every((w) => w.startsWith('local:'))).toBe(true);

    // Honey manager registry cleared
    expect(mgr.allKeys('local').length).toBe(0);

    // Reads return null after wipeAll
    expect(await adapter.getItem('low-key')).toBeNull();
    expect(await adapter.getItem('high-key')).toBeNull();
  });

  // cleanOrphanedHoneyKeys: wipes orphaned honey entries, leaves real keys intact
  it('cleanOrphanedHoneyKeys wipes orphaned honey entries but preserves real keys', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');

    // Session 1: write real key + honey keys
    const mgr1 = new HoneyKeyManager(config);
    const adapter1 = new LocalStorageAdapter(config, session, new TesseraEmitter());
    adapter1.setHoneyManager(mgr1);
    await adapter1.setItem('persist', 'still-here', { sensitivity: 'low' });
    const orphanKeys = mgr1.allKeys('local');
    expect(orphanKeys.length).toBe(2);

    // Session 2: fresh manager (simulates page reload — registry is empty)
    const mgr2 = new HoneyKeyManager(config);
    const adapter2 = new LocalStorageAdapter(config, session, new TesseraEmitter());
    adapter2.setHoneyManager(mgr2);

    // Orphans exist in storage but mgr2 doesn't know about them
    expect(orphanKeys.every((k) => localStorage.getItem(k) !== null)).toBe(true);

    await adapter2.cleanOrphanedHoneyKeys();

    // Orphaned honey keys are wiped
    for (const k of orphanKeys) {
      expect(localStorage.getItem(k)).toBeNull();
    }

    // Real key is unaffected
    expect(await adapter2.getItem('persist')).toBe('still-here');
  });

  // cleanOrphanedHoneyKeys: skips live honey keys tracked in current session
  it('cleanOrphanedHoneyKeys skips honey keys registered in the current session', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');
    const mgr = new HoneyKeyManager(config);
    const adapter = new LocalStorageAdapter(config, session, new TesseraEmitter());
    adapter.setHoneyManager(mgr);

    await adapter.setItem('live-key', 'val');
    const liveHoneyKeys = mgr.allKeys('local');
    expect(liveHoneyKeys.length).toBe(2);

    await adapter.cleanOrphanedHoneyKeys();

    // Live honey keys must NOT be wiped
    for (const k of liveHoneyKeys) {
      expect(localStorage.getItem(k)).not.toBeNull();
    }
  });

  // cleanOrphanedHoneyKeys: returns immediately when vault is locked
  it('cleanOrphanedHoneyKeys does nothing when vault is locked', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('k', 'v');
    session.lock();
    const tKeysBefore = Object.keys(localStorage).filter((k) => k.startsWith('t_'));
    await adapter.cleanOrphanedHoneyKeys();
    const tKeysAfter = Object.keys(localStorage).filter((k) => k.startsWith('t_'));
    expect(tKeysAfter).toEqual(tKeysBefore);
  });

  it('getItem returns null and records honey hit when key is a decoy alias', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');
    const mgr = new HoneyKeyManager(config);
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new LocalStorageAdapter(config, session, events, suspicion);
    adapter.setHoneyManager(mgr);
    await adapter.setItem('real-key', 'real-value');
    const aliases = mgr.allDecoyAliases('local');
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

  it('exportItem returns null and records honey hit when alias is a decoy', async () => {
    const config = resolveConfig({ honeyKeys: { count: 2 } } as Parameters<
      typeof resolveConfig
    >[0]);
    const { HoneyKeyManager } = await import('../../src/storage/honey');
    const mgr = new HoneyKeyManager(config);
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new LocalStorageAdapter(config, session, events, suspicion);
    adapter.setHoneyManager(mgr);
    await adapter.setItem('real-key', 'real-value');
    const aliases = mgr.allDecoyAliases('local');
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

  // ── P1: exportItem is a required method (not optional) ────────────────────────

  it('exportItem is defined and callable on the adapter (P1)', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    // The method must exist (not optional) — call it for a missing key
    expect(typeof adapter.exportItem).toBe('function');
    const result = await adapter.exportItem('nonexistent');
    expect(result).toBeNull();
  });

  // ── P3: maxValueBytes and onBeforeWrite validation ────────────────────────────

  it('throws VALIDATION_ERROR when value exceeds maxValueBytes (P3)', async () => {
    const config = resolveConfig({ maxValueBytes: 5 });
    const adapter = new LocalStorageAdapter(config, session, new TesseraEmitter());
    await expect(adapter.setItem('k', 'this-is-longer-than-5-bytes')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
    });
  });

  it('allows write when value is within maxValueBytes (P3)', async () => {
    const config = resolveConfig({ maxValueBytes: 1000 });
    const adapter = new LocalStorageAdapter(config, session, new TesseraEmitter());
    await expect(adapter.setItem('k', 'ok')).resolves.not.toThrow();
    expect(await adapter.getItem('k')).toBe('ok');
  });

  it('throws VALIDATION_ERROR when onBeforeWrite returns false (P3)', async () => {
    const config = resolveConfig({ onBeforeWrite: (_k, _v) => false });
    const adapter = new LocalStorageAdapter(config, session, new TesseraEmitter());
    await expect(adapter.setItem('blocked', 'value')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
    });
  });

  it('allows write when onBeforeWrite returns true (P3)', async () => {
    const calls: string[] = [];
    const config = resolveConfig({
      onBeforeWrite: (k) => {
        calls.push(k);
        return true;
      },
    });
    const adapter = new LocalStorageAdapter(config, session, new TesseraEmitter());
    await adapter.setItem('mykey', 'val');
    expect(calls).toContain('mykey');
    expect(await adapter.getItem('mykey')).toBe('val');
  });

  it('onBeforeWrite receives the pre-rotation alias and plaintext value (P3)', async () => {
    let capturedKey = '';
    let capturedValue = '';
    const config = resolveConfig({
      onBeforeWrite: (k, v) => {
        capturedKey = k;
        capturedValue = v;
        return true;
      },
    });
    const adapter = new LocalStorageAdapter(config, session, new TesseraEmitter());
    await adapter.setItem('aliasKey', 'plainValue');
    expect(capturedKey).toBe('aliasKey');
    expect(capturedValue).toBe('plainValue');
  });
});
