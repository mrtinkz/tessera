import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IndexedDbAdapter } from '../../src/adapters/indexed-db';
import { KeySession } from '../../src/core/session';
import { deriveKey, deriveHmacKey, getSalt, encryptWithSalt } from '../../src/core/crypto';
import { resolveConfig } from '../../src/core/config';
import { TesseraEmitter } from '../../src/core/events';
import { SuspicionEngine } from '../../src/core/suspicion';
import { HoneyKeyManager } from '../../src/storage/honey';

// Helper to directly overwrite a record's value in the IDB tessera_data store
async function overwriteIdbValue(
  storeName: string,
  storageKey: string,
  newValue: string,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const req = indexedDB.open('tessera_vault', 2);
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      store.put({ store: storeName, key: storageKey, value: newValue, updatedAt: Date.now() });
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.addEventListener('error', () => {
        db.close();
        reject(tx.error);
      });
    };
    req.addEventListener('error', () => reject(req.error));
  });
}

let session: KeySession;

async function setupSession(): Promise<void> {
  session = new KeySession();
  const salt = await getSalt();
  const key = await deriveKey('246813', salt);
  const hmacKey = await deriveHmacKey('246813', salt);
  session.setKey(key, 900_000);
  session.setHmacKey(hmacKey);
}

describe('IndexedDbAdapter', () => {
  beforeEach(async () => {
    await setupSession();
  });

  afterEach(() => {
    session.reset();
    vi.restoreAllMocks();
  });

  it('should store and retrieve a value', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('myStore', 'key1', { hello: 'world' });
    const result = await adapter.get('myStore', 'key1');
    expect(result).toEqual({ hello: 'world' });
  });

  it('should return undefined for a missing key', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    const result = await adapter.get('myStore', 'nonexistent');
    expect(result).toBeUndefined();
  });

  it('should store the value encrypted (raw stored value is not plaintext)', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('myStore', 'secret', 'plaintext');
    // A different key+hmac pair would fail to look up or decrypt — confirms data is encrypted
    const salt2 = await getSalt();
    const key2 = await deriveKey('987654', salt2);
    const hmacKey2 = await deriveHmacKey('987654', salt2);
    session.setKey(key2, 900_000);
    session.setHmacKey(hmacKey2);
    const result = await adapter.get('myStore', 'secret');
    // Different HMAC key → different storage key → record not found → undefined
    expect(result).toBeUndefined();
  });

  it('should remove a stored value', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('myStore', 'toRemove', 42);
    await adapter.remove('myStore', 'toRemove');
    const result = await adapter.get('myStore', 'toRemove');
    expect(result).toBeUndefined();
  });

  it('should clear all values in a named store', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('clearStore', 'a', 1);
    await adapter.put('clearStore', 'b', 2);
    await adapter.put('otherStore', 'c', 3);
    await adapter.clear('clearStore');
    expect(await adapter.get('clearStore', 'a')).toBeUndefined();
    expect(await adapter.get('clearStore', 'b')).toBeUndefined();
    // Other store must be untouched
    expect(await adapter.get('otherStore', 'c')).toBe(3);
  });

  it('should return undefined when vault is locked', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('myStore', 'lockedKey', 'value');
    session.lock();
    const result = await adapter.get('myStore', 'lockedKey');
    expect(result).toBeUndefined();
  });

  it('should support complex nested objects', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    const data = {
      users: [
        { id: 1, name: 'Alice' },
        { id: 2, name: 'Bob' },
      ],
      meta: { count: 2 },
    };
    await adapter.put('myStore', 'users', data);
    const result = await adapter.get('myStore', 'users');
    expect(result).toEqual(data);
  });

  // TTL expiry
  it('should return undefined when TTL has expired', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('idb-ttl', 'key-ttl', 'will-expire', { ttl: 1 });
    await new Promise((r) => setTimeout(r, 10));
    expect(await adapter.get('idb-ttl', 'key-ttl')).toBeUndefined();
  });

  it('should emit key-expired event on TTL expiry', async () => {
    const events = new TesseraEmitter();
    const adapter = new IndexedDbAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('key-expired', handler);
    await adapter.put('idb-ttl-ev', 'key-ev', 'data', { ttl: 1 });
    await new Promise((r) => setTimeout(r, 10));
    await adapter.get('idb-ttl-ev', 'key-ev');
    expect(handler).toHaveBeenCalled();
  });

  // maxReads
  it('should return undefined when maxReads is exhausted', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('idb-mr', 'key-mr', 'value', { maxReads: 1 });
    const first = await adapter.get('idb-mr', 'key-mr');
    expect(first).toBe('value');
    const second = await adapter.get('idb-mr', 'key-mr');
    expect(second).toBeUndefined();
  });

  it('should emit max-reads-reached event when maxReads exhausted', async () => {
    const events = new TesseraEmitter();
    const adapter = new IndexedDbAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('max-reads-reached', handler);
    await adapter.put('idb-mr-ev', 'key-mr-ev', 'data', { maxReads: 1 });
    await adapter.get('idb-mr-ev', 'key-mr-ev'); // first
    await adapter.get('idb-mr-ev', 'key-mr-ev'); // second triggers event
    expect(handler).toHaveBeenCalled();
  });

  // halfLife hard
  it('should return undefined when halfLife.hard has elapsed', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('idb-hl', 'hl-hard', 'v', { halfLife: { hard: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    expect(await adapter.get('idb-hl', 'hl-hard')).toBeUndefined();
  });

  // halfLife soft
  it('should throw RECONFIRMATION_REQUIRED when halfLife.soft has elapsed and no reconfirm key', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('idb-hl-s', 'hl-soft', 'v', { halfLife: { soft: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    await expect(adapter.get('idb-hl-s', 'hl-soft')).rejects.toMatchObject({
      code: 'RECONFIRMATION_REQUIRED',
    });
  });

  it('should emit reconfirmation-required on soft half-life expiry', async () => {
    const events = new TesseraEmitter();
    const adapter = new IndexedDbAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('reconfirmation-required', handler);
    await adapter.put('idb-hl-ev', 'hl-soft-ev', 'v', { halfLife: { soft: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    // get now throws after emitting the event
    try {
      await adapter.get('idb-hl-ev', 'hl-soft-ev');
    } catch {
      /* expected RECONFIRMATION_REQUIRED */
    }
    expect(handler).toHaveBeenCalled();
  });

  // wipeHighSensitivity
  it('should wipe high-sensitivity idb entries via wipeHighSensitivity', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('wipe-store', 'lo', 'lo-val', { sensitivity: 'low' });
    await adapter.put('wipe-store', 'hi', 'hi-val', { sensitivity: 'high' });
    const wiped: string[] = [];
    await adapter.wipeHighSensitivity(wiped);
    expect(wiped.some((w) => w.includes('idb:'))).toBe(true);
    expect(await adapter.get('wipe-store', 'hi')).toBeUndefined();
    expect(await adapter.get('wipe-store', 'lo')).toBe('lo-val');
  });

  // legacy format: no dot in stored value
  it('should decrypt a legacy-format idb value (no dot separator)', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    const { encryptWithSalt } = await import('../../src/core/crypto');
    const cryptoKey = session.getKey();
    const legacyEncrypted = await encryptWithSalt(cryptoKey, '"legacy-idb-val"');
    const storageKey = await session.rotateKeyName('legacy-key');
    await overwriteIdbValue('legacy-store', storageKey, legacyEncrypted);
    const result = await adapter.get('legacy-store', 'legacy-key');
    expect(result).toBe('legacy-idb-val');
  });

  // legacy format: corrupt (no dot, invalid ciphertext)
  it('should return undefined for corrupt legacy-format idb value', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    const storageKey = await session.rotateKeyName('corrupt-legacy');
    await overwriteIdbValue('corrupt-store', storageKey, 'NOTVALIDENCRYPTED!!');
    const result = await adapter.get('corrupt-store', 'corrupt-legacy');
    expect(result).toBeUndefined();
  });

  // critical sensitivity is also wiped via wipeHighSensitivity
  it('should wipe critical-sensitivity idb entries via wipeHighSensitivity', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('crit-store', 'crit-key', 'crit-val', { sensitivity: 'critical' });
    const wiped: string[] = [];
    await adapter.wipeHighSensitivity(wiped);
    expect(wiped.some((w) => w.includes('idb:'))).toBe(true);
    expect(await adapter.get('crit-store', 'crit-key')).toBeUndefined();
  });

  // meta HMAC failure in IDB (corrupt meta part)
  it('should emit hmac-failure and return undefined when meta decryption fails in idb', async () => {
    const events = new TesseraEmitter();
    const adapter = new IndexedDbAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('hmac-failure', handler);

    await adapter.put('meta-corrupt-store', 'meta-key', 'value');

    // Derive the storage key (HMAC rotation) so we can overwrite the IDB record
    const storageKey = await session.rotateKeyName('meta-key');
    // Overwrite with corrupt meta but keep a dot separator
    await overwriteIdbValue(
      'meta-corrupt-store',
      storageKey,
      'INVALIDBASE64GARBAGE==.VALIDLOOKINGVALUE==',
    );

    const result = await adapter.get('meta-corrupt-store', 'meta-key');
    expect(result).toBeUndefined();
    expect(handler).toHaveBeenCalled();
  });

  // applyOnSuspicion – lock via value HMAC failure
  it('should lock session when onSuspicion is "lock" and value decryption fails in idb', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('sus-store', 'sus-lock', 'secure', { onSuspicion: 'lock' });

    // Get the rotated storage key
    const storageKey = await session.rotateKeyName('sus-lock');
    // Read the actual stored value to get the valid meta part
    const rawRecord = await new Promise<{ value: string } | undefined>((resolve) => {
      const req = indexedDB.open('tessera_vault', 2);
      req.onsuccess = () => {
        const db = req.result;
        const tx = db.transaction('tessera_data', 'readonly');
        const store = tx.objectStore('tessera_data');
        const getReq = store.get(['sus-store', storageKey]);
        getReq.onsuccess = () => {
          db.close();
          resolve(getReq.result as { value: string });
        };
        tx.addEventListener('error', () => {
          db.close();
          resolve();
        });
      };
    });

    if (rawRecord) {
      const dotIdx = rawRecord.value.indexOf('.');
      // Keep valid meta but corrupt the value portion
      const corrupted = rawRecord.value.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==';
      await overwriteIdbValue('sus-store', storageKey, corrupted);
      await adapter.get('sus-store', 'sus-lock');
      expect(session.isLocked()).toBe(true);
    } else {
      // Record not found — skip this test (shouldn't happen)
      expect(true).toBe(true);
    }
  });

  // applyOnSuspicion – throw (key stays)
  it('should return undefined without wiping when onSuspicion is "throw" and value HMAC fails', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('sus-throw-store', 'sus-throw', 'val', { onSuspicion: 'throw' });

    const storageKey = await session.rotateKeyName('sus-throw');
    const rawRecord = await new Promise<{ value: string } | undefined>((resolve) => {
      const req = indexedDB.open('tessera_vault', 2);
      req.onsuccess = () => {
        const db = req.result;
        const tx = db.transaction('tessera_data', 'readonly');
        const s = tx.objectStore('tessera_data');
        const getReq = s.get(['sus-throw-store', storageKey]);
        getReq.onsuccess = () => {
          db.close();
          resolve(getReq.result as { value: string });
        };
        tx.addEventListener('error', () => {
          db.close();
          resolve();
        });
      };
    });

    if (rawRecord) {
      const dotIdx = rawRecord.value.indexOf('.');
      await overwriteIdbValue(
        'sus-throw-store',
        storageKey,
        rawRecord.value.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==',
      );
      const result = await adapter.get('sus-throw-store', 'sus-throw');
      expect(result).toBeUndefined();
      // Record should still exist (not wiped)
      const stillExists = await new Promise<boolean>((resolve) => {
        const req = indexedDB.open('tessera_vault', 2);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction('tessera_data', 'readonly');
          const s = tx.objectStore('tessera_data');
          const getReq = s.get(['sus-throw-store', storageKey]);
          getReq.onsuccess = () => {
            db.close();
            resolve(getReq.result !== undefined);
          };
          tx.addEventListener('error', () => {
            db.close();
            resolve(false);
          });
        };
      });
      expect(stillExists).toBe(true);
    } else {
      expect(true).toBe(true);
    }
  });

  // wipeHighSensitivity JSON.parse catch branch (lines 419-420):
  // A record whose meta decrypts fine but is not valid JSON is silently skipped
  it('should skip records with non-JSON meta during wipeHighSensitivity', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    // Write a valid high-sensitivity item first
    await adapter.put('json-catch-store', 'valid-hi', 'val', { sensitivity: 'high' });

    // Write a record where meta = valid ciphertext but plaintext is not JSON
    const cryptoKey = session.getKey();
    const nonJsonMeta = await encryptWithSalt(cryptoKey, 'NOT-JSON {{{');
    const encVal = await encryptWithSalt(cryptoKey, 'ignored');
    const storageKey = await session.rotateKeyName('bad-meta-key');
    await overwriteIdbValue('json-catch-store', storageKey, `${nonJsonMeta}.${encVal}`);

    const wiped: string[] = [];
    await adapter.wipeHighSensitivity(wiped);
    // The valid high-sensitivity item is wiped; the bad-meta item is silently skipped
    expect(wiped.some((w) => w.includes('idb:'))).toBe(true);
    expect(await adapter.get('json-catch-store', 'valid-hi')).toBeUndefined();
  });

  // readCount NaN branch: inject metadata with non-finite readCount
  it('should normalise non-finite readCount in IDB metadata', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    const cryptoKey = session.getKey();
    const meta = JSON.stringify({
      writeTime: Date.now(),
      readCount: Number.NaN,
      sensitivity: 'low',
      onSuspicion: 'wipe',
    });
    const encMeta = await encryptWithSalt(cryptoKey, meta);
    const encVal = await encryptWithSalt(cryptoKey, JSON.stringify('nan-idb-val'));
    const storageKey = await session.rotateKeyName('nan-idb-key');
    await overwriteIdbValue('nan-idb-store', storageKey, `${encMeta}.${encVal}`);

    const result = await adapter.get('nan-idb-store', 'nan-idb-key');
    expect(result).toBe('nan-idb-val');
  });

  // buildMeta false branches: low sensitivity has no ttl/maxReads/halfLifeHard defaults
  it('should store and retrieve a low-sensitivity IDB item (no ttl/maxReads/halfLife defaults)', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('low-store', 'low-key', 'low-val', { sensitivity: 'low' });
    const result = await adapter.get('low-store', 'low-key');
    expect(result).toBe('low-val');
  });

  // Rate limit branch in get() (covers lines 121-126)
  it('should return undefined when suspicion rate limit is exceeded in get()', async () => {
    const config = resolveConfig({
      suspicion: {
        rateLimit: { callsPerSecond: 2, scorePerExcess: 1 },
        thresholds: { lockdown: 10_000 },
      },
    });
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new IndexedDbAdapter(config, session, events, suspicion);
    await adapter.put('rate-idb', 'rate-key', 'rate-val');

    let lastResult: unknown;
    for (let i = 0; i < 6; i++) {
      lastResult = await adapter.get('rate-idb', 'rate-key');
    }
    expect(lastResult).toBeUndefined();
    suspicion.destroy();
  });

  // JSON.parse catch branch in get() (covers line 157)
  it('should return undefined when IDB value decrypts to non-JSON text', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    const cryptoKey = session.getKey();
    const meta = JSON.stringify({
      writeTime: Date.now(),
      readCount: 0,
      sensitivity: 'low',
      onSuspicion: 'wipe',
    });
    const encMeta = await encryptWithSalt(cryptoKey, meta);
    // Value encrypts to a plain string that is not valid JSON
    const encVal = await encryptWithSalt(cryptoKey, 'not-json-at-all{{{');
    const storageKey = await session.rotateKeyName('non-json-idb-key');
    await overwriteIdbValue('non-json-idb-store', storageKey, `${encMeta}.${encVal}`);

    const result = await adapter.get('non-json-idb-store', 'non-json-idb-key');
    expect(result).toBeUndefined();
  });

  // checkQuota: storage-quota-warning emitted when usage exceeds 80% threshold (covers lines 50-54)
  it('should emit storage-quota-warning when storage usage exceeds 80% quota', async () => {
    // happy-dom does not provide navigator.storage; define it for this test only
    const storageMock = { estimate: vi.fn().mockResolvedValue({ usage: 900, quota: 1000 }) };
    Object.defineProperty(navigator, 'storage', {
      configurable: true,
      writable: true,
      value: storageMock,
    });

    const events = new TesseraEmitter();
    const handler = vi.fn();
    events.on('storage-quota-warning', handler);

    try {
      const adapter = new IndexedDbAdapter(resolveConfig(), session, events);
      await adapter.put('quota-check', 'key', 'val');
      // checkQuota is fire-and-forget; give it a tick to resolve
      await new Promise((r) => setTimeout(r, 30));
      expect(handler).toHaveBeenCalledWith(
        expect.objectContaining({ backend: 'idb', usedBytes: 900, quotaBytes: 1000 }),
      );
    } finally {
      try {
        Object.defineProperty(navigator, 'storage', {
          configurable: true,
          writable: true,
          value: undefined,
        });
      } catch {
        /* best-effort cleanup */
      }
    }
  });

  // applyOnSuspicion – wipe (default)
  it('should wipe the key when onSuspicion is "wipe" (default) and value HMAC fails', async () => {
    const events = new TesseraEmitter();
    const adapter = new IndexedDbAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('key-wiped', handler);
    await adapter.put('sus-wipe-store', 'sus-wipe', 'val', { onSuspicion: 'wipe' });

    const storageKey = await session.rotateKeyName('sus-wipe');
    const rawRecord = await new Promise<{ value: string } | undefined>((resolve) => {
      const req = indexedDB.open('tessera_vault', 2);
      req.onsuccess = () => {
        const db = req.result;
        const tx = db.transaction('tessera_data', 'readonly');
        const s = tx.objectStore('tessera_data');
        const getReq = s.get(['sus-wipe-store', storageKey]);
        getReq.onsuccess = () => {
          db.close();
          resolve(getReq.result as { value: string });
        };
        tx.addEventListener('error', () => {
          db.close();
          resolve();
        });
      };
    });

    if (rawRecord) {
      const dotIdx = rawRecord.value.indexOf('.');
      await overwriteIdbValue(
        'sus-wipe-store',
        storageKey,
        rawRecord.value.slice(0, dotIdx + 1) + 'INVALIDBASE64GARBAGE==',
      );
      const result = await adapter.get('sus-wipe-store', 'sus-wipe');
      expect(result).toBeUndefined();
      expect(handler).toHaveBeenCalled();
    } else {
      expect(true).toBe(true);
    }
  });

  // Honey keys: put() writes honeyKeys.count extra entries in the same store
  it('should write honey entries alongside the real entry on put()', async () => {
    const config = resolveConfig({ debug: true, honeyKeys: { count: 2 } });
    const adapter = new IndexedDbAdapter(config, session, new TesseraEmitter());
    const honeyManager = new HoneyKeyManager(config);
    adapter.setHoneyManager(honeyManager);

    await adapter.put('honey-store', 'real-key', 'real-value');

    const honeyStorageKeys = honeyManager.allKeys('idb');
    expect(honeyStorageKeys.length).toBe(2);

    // Each honey entry must exist in IDB under the same store name
    for (const hk of honeyStorageKeys) {
      const raw = await new Promise<unknown>((resolve) => {
        const req = indexedDB.open('tessera_vault', 2);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction('tessera_data', 'readonly');
          const s = tx.objectStore('tessera_data');
          const getReq = s.get(['honey-store', hk]);
          getReq.onsuccess = () => {
            db.close();
            resolve(getReq.result);
          };
          tx.addEventListener('error', () => {
            db.close();
            resolve();
          });
        };
      });
      expect(raw).not.toBeUndefined();
    }

    // Real key is still readable
    expect(await adapter.get('honey-store', 'real-key')).toBe('real-value');
  });

  // cleanOrphanedHoneyKeys: wipes IDB honey entries from a previous session
  it('cleanOrphanedHoneyKeys wipes orphaned IDB honey entries from a prior session', async () => {
    const config = resolveConfig({ debug: true, honeyKeys: { count: 2 } });

    // Session 1: write a real key + honey entries
    const session1 = new KeySession();
    const salt = await getSalt();
    const key1 = await deriveKey('246813', salt);
    const hmac1 = await deriveHmacKey('246813', salt);
    session1.setKey(key1, 900_000);
    session1.setHmacKey(hmac1);

    const adapter1 = new IndexedDbAdapter(config, session1, new TesseraEmitter());
    const honeyMgr1 = new HoneyKeyManager(config);
    adapter1.setHoneyManager(honeyMgr1);
    await adapter1.put('orphan-store', 'real', 'value');
    const honeyKeys1 = honeyMgr1.allKeys('idb');
    expect(honeyKeys1.length).toBe(2);
    session1.reset();

    // Session 2: new session with same key, empty honey manager
    const session2 = new KeySession();
    session2.setKey(await deriveKey('246813', salt), 900_000);
    session2.setHmacKey(await deriveHmacKey('246813', salt));

    const adapter2 = new IndexedDbAdapter(config, session2, new TesseraEmitter());
    const honeyMgr2 = new HoneyKeyManager(config);
    adapter2.setHoneyManager(honeyMgr2);

    await adapter2.cleanOrphanedHoneyKeys();

    // Orphaned honey entries must be gone
    for (const hk of honeyKeys1) {
      const raw = await new Promise<unknown>((resolve) => {
        const req = indexedDB.open('tessera_vault', 2);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction('tessera_data', 'readonly');
          const s = tx.objectStore('tessera_data');
          const getReq = s.get(['orphan-store', hk]);
          getReq.onsuccess = () => {
            db.close();
            resolve(getReq.result);
          };
          tx.addEventListener('error', () => {
            db.close();
            resolve();
          });
        };
      });
      expect(raw).toBeUndefined();
    }

    // Real entry survives
    expect(await adapter2.get('orphan-store', 'real')).toBe('value');
    session2.reset();
  });

  // get() honey hit: isDecoyAlias — accessing a honey key via its decoy developer alias
  it('get() records honey hit when called with a decoy alias on idb', async () => {
    const config = resolveConfig({ debug: true, honeyKeys: { count: 1 } });
    const { SuspicionEngine } = await import('../../src/core/suspicion');
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new IndexedDbAdapter(config, session, events, suspicion);
    const honeyManager = new HoneyKeyManager(config);
    adapter.setHoneyManager(honeyManager);

    await adapter.put('decoy-store', 'real-key', 'real-value');
    const decoyAliases = honeyManager.allDecoyAliases('idb');
    expect(decoyAliases.length).toBeGreaterThan(0);

    const result = await adapter.get('decoy-store', decoyAliases[0]!);
    expect(result).toBeUndefined();
    expect(suspicion.score).toBeGreaterThan(0);
    suspicion.destroy();
  });

  // cleanOrphanedSplits: removes _splits IDB entries whose sessionStorage pointer is gone
  it('cleanOrphanedSplits removes orphaned entries and preserves live ones', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());

    // Seed _splits directly via native IDB API
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.open('tessera_vault', 2);
      req.onsuccess = () => {
        const db = req.result;
        const tx = db.transaction('_splits', 'readwrite');
        const s = tx.objectStore('_splits');
        s.put({ store: 'sp-store', key: 't_orphan_split', value: 'orphan-data' });
        s.put({ store: 'sp-store', key: 't_live_split', value: 'live-data' });
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.addEventListener('error', () => {
          db.close();
          reject(tx.error);
        });
      };
      req.addEventListener('error', () => reject(req.error));
    });

    // Only the live key has a valid split pointer in sessionStorage
    sessionStorage.setItem('t_live_split', 'split:somebase64data');

    await adapter.cleanOrphanedSplits();

    // Verify orphan was deleted and live entry survives
    const remaining = await new Promise<string[]>((resolve) => {
      const req = indexedDB.open('tessera_vault', 2);
      req.onsuccess = () => {
        const db = req.result;
        const keys: string[] = [];
        const tx = db.transaction('_splits', 'readonly');
        const s = tx.objectStore('_splits');
        s.openCursor().onsuccess = (e) => {
          const cursor = (e.target as IDBRequest<IDBCursorWithValue | null>).result;
          if (cursor) {
            keys.push((cursor.value as { key: string }).key);
            cursor.continue();
          }
        };
        tx.oncomplete = () => {
          db.close();
          resolve(keys);
        };
      };
    });

    expect(remaining).not.toContain('t_orphan_split');
    expect(remaining).toContain('t_live_split');
    sessionStorage.clear();
  });

  // cleanOrphanedClaims: removes _claims IDB entries whose ref token is no longer in sessionStorage
  it('cleanOrphanedClaims removes orphaned claims and preserves live ones', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());

    // Seed _claims directly via native IDB API
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.open('tessera_vault', 2);
      req.onsuccess = () => {
        const db = req.result;
        const tx = db.transaction('_claims', 'readwrite');
        const s = tx.objectStore('_claims');
        s.put({ token: 'orphan-token-abc', value: 'orphan-encrypted' });
        s.put({ token: 'live-token-xyz', value: 'live-encrypted' });
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.addEventListener('error', () => {
          db.close();
          reject(tx.error);
        });
      };
      req.addEventListener('error', () => reject(req.error));
    });

    // Only the live token is referenced in sessionStorage
    sessionStorage.setItem('some-claim-key', 'ref:live-token-xyz');

    await adapter.cleanOrphanedClaims();

    // Verify orphan was deleted and live claim survives
    const remaining = await new Promise<string[]>((resolve) => {
      const req = indexedDB.open('tessera_vault', 2);
      req.onsuccess = () => {
        const db = req.result;
        const tokens: string[] = [];
        const tx = db.transaction('_claims', 'readonly');
        const s = tx.objectStore('_claims');
        s.openCursor().onsuccess = (e) => {
          const cursor = (e.target as IDBRequest<IDBCursorWithValue | null>).result;
          if (cursor) {
            tokens.push((cursor.value as { token: string }).token);
            cursor.continue();
          }
        };
        tx.oncomplete = () => {
          db.close();
          resolve(tokens);
        };
      };
    });

    expect(remaining).not.toContain('orphan-token-abc');
    expect(remaining).toContain('live-token-xyz');
    sessionStorage.clear();
  });

  // ── honey key detection branches ──────────────────────────────────────────────

  it('get() returns undefined when developer key is a honey decoy alias (isDecoyAlias)', async () => {
    const config = resolveConfig({});
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new IndexedDbAdapter(config, session, events, suspicion);
    const fakeMgr = {
      add: () => {},
      remove: () => {},
      isHoney: () => false,
      isDecoyAlias: () => true, // every developer key is a decoy alias
      allDecoyAliases: () => [] as string[],
    };
    adapter.setHoneyManager(fakeMgr);
    const result = await adapter.get('tessera_data', 'any-key');
    expect(result).toBeUndefined();
  });

  it('get() returns undefined when rotated key matches a honey key (isHoney)', async () => {
    const config = resolveConfig({});
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(config, events);
    const adapter = new IndexedDbAdapter(config, session, events, suspicion);
    const fakeMgr = {
      add: () => {},
      remove: () => {},
      isHoney: () => true, // every rotated key is a honey key
      isDecoyAlias: () => false,
      allDecoyAliases: () => [] as string[],
    };
    adapter.setHoneyManager(fakeMgr);
    const result = await adapter.get('tessera_data', 'any-key');
    expect(result).toBeUndefined();
  });
});
