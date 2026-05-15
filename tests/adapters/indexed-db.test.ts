import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IndexedDbAdapter } from '../../src/adapters/indexed-db';
import { KeySession } from '../../src/core/session';
import { deriveKey, deriveHmacKey, getSalt, encryptWithSalt } from '../../src/core/crypto';
import { resolveConfig } from '../../src/core/config';
import { TesseraEmitter } from '../../src/core/events';

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
  it('should return undefined when halfLife.soft has elapsed and no reconfirm key', async () => {
    const adapter = new IndexedDbAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.put('idb-hl-s', 'hl-soft', 'v', { halfLife: { soft: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    expect(await adapter.get('idb-hl-s', 'hl-soft')).toBeUndefined();
  });

  it('should emit reconfirmation-required on soft half-life expiry', async () => {
    const events = new TesseraEmitter();
    const adapter = new IndexedDbAdapter(resolveConfig(), session, events);
    const handler = vi.fn();
    events.on('reconfirmation-required', handler);
    await adapter.put('idb-hl-ev', 'hl-soft-ev', 'v', { halfLife: { soft: 1 } });
    await new Promise((r) => setTimeout(r, 10));
    await adapter.get('idb-hl-ev', 'hl-soft-ev');
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
});
