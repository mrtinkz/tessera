import {
  type IIDBAdapter,
  type StorageItemOptions,
  type ValueMetadata,
  type ResolvedConfig,
  type SensitivityLevel,
  type SuspicionAction,
  TesseraError,
  TesseraErrorCode,
} from '../types';
import { type KeySession } from '../core/session';
import { encryptWithSalt, decryptFull, rotateKeyName as rotateKeyNameFn } from '../core/crypto';
import { type TesseraEmitter } from '../core/events';
import { type SuspicionEngine } from '../core/suspicion';
import { generateNoiseBlock } from '../core/wipe';
import { SENSITIVITY_DEFAULTS } from '../types';

const DB_NAME = 'tessera_vault';
const DB_VERSION = 2;
const QUOTA_WARNING_THRESHOLD = 0.8;
const DEFAULT_ON_SUSPICION: SuspicionAction = 'wipe';

function openDb(): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('tessera_data')) {
        db.createObjectStore('tessera_data', { keyPath: ['store', 'key'] });
      }
      if (!db.objectStoreNames.contains('_claims')) {
        db.createObjectStore('_claims', { keyPath: 'token' });
      }
      if (!db.objectStoreNames.contains('_splits')) {
        db.createObjectStore('_splits', { keyPath: ['store', 'key'] });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.addEventListener('error', () =>
      reject(new TesseraError(TesseraErrorCode.STORAGE_QUOTA, 'Failed to open IndexedDB.')),
    );
  });
}

async function checkQuota(events: TesseraEmitter): Promise<void> {
  try {
    if ('storage' in navigator && 'estimate' in navigator.storage) {
      const estimate = await navigator.storage.estimate();
      if (estimate.usage !== undefined && estimate.quota !== undefined && estimate.quota > 0) {
        const usageRatio = estimate.usage / estimate.quota;
        if (usageRatio >= QUOTA_WARNING_THRESHOLD) {
          events?.emit('storage-quota-warning', {
            backend: 'idb',
            usedBytes: estimate.usage,
            quotaBytes: estimate.quota,
          });
        }
      }
    }
  } catch {
    /* best-effort */
  }
}

export class IndexedDbAdapter implements IIDBAdapter {
  private sensitivityRegistry = new Map<string, Map<string, SensitivityLevel>>();

  constructor(
    private config: ResolvedConfig,
    private session: KeySession,
    private events: TesseraEmitter,
    private suspicion?: SuspicionEngine,
  ) {}

  async put(
    storeName: string,
    key: string,
    value: unknown,
    options?: StorageItemOptions,
  ): Promise<void> {
    const cryptoKey = this.session.getKey();
    const storageKey = await this.session.rotateKeyName(key);

    const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
    const metadata = this.buildMeta(sensitivity, options);

    let storeMap = this.sensitivityRegistry.get(storeName);
    if (!storeMap) {
      storeMap = new Map();
      this.sensitivityRegistry.set(storeName, storeMap);
    }
    storeMap.set(key, sensitivity);

    const packed = await this.packageValue(cryptoKey, JSON.stringify(value), metadata);

    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      store.put({ store: storeName, key: storageKey, value: packed, updatedAt: Date.now() });
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.addEventListener('error', () => {
        db.close();
        reject(new TesseraError(TesseraErrorCode.STORAGE_QUOTA, 'IndexedDB write failed.'));
      });
    });
    this.session.touch();
    void checkQuota(this.events);
  }

  async get(storeName: string, key: string): Promise<unknown> {
    const cryptoKey = this.session.getKeySafe();
    if (cryptoKey === null) return undefined;

    if (this.suspicion) {
      const rateCheck = this.suspicion.checkRateLimit();
      if (
        !rateCheck.ok &&
        rateCheck.callsPerSecond > this.config.suspicion.rateLimit.callsPerSecond * 1.5
      ) {
        return undefined;
      }
    }

    const storageKey = await this.session.rotateKeyNameSafe(key);
    if (storageKey === null) return undefined;

    const db = await openDb();
    const record = await new Promise<{ value: string } | undefined>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readonly');
      const store = tx.objectStore('tessera_data');
      const request = store.get([storeName, storageKey]);
      request.onsuccess = () => {
        resolve(request.result);
      };
      request.addEventListener('error', () => {
        reject(new TesseraError(TesseraErrorCode.STORAGE_QUOTA, 'IndexedDB read failed.'));
      });
      tx.oncomplete = () => {
        db.close();
      };
    });

    if (record === undefined) return undefined;

    const result = await this.readWithMetadata(cryptoKey, record.value, key, 'idb', storeName);
    if (result === null) return undefined;

    try {
      return JSON.parse(result) as unknown;
    } catch {
      return undefined;
    }
  }

  async remove(storeName: string, key: string): Promise<void> {
    if (this.session.isLocked()) return;

    const storageKey = await this.session.rotateKeyNameSafe(key);
    if (storageKey === null) return;

    // Overwrite with noise before deleting for forensic mitigation.
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      store.put({
        store: storeName,
        key: storageKey,
        value: generateNoiseBlock(),
        updatedAt: Date.now(),
      });
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.addEventListener('error', () => {
        db.close();
        reject();
      });
    });

    const db2 = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db2.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      store.delete([storeName, storageKey]);
      tx.oncomplete = () => {
        db2.close();
        resolve();
      };
      tx.addEventListener('error', () => {
        db2.close();
        reject();
      });
    });
    this.events?.emit('key-wiped', { keyAlias: key, backend: 'idb', reason: 'removed' });
  }

  async clear(storeName: string): Promise<void> {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      const request = store.openCursor();
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor) {
          const data = cursor.value as { store: string };
          if (data.store === storeName) {
            cursor.delete();
          }
          cursor.continue();
        }
      };
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.addEventListener('error', () => {
        db.close();
        reject();
      });
    });
  }

  private async readWithMetadata(
    cryptoKey: CryptoKey,
    raw: string,
    keyAlias: string,
    backend: string,
    storeName?: string,
  ): Promise<string | null> {
    const dotIdx = raw.indexOf('.');
    if (dotIdx === -1) {
      const legacyResult = await decryptFull(cryptoKey, raw);
      if (legacyResult.ok) return legacyResult.value;
      return null;
    }

    const metaB64 = raw.slice(0, dotIdx);
    const valueB64 = raw.slice(dotIdx + 1);

    const metaResult = await decryptFull(cryptoKey, metaB64);
    if (!metaResult.ok) {
      this.suspicion?.recordHmacFailure();
      this.events?.emit('hmac-failure', { keyAlias, backend });
      if (storeName) await this.remove(storeName, keyAlias);
      return null;
    }

    const metadata: ValueMetadata = JSON.parse(metaResult.value);
    if (typeof metadata.readCount !== 'number' || !Number.isFinite(metadata.readCount)) {
      metadata.readCount = 0;
    }

    if (metadata.ttl !== undefined && Date.now() - metadata.writeTime > metadata.ttl) {
      this.events?.emit('key-expired', {
        keyAlias,
        backend,
        expiredAt: metadata.writeTime + metadata.ttl,
      });
      if (storeName) await this.remove(storeName, keyAlias);
      return null;
    }

    if (metadata.maxReads !== undefined && metadata.readCount >= metadata.maxReads) {
      this.events?.emit('max-reads-reached', { keyAlias, backend, reads: metadata.readCount });
      if (storeName) await this.remove(storeName, keyAlias);
      return null;
    }

    if (
      metadata.halfLifeHard !== undefined &&
      Date.now() - metadata.writeTime > metadata.halfLifeHard
    ) {
      this.events?.emit('key-expired', {
        keyAlias,
        backend,
        expiredAt: metadata.writeTime + metadata.halfLifeHard,
      });
      if (storeName) await this.remove(storeName, keyAlias);
      return null;
    }

    if (
      metadata.halfLifeSoft !== undefined &&
      Date.now() - metadata.writeTime > metadata.halfLifeSoft &&
      !this.session.hasReconfirm()
    ) {
      this.events?.emit('reconfirmation-required', {
        keyAlias,
        softThresholdMs: metadata.halfLifeSoft,
        elapsedMs: Date.now() - metadata.writeTime,
      });
      return null;
    }

    const valueResult = await decryptFull(cryptoKey, valueB64);
    if (!valueResult.ok) {
      this.suspicion?.recordHmacFailure();
      this.events?.emit('hmac-failure', { keyAlias, backend });
      await this.applyOnSuspicion(metadata.onSuspicion, keyAlias, backend, storeName);
      return null;
    }

    metadata.readCount += 1;
    await this.updateMetadata(cryptoKey, keyAlias, metadata, storeName);

    this.session.touch();
    return valueResult.value;
  }

  private async packageValue(
    cryptoKey: CryptoKey,
    value: string,
    metadata: ValueMetadata,
  ): Promise<string> {
    const metaStr = JSON.stringify(metadata);
    const encryptedMeta = await encryptWithSalt(cryptoKey, metaStr);
    const encryptedValue = await encryptWithSalt(cryptoKey, value);
    return `${encryptedMeta}.${encryptedValue}`;
  }

  private async updateMetadata(
    cryptoKey: CryptoKey,
    keyAlias: string,
    metadata: ValueMetadata,
    storeName = 'tessera_data',
  ): Promise<void> {
    const resolvedStore = storeName;
    const hmacKey = this.session.getHmacKeySafe()!;
    const storageKey = await rotateKeyNameFn(hmacKey, keyAlias);

    // Encrypt metadata BEFORE the transaction (async work not allowed inside IDB transactions).
    const encryptedMeta = await encryptWithSalt(cryptoKey, JSON.stringify(metadata));

    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      const req = store.get([resolvedStore, storageKey]);
      req.onsuccess = () => {
        const record = req.result as { store: string; key: string; value: string } | undefined;
        if (!record) {
          resolve();
          return;
        }
        const dotIdx = record.value.indexOf('.');
        if (dotIdx === -1) {
          resolve();
          return;
        }
        const valueB64 = record.value.slice(dotIdx + 1);
        store.put({
          store: resolvedStore,
          key: storageKey,
          value: `${encryptedMeta}.${valueB64}`,
          updatedAt: Date.now(),
        });
      };
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.addEventListener('error', () => {
        db.close();
        reject(
          new TesseraError(TesseraErrorCode.STORAGE_QUOTA, 'IndexedDB updateMetadata failed.'),
        );
      });
    });
  }

  async wipeHighSensitivity(wiped: string[]): Promise<void> {
    const cryptoKey = this.session.getKeySafe();
    if (!cryptoKey) return;

    // Scan the full IDB store — covers items from previous sessions not in the registry
    const db = await openDb();
    const allRecords = await new Promise<Array<{ store: string; key: string; value: string }>>(
      (resolve, reject) => {
        const tx = db.transaction('tessera_data', 'readonly');
        const objStore = tx.objectStore('tessera_data');
        const results: Array<{ store: string; key: string; value: string }> = [];
        const req = objStore.openCursor();
        req.onsuccess = () => {
          const cursor = req.result;
          if (cursor) {
            results.push(cursor.value as { store: string; key: string; value: string });
            cursor.continue();
          }
        };
        tx.oncomplete = () => {
          db.close();
          resolve(results);
        };
        tx.addEventListener('error', () => {
          db.close();
          reject();
        });
      },
    );

    for (const record of allRecords) {
      const dotIdx = record.value.indexOf('.');
      if (dotIdx === -1) continue;
      const metaResult = await decryptFull(cryptoKey, record.value.slice(0, dotIdx));
      if (!metaResult.ok) continue;
      let meta: ValueMetadata;
      try {
        meta = JSON.parse(metaResult.value) as ValueMetadata;
      } catch {
        continue;
      }
      if (meta.sensitivity === 'high' || meta.sensitivity === 'critical') {
        const db2 = await openDb();
        await new Promise<void>((resolve2, reject2) => {
          const tx2 = db2.transaction('tessera_data', 'readwrite');
          tx2.objectStore('tessera_data').delete([record.store, record.key]);
          tx2.oncomplete = () => {
            db2.close();
            resolve2();
          };
          tx2.addEventListener('error', () => {
            db2.close();
            reject2();
          });
        });
        wiped.push(`idb:${record.store}:${record.key}`);
      }
    }

    // Purge matching entries from the in-session registry
    for (const [, storeMap] of this.sensitivityRegistry) {
      for (const [key, sensitivity] of storeMap) {
        if (sensitivity === 'high' || sensitivity === 'critical') storeMap.delete(key);
      }
    }
  }

  private async applyOnSuspicion(
    action: SuspicionAction | undefined,
    keyAlias: string,
    backend: string,
    storeName?: string,
  ): Promise<void> {
    if (action === 'lock') {
      this.session.lock();
      this.events?.emit('vault-locked', { reason: `suspicion: hmac-failure on ${keyAlias}` });
    } else if (action === 'throw') {
      // Leave the key intact; caller returns null.
    } else {
      if (storeName) await this.remove(storeName, keyAlias);
      this.events?.emit('key-wiped', { keyAlias, backend, reason: 'hmac-failure' });
    }
  }

  private buildMeta(sensitivity: SensitivityLevel, options?: StorageItemOptions): ValueMetadata {
    const meta: ValueMetadata = {
      writeTime: Date.now(),
      readCount: 0,
      sensitivity,
    };

    const defaults = SENSITIVITY_DEFAULTS[sensitivity];
    const ttl = options?.ttl ?? defaults?.ttl ?? this.config.defaults?.ttl;
    if (ttl !== undefined) meta.ttl = ttl;

    const maxReads = options?.maxReads ?? defaults?.maxReads ?? this.config.defaults?.maxReads;
    if (maxReads !== undefined) meta.maxReads = maxReads;

    const onSuspicion =
      options?.onSuspicion ?? this.config.defaults?.onSuspicion ?? DEFAULT_ON_SUSPICION;
    if (onSuspicion !== undefined) meta.onSuspicion = onSuspicion;

    const hlSoft = options?.halfLife?.soft ?? defaults?.halfLifeSoft;
    if (hlSoft !== undefined) meta.halfLifeSoft = hlSoft;

    const hlHard = options?.halfLife?.hard ?? this.config.halfLife?.hard;
    if (hlHard !== undefined) meta.halfLifeHard = hlHard;

    return meta;
  }
}
