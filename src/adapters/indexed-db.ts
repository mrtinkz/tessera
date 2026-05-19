import {
  type IIDBAdapter,
  type StorageItemOptions,
  type ValueMetadata,
  type ResolvedConfig,
  type SensitivityLevel,
  type SuspicionAction,
  type HoneyKeyManagerIsh,
  TesseraError,
  TesseraErrorCode,
} from '../types';
import { type HoneyKeyManager } from '../storage/honey';
import { type KeySession } from '../core/session';
import {
  encryptWithSalt,
  decryptFull,
  rotateKeyName as rotateKeyNameFn,
  generateHoneyCiphertext,
} from '../core/crypto';
import { type TesseraEmitter } from '../core/events';
import { type SuspicionEngine } from '../core/suspicion';
import { generateNoiseBlock } from '../core/wipe';
import { SENSITIVITY_DEFAULTS } from '../types';

// DB_NAME is computed per vault. 'default' keeps the legacy name for zero migration.
function resolveDbName(vaultId = 'default'): string {
  return vaultId === 'default' ? 'tessera_vault' : `tessera_vault_${vaultId}`;
}

const DB_VERSION = 2;
const QUOTA_WARNING_THRESHOLD = 0.8;
const DEFAULT_ON_SUSPICION: SuspicionAction = 'wipe';

function openDb(vaultId = 'default'): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(resolveDbName(vaultId), DB_VERSION);

    request.onupgradeneeded = (): void => {
      const db = request.result;
      /* v8 ignore next 2 */
      if (!db.objectStoreNames.contains('tessera_data')) {
        db.createObjectStore('tessera_data', { keyPath: ['store', 'key'] });
      }
      /* v8 ignore next 2 */
      if (!db.objectStoreNames.contains('_claims')) {
        db.createObjectStore('_claims', { keyPath: 'token' });
      }
      /* v8 ignore next 2 */
      if (!db.objectStoreNames.contains('_splits')) {
        db.createObjectStore('_splits', { keyPath: ['store', 'key'] });
      }
    };

    request.onsuccess = (): void => resolve(request.result);
    request.addEventListener('error', () =>
      reject(
        new TesseraError(
          TesseraErrorCode.UNSUPPORTED_ENV,
          'Failed to open IndexedDB. IndexedDB may be unavailable in this environment (private/incognito mode or security policy).',
        ),
      ),
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
  private honeyManager: HoneyKeyManagerIsh | null = null;
  // Store the resolved vault ID so all IDB operations use the right database.
  private readonly vaultId: string;
  // Persistent IDB connection — open once per vault session, close on lock/destroy.
  private db: IDBDatabase | null = null;

  constructor(
    private config: ResolvedConfig,
    private session: KeySession,
    private events: TesseraEmitter,
    private suspicion?: SuspicionEngine,
  ) {
    this.vaultId = config.vaultId ?? 'default';
  }

  /**
   * Returns the cached IDB connection, opening it if necessary.
   * Registers a `versionchange` listener so we gracefully close if another tab
   * tries to upgrade the schema.
   */
  private async getDb(): Promise<IDBDatabase> {
    if (this.db !== null) return this.db;
    const db = await openDb(this.vaultId);
    // Close our hold if another tab triggers a schema upgrade.
    /* v8 ignore next 4 */
    db.addEventListener('versionchange', () => {
      this.db?.close();
      this.db = null;
    });
    this.db = db;
    return db;
  }

  setHoneyManager(manager: HoneyKeyManagerIsh): void {
    this.honeyManager = manager;
  }

  /** Close the persistent IDB connection. Called when the vault is locked or destroyed. */
  close(): void {
    this.db?.close();
    this.db = null;
  }

  async put(
    storeName: string,
    key: string,
    value: unknown,
    options?: StorageItemOptions,
  ): Promise<void> {
    const cryptoKey = this.session.getKey();
    const storageKey = await this.session.rotateKeyName(key);

    const serialised = JSON.stringify(value);
    if (this.config.maxValueBytes !== undefined) {
      const byteLength = new TextEncoder().encode(serialised).byteLength;
      if (byteLength > this.config.maxValueBytes) {
        throw new TesseraError(
          TesseraErrorCode.VALIDATION_ERROR,
          `Value for '${key}' is ${byteLength} bytes, exceeds maxValueBytes (${this.config.maxValueBytes}).`,
        );
      }
    }
    if (this.config.onBeforeWrite !== undefined && !this.config.onBeforeWrite(key, serialised)) {
      throw new TesseraError(
        TesseraErrorCode.VALIDATION_ERROR,
        `Write for key '${key}' was rejected by onBeforeWrite.`,
      );
    }

    const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
    const metadata = this.buildMeta(sensitivity, options);

    let storeMap = this.sensitivityRegistry.get(storeName);
    if (!storeMap) {
      storeMap = new Map();
      this.sensitivityRegistry.set(storeName, storeMap);
    }
    storeMap.set(key, sensitivity);

    // Prepare honey keys and generate all ciphertexts in parallel with the real value.
    const honeyKeys = this.prepareHoneyKeys();
    const allCts = await Promise.all([
      this.packageValue(cryptoKey, serialised, metadata),
      ...honeyKeys.map(() => generateHoneyCiphertext(cryptoKey)),
    ]);
    const packed = allCts[0]!;
    const honeyCts = allCts.slice(1);

    // Collect all writes and shuffle them so the real entry has no fixed position.
    const writes: Array<[string, string]> = [
      [storageKey, packed],
      ...honeyKeys.map((hk, i) => [hk, honeyCts[i]!] as [string, string]),
    ];
    for (let i = writes.length - 1; i > 0; i--) {
      const j = crypto.getRandomValues(new Uint8Array(1))[0]! % (i + 1);
      // eslint-disable-next-line security/detect-object-injection
      [writes[i]!, writes[j]!] = [writes[j]!, writes[i]!];
    }

    const db = await this.getDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      for (const [k, v] of writes) {
        store.put({ store: storeName, key: k, value: v, updatedAt: Date.now() });
      }
      tx.oncomplete = (): void => {
        resolve();
      };
      tx.addEventListener('error', (): void => {
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

    if (this.honeyManager?.isDecoyAlias('idb', key)) {
      this.suspicion?.recordHoneyHit('idb');
      return undefined;
    }

    const storageKey = await this.session.rotateKeyNameSafe(key);
    if (storageKey === null) return undefined;

    if (this.honeyManager?.isHoney('idb', storageKey)) {
      this.suspicion?.recordHoneyHit('idb');
      return undefined;
    }

    const db = await this.getDb();
    const record = await new Promise<{ value: string } | undefined>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readonly');
      const store = tx.objectStore('tessera_data');
      const request = store.get([storeName, storageKey]);
      request.onsuccess = (): void => {
        resolve(request.result);
      };
      request.addEventListener('error', (): void => {
        reject(new TesseraError(TesseraErrorCode.STORAGE_QUOTA, 'IndexedDB read failed.'));
      });
      tx.oncomplete = (): void => {};
    });

    /* v8 ignore next */
    if (record === undefined) return undefined;

    const result = await this.readWithMetadata(cryptoKey, record.value, key, 'idb', storeName);
    /* v8 ignore next */
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
    const db = await this.getDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      store.put({
        store: storeName,
        key: storageKey,
        value: generateNoiseBlock(),
        updatedAt: Date.now(),
      });
      tx.oncomplete = (): void => {
        resolve();
      };
      /* v8 ignore next 4 */
      tx.addEventListener('error', (): void => {
        reject();
      });
    });

    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      store.delete([storeName, storageKey]);
      tx.oncomplete = (): void => {
        resolve();
      };
      /* v8 ignore next 4 */
      tx.addEventListener('error', (): void => {
        reject();
      });
    });
    this.events?.emit('key-wiped', { keyAlias: key, backend: 'idb', reason: 'removed' });
  }

  async clear(storeName: string): Promise<void> {
    const db = await this.getDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      const request = store.openCursor();
      request.onsuccess = (): void => {
        const cursor = request.result;
        if (cursor) {
          const data = cursor.value as { store: string };
          if (data.store === storeName) {
            cursor.delete();
          }
          cursor.continue();
        }
      };
      tx.oncomplete = (): void => {
        resolve();
      };
      /* v8 ignore next 4 */
      tx.addEventListener('error', (): void => {
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
      // Throw typed error so callers get an explicit signal.
      throw new TesseraError(
        TesseraErrorCode.RECONFIRMATION_REQUIRED,
        `Key '${keyAlias}' requires reconfirmation before it can be read.`,
      );
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
    // Guard against session locking between the get() and updateMetadata() calls.
    // getHmacKeySafe() returns null when locked — bail out gracefully instead of
    // crashing with a TypeError inside the IDB transaction.
    const hmacKey = this.session.getHmacKeySafe();
    /* v8 ignore next */
    if (hmacKey === null) return;
    const storageKey = await rotateKeyNameFn(hmacKey, keyAlias);

    // Encrypt metadata BEFORE the transaction (async work not allowed inside IDB transactions).
    const encryptedMeta = await encryptWithSalt(cryptoKey, JSON.stringify(metadata));

    const db = await this.getDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      const req = store.get([resolvedStore, storageKey]);
      req.onsuccess = (): void => {
        const record = req.result as { store: string; key: string; value: string } | undefined;
        /* v8 ignore next 4 */
        if (!record) {
          resolve();
          return;
        }
        const dotIdx = record.value.indexOf('.');
        /* v8 ignore next 4 */
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
      tx.oncomplete = (): void => {
        resolve();
      };
      /* v8 ignore next 5 */
      tx.addEventListener('error', (): void => {
        reject(
          new TesseraError(TesseraErrorCode.STORAGE_QUOTA, 'IndexedDB updateMetadata failed.'),
        );
      });
    });
  }

  async wipeAll(wiped: string[]): Promise<void> {
    /* v8 ignore next */
    if (typeof indexedDB === 'undefined') return;
    const db = await this.getDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(['tessera_data', '_claims', '_splits'], 'readwrite');
      tx.objectStore('tessera_data').clear();
      tx.objectStore('_claims').clear();
      tx.objectStore('_splits').clear();
      tx.oncomplete = (): void => {
        resolve();
      };
      /* v8 ignore next 4 */
      tx.addEventListener('error', (): void => {
        reject();
      });
    });
    wiped.push('idb:*');
    this.sensitivityRegistry.clear();
  }

  async wipeHighSensitivity(wiped: string[]): Promise<void> {
    const cryptoKey = this.session.getKeySafe();
    if (!cryptoKey) return;
    /* v8 ignore next */
    if (typeof indexedDB === 'undefined') return;

    // Scan the full IDB store — covers items from previous sessions not in the registry
    const db = await this.getDb();
    const allRecords = await new Promise<Array<{ store: string; key: string; value: string }>>(
      (resolve, reject) => {
        const tx = db.transaction('tessera_data', 'readonly');
        const objStore = tx.objectStore('tessera_data');
        const results: Array<{ store: string; key: string; value: string }> = [];
        const req = objStore.openCursor();
        req.onsuccess = (): void => {
          const cursor = req.result;
          if (cursor) {
            results.push(cursor.value as { store: string; key: string; value: string });
            cursor.continue();
          }
        };
        tx.oncomplete = (): void => {
          resolve(results);
        };
        /* v8 ignore next 4 */
        tx.addEventListener('error', (): void => {
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
        await new Promise<void>((resolve2, reject2) => {
          const tx2 = db.transaction('tessera_data', 'readwrite');
          tx2.objectStore('tessera_data').delete([record.store, record.key]);
          tx2.oncomplete = (): void => {
            resolve2();
          };
          /* v8 ignore next 4 */
          tx2.addEventListener('error', (): void => {
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

    // eslint-disable-next-line security/detect-object-injection
    const defaults = SENSITIVITY_DEFAULTS[sensitivity];
    const ttl = options?.ttl ?? defaults?.ttl ?? this.config.defaults?.ttl;
    /* v8 ignore next */
    if (ttl !== undefined) meta.ttl = ttl;

    const maxReads = options?.maxReads ?? defaults?.maxReads ?? this.config.defaults?.maxReads;
    /* v8 ignore next */
    if (maxReads !== undefined) meta.maxReads = maxReads;

    /* v8 ignore next 3 */
    const onSuspicion =
      options?.onSuspicion ?? this.config.defaults?.onSuspicion ?? DEFAULT_ON_SUSPICION;
    if (onSuspicion !== undefined) meta.onSuspicion = onSuspicion;

    const hlSoft = options?.halfLife?.soft ?? defaults?.halfLifeSoft;
    if (hlSoft !== undefined) meta.halfLifeSoft = hlSoft;

    const hlHard = options?.halfLife?.hard ?? this.config.halfLife?.hard;
    /* v8 ignore next */
    if (hlHard !== undefined) meta.halfLifeHard = hlHard;

    return meta;
  }

  private prepareHoneyKeys(): string[] {
    const mgr = this.honeyManager as HoneyKeyManager | null;
    /* v8 ignore next */
    if (!mgr?.isEnabled) return [];
    const needed = this.config.honeyKeys.count;
    /* v8 ignore next */
    if (needed <= 0) return [];
    const honeyStorageKeys = mgr.generateHoneyKeys('idb', [], needed);
    for (const storageKey of honeyStorageKeys) {
      mgr.assignDecoyAlias('idb', storageKey, []);
    }
    return honeyStorageKeys;
  }

  async cleanOrphanedHoneyKeys(): Promise<void> {
    try {
      /* v8 ignore next */
      if (typeof indexedDB === 'undefined') return;
      const cryptoKey = this.session.getKeySafe();
      if (!cryptoKey) return;

      const db = await this.getDb();
      const allRecords = await new Promise<Array<{ store: string; key: string; value: string }>>(
        (resolve, reject) => {
          const records: Array<{ store: string; key: string; value: string }> = [];
          const tx = db.transaction('tessera_data', 'readonly');
          const objStore = tx.objectStore('tessera_data');
          const req = objStore.openCursor();
          req.onsuccess = (): void => {
            const cursor = req.result;
            if (cursor) {
              records.push(cursor.value as { store: string; key: string; value: string });
              cursor.continue();
            }
          };
          tx.oncomplete = (): void => resolve(records);
          /* v8 ignore next 2 */
          tx.addEventListener('error', (): void => reject());
        },
      );

      for (const record of allRecords) {
        if (this.session.getKeySafe() === null) return;
        if (this.honeyManager?.isHoney('idb', record.key)) continue;
        const dotIdx = record.value.indexOf('.');
        if (dotIdx === -1) continue;
        const metaResult = await decryptFull(cryptoKey, record.value.slice(0, dotIdx));
        if (!metaResult.ok) continue;
        try {
          JSON.parse(metaResult.value);
        } catch {
          // Decrypts but is not valid JSON — orphaned IDB honey key from a previous session
          await new Promise<void>((resolve) => {
            const delTx = db.transaction('tessera_data', 'readwrite');
            delTx.objectStore('tessera_data').delete([record.store, record.key]);
            delTx.oncomplete = (): void => resolve();
            /* v8 ignore next */
            delTx.addEventListener('error', (): void => resolve()); // best-effort
          });
        }
      }
    } catch {
      // Background task — never propagate errors
    }
  }

  /**
   * Remove orphaned `_splits` IDB entries whose sessionStorage pointer no
   * longer exists (e.g. the session was cleared or the tab was closed after a split
   * write but before the corresponding remove).
   *
   * An entry is considered orphaned when `sessionStorage.getItem(storageKey)` does
   * NOT start with `'split:'`.
   */
  async cleanOrphanedSplits(): Promise<void> {
    if (typeof indexedDB === 'undefined' || typeof sessionStorage === 'undefined') return;

    const db = await this.getDb();
    const orphanKeys = await new Promise<Array<[string, string]>>((resolve, reject) => {
      const keys: Array<[string, string]> = [];
      const tx = db.transaction('_splits', 'readonly');
      const store = tx.objectStore('_splits');
      const req = store.openCursor();
      req.onsuccess = (): void => {
        const cursor = req.result;
        if (cursor) {
          const record = cursor.value as { store: string; key: string };
          const rawSs = sessionStorage.getItem(record.key);
          if (rawSs === null || !rawSs.startsWith('split:')) {
            keys.push([record.store, record.key]);
          }
          cursor.continue();
        }
      };
      tx.oncomplete = (): void => resolve(keys);
      /* v8 ignore next 2 */
      tx.addEventListener('error', (): void => reject());
    });

    if (orphanKeys.length === 0) return;

    for (const compoundKey of orphanKeys) {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction('_splits', 'readwrite');
        tx.objectStore('_splits').delete(compoundKey);
        tx.oncomplete = (): void => resolve();
        /* v8 ignore next 2 */
        tx.addEventListener('error', (): void => reject());
      });
    }
  }

  /**
   * Remove orphaned `_claims` IDB entries whose claim token is no longer
   * referenced by any sessionStorage value (e.g. the session was cleared after a
   * claim write but before the corresponding remove).
   *
   * An entry is considered orphaned when no sessionStorage value equals
   * `'ref:' + token`.
   */
  async cleanOrphanedClaims(): Promise<void> {
    if (typeof indexedDB === 'undefined' || typeof sessionStorage === 'undefined') return;

    // Build a Set of all claim tokens currently alive in sessionStorage.
    const liveTokens = new Set<string>();
    for (let i = 0; i < sessionStorage.length; i++) {
      const val = sessionStorage.getItem(sessionStorage.key(i) ?? '') ?? '';
      if (val.startsWith('ref:')) {
        liveTokens.add(val.slice('ref:'.length));
      }
    }

    const db = await this.getDb();
    const orphanTokens = await new Promise<string[]>((resolve, reject) => {
      const tokens: string[] = [];
      const tx = db.transaction('_claims', 'readonly');
      const store = tx.objectStore('_claims');
      const req = store.openCursor();
      req.onsuccess = (): void => {
        const cursor = req.result;
        if (cursor) {
          const record = cursor.value as { token: string };
          if (!liveTokens.has(record.token)) {
            tokens.push(record.token);
          }
          cursor.continue();
        }
      };
      tx.oncomplete = (): void => resolve(tokens);
      /* v8 ignore next 2 */
      tx.addEventListener('error', (): void => reject());
    });

    if (orphanTokens.length === 0) return;

    for (const token of orphanTokens) {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction('_claims', 'readwrite');
        tx.objectStore('_claims').delete(token);
        tx.oncomplete = (): void => resolve();
        /* v8 ignore next 2 */
        tx.addEventListener('error', (): void => reject());
      });
    }
  }
}
