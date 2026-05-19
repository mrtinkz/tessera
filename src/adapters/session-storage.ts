import {
  type IStorageAdapter,
  type StorageItemOptions,
  type ValueMetadata,
  type ExportedItem,
  type ResolvedConfig,
  type SensitivityLevel,
  type SuspicionAction,
  type HoneyKeyManagerIsh,
  TesseraError,
  TesseraErrorCode,
  CLAIM_TOKEN_PREFIX,
} from '../types';
import { type KeySession } from '../core/session';
import { encryptWithSalt, decryptFull, generateHoneyCiphertext } from '../core/crypto';
import { type TesseraEmitter } from '../core/events';
import { type SuspicionEngine } from '../core/suspicion';
import { type HoneyKeyManager } from '../storage/honey';
import { type IndexedDbAdapter } from './indexed-db';
import { hardWipe } from '../core/wipe';
import { splitValue, reconstructValue, shareToBase64, base64ToShare } from '../core/splitter';
import { generateClaimToken, extractTokenId } from '../storage/claim';
import { SENSITIVITY_DEFAULTS } from '../types';

const DEFAULT_ON_SUSPICION: SuspicionAction = 'wipe';
const SPLIT_PREFIX = 'split:';
// CLAIM_TOKEN_PREFIX ('ref:') is the canonical constant from types.ts — no local duplicate.

export class SessionStorageAdapter implements IStorageAdapter {
  private honeyManager: HoneyKeyManagerIsh | null = null;
  private idb: IndexedDbAdapter | null = null;
  private keyRegistry = new Set<string>();
  private sensitivityRegistry = new Map<string, SensitivityLevel>();

  constructor(
    private config: ResolvedConfig,
    private session: KeySession,
    private events: TesseraEmitter,
    private suspicion?: SuspicionEngine,
  ) {}

  setHoneyManager(manager: HoneyKeyManagerIsh): void {
    this.honeyManager = manager;
  }

  setIdbAdapter(adapter: IndexedDbAdapter): void {
    this.idb = adapter;
  }

  private rawSetItem(key: string, value: string): void {
    sessionStorage.setItem(key, value);
  }

  private rawGetItem(key: string): string | null {
    return sessionStorage.getItem(key);
  }

  private rawRemoveItem(key: string): void {
    sessionStorage.removeItem(key);
  }

  async getItem(key: string): Promise<string | null> {
    const cryptoKey = this.session.getKeySafe();
    if (cryptoKey === null) return null;

    if (this.suspicion) {
      const rateCheck = this.suspicion.checkRateLimit();
      if (
        !rateCheck.ok &&
        rateCheck.callsPerSecond > this.config.suspicion.rateLimit.callsPerSecond * 1.5
      ) {
        return null;
      }
    }

    if (this.honeyManager?.isDecoyAlias('session', key)) {
      this.suspicion?.recordHoneyHit('session');
      return null;
    }

    const storageKey = await this.session.rotateKeyNameSafe(key);
    if (storageKey === null) return null;
    const raw = this.rawGetItem(storageKey);
    if (raw === null) return null;

    if (this.honeyManager?.isHoney('session', storageKey)) {
      this.suspicion?.recordHoneyHit('session');
      return null;
    }

    if (raw.startsWith(SPLIT_PREFIX)) {
      return this.handleSplitRead(cryptoKey, raw, key, 'session', storageKey);
    }

    if (raw.startsWith(CLAIM_TOKEN_PREFIX)) {
      return this.handleClaimRead(cryptoKey, raw, key, 'session');
    }

    const result = await this.readWithMetadata(cryptoKey, raw, key, 'session');
    return result;
  }

  async setItem(key: string, value: string, options?: StorageItemOptions): Promise<void> {
    const cryptoKey = this.session.getKey();
    const storageKey = await this.session.rotateKeyName(key);

    if (this.config.maxValueBytes !== undefined) {
      const byteLength = new TextEncoder().encode(value).byteLength;
      if (byteLength > this.config.maxValueBytes) {
        throw new TesseraError(
          TesseraErrorCode.VALIDATION_ERROR,
          `Value for '${key}' is ${byteLength} bytes, exceeds maxValueBytes (${this.config.maxValueBytes}).`,
        );
      }
    }
    if (this.config.onBeforeWrite !== undefined && !this.config.onBeforeWrite(key, value)) {
      throw new TesseraError(
        TesseraErrorCode.VALIDATION_ERROR,
        `Write for key '${key}' was rejected by onBeforeWrite.`,
      );
    }

    const mode = options?.mode ?? 'direct';

    if (mode === 'split') {
      await this.handleSplitWrite(cryptoKey, value, key, storageKey, options);
      this.keyRegistry.add(key);
      this.session.touch(); // reset idle timer on split writes
      await this.writeHoneyKeysInterleaved('session', storageKey, cryptoKey);
      return;
    }

    if (mode === 'claim') {
      await this.handleClaimWrite(cryptoKey, value, key, storageKey, options);
      this.keyRegistry.add(key);
      this.session.touch(); // reset idle timer on claim writes
      await this.writeHoneyKeysInterleaved('session', storageKey, cryptoKey);
      return;
    }

    const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
    const metadata = this.buildMeta(sensitivity, options);

    // Prepare honey keys and generate all ciphertexts in parallel with the real key.
    const honeyKeys = this.prepareHoneyKeys('session');
    const allCts = await Promise.all([
      this.packageValue(cryptoKey, value, metadata),
      ...honeyKeys.map(() => generateHoneyCiphertext(cryptoKey)),
    ]);
    const packed = allCts[0]!;
    const honeyCts = allCts.slice(1);

    // Write real key and honey keys in random order — no fixed creation pattern.
    const writes: Array<[string, string]> = [
      [storageKey, packed],
      ...honeyKeys.map((hk, i) => [hk, honeyCts[i]!] as [string, string]),
    ];
    for (let i = writes.length - 1; i > 0; i--) {
      const j = crypto.getRandomValues(new Uint8Array(1))[0]! % (i + 1);
      // eslint-disable-next-line security/detect-object-injection
      [writes[i]!, writes[j]!] = [writes[j]!, writes[i]!];
    }
    for (const [k, v] of writes) {
      this.rawSetItem(k, v);
    }

    this.keyRegistry.add(key);
    this.sensitivityRegistry.set(key, sensitivity);
    this.session.touch();
  }

  async removeItem(key: string): Promise<void> {
    if (this.session.isLocked()) return;
    const storageKey = await this.session.rotateKeyNameSafe(key);
    if (storageKey === null) return;
    const raw = this.rawGetItem(storageKey);

    if (raw?.startsWith(CLAIM_TOKEN_PREFIX) && this.idb) {
      const token = extractTokenId(raw);
      await this.idb.remove('_claims', token).catch(() => {});
    }

    await hardWipe(
      { setItem: (k, v) => this.rawSetItem(k, v), removeItem: (k) => this.rawRemoveItem(k) },
      storageKey,
    );
    this.keyRegistry.delete(key);
    this.sensitivityRegistry.delete(key);
    this.honeyManager?.remove('session', storageKey);
    this.events?.emit('key-wiped', { keyAlias: key, backend: 'session', reason: 'removed' });
  }

  async wipeAll(wiped: string[]): Promise<void> {
    const backend = {
      setItem: (k: string, v: string): void => this.rawSetItem(k, v),
      removeItem: (k: string): void => this.rawRemoveItem(k),
    };
    const storageKeys: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      /* v8 ignore next */
      if (k?.startsWith('t_')) storageKeys.push(k);
    }
    for (const storageKey of storageKeys) {
      await hardWipe(backend, storageKey);
      wiped.push(`session:${storageKey}`);
    }
    this.keyRegistry.clear();
    this.sensitivityRegistry.clear();
    if (this.honeyManager && 'clearBackend' in this.honeyManager) {
      (this.honeyManager as HoneyKeyManager).clearBackend('session');
    }
  }

  async wipeHighSensitivity(wiped: string[]): Promise<void> {
    const cryptoKey = this.session.getKeySafe();
    if (!cryptoKey) return;

    const storageKeys: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k?.startsWith('t_')) storageKeys.push(k);
    }

    for (const storageKey of storageKeys) {
      if (this.honeyManager?.isHoney('session', storageKey)) continue;
      const raw = this.rawGetItem(storageKey);
      if (!raw || raw.startsWith('split:') || raw.startsWith('ref:')) continue;
      const dotIdx = raw.indexOf('.');
      if (dotIdx === -1) continue;
      const metaResult = await decryptFull(cryptoKey, raw.slice(0, dotIdx));
      if (!metaResult.ok) continue;
      let meta: ValueMetadata;
      try {
        meta = JSON.parse(metaResult.value) as ValueMetadata;
      } catch {
        continue;
      }
      if (meta.sensitivity === 'high' || meta.sensitivity === 'critical') {
        await hardWipe(
          { setItem: (k, v) => this.rawSetItem(k, v), removeItem: (k) => this.rawRemoveItem(k) },
          storageKey,
        );
        wiped.push(`session:${storageKey}`);
      }
    }

    for (const [key, sensitivity] of this.sensitivityRegistry) {
      if (sensitivity === 'high' || sensitivity === 'critical') {
        this.keyRegistry.delete(key);
        this.sensitivityRegistry.delete(key);
      }
    }
  }

  async cleanOrphanedHoneyKeys(): Promise<void> {
    try {
      const cryptoKey = this.session.getKeySafe();
      if (!cryptoKey) return;
      const storageKeys: string[] = [];
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        /* v8 ignore next */
        if (k?.startsWith('t_')) storageKeys.push(k);
      }
      for (const storageKey of storageKeys) {
        if (this.session.getKeySafe() === null) return;
        if (this.honeyManager?.isHoney('session', storageKey)) continue;
        const raw = this.rawGetItem(storageKey);
        if (!raw || raw.startsWith(SPLIT_PREFIX) || raw.startsWith(CLAIM_TOKEN_PREFIX)) continue;
        const dotIdx = raw.indexOf('.');
        if (dotIdx === -1) continue;
        const metaResult = await decryptFull(cryptoKey, raw.slice(0, dotIdx));
        if (!metaResult.ok) continue;
        try {
          JSON.parse(metaResult.value);
        } catch {
          await hardWipe(
            { setItem: (k, v) => this.rawSetItem(k, v), removeItem: (k) => this.rawRemoveItem(k) },
            storageKey,
          );
        }
      }
    } catch {
      // Background task — never propagate errors
    }
  }

  async clear(): Promise<void> {
    sessionStorage.clear();
    this.keyRegistry.clear();
    if (this.honeyManager && 'clearBackend' in this.honeyManager) {
      (this.honeyManager as HoneyKeyManager).clearBackend('session');
    }
  }

  async keys(): Promise<string[]> {
    const decoys = this.honeyManager?.allDecoyAliases('session') ?? [];
    return [...this.keyRegistry, ...decoys];
  }

  async getRawKey(developerKey: string): Promise<string> {
    if (!this.config.debug) {
      throw new Error('getRawKey is only available in debug mode. Set config.debug = true.');
    }
    if (this.session.isLocked()) return developerKey;
    return this.session.rotateKeyName(developerKey);
  }

  async exportItem(alias: string): Promise<ExportedItem | null> {
    const cryptoKey = this.session.getKeySafe();
    if (cryptoKey === null) return null;

    if (this.honeyManager?.isDecoyAlias('session', alias)) {
      this.suspicion?.recordHoneyHit('session');
      return null;
    }

    const storageKey = await this.session.rotateKeyNameSafe(alias);
    if (storageKey === null) return null;

    if (this.honeyManager?.isHoney('session', storageKey)) return null;

    const raw = this.rawGetItem(storageKey);
    if (raw === null) return null;

    if (raw.startsWith(SPLIT_PREFIX) || raw.startsWith(CLAIM_TOKEN_PREFIX)) return null;

    const dotIdx = raw.indexOf('.');
    if (dotIdx === -1) return null;

    const metaB64 = raw.slice(0, dotIdx);
    const valueB64 = raw.slice(dotIdx + 1);

    const metaResult = await decryptFull(cryptoKey, metaB64);
    if (!metaResult.ok) {
      this.suspicion?.recordHmacFailure();
      this.events?.emit('hmac-failure', { keyAlias: alias, backend: 'session' });
      await this.removeItem(alias);
      return null;
    }

    const metadata: ValueMetadata = JSON.parse(metaResult.value);
    if (typeof metadata.readCount !== 'number' || !Number.isFinite(metadata.readCount)) {
      metadata.readCount = 0;
    }

    if (metadata.ttl !== undefined && Date.now() - metadata.writeTime > metadata.ttl) {
      this.events?.emit('key-expired', {
        keyAlias: alias,
        backend: 'session',
        expiredAt: metadata.writeTime + metadata.ttl,
      });
      await this.removeItem(alias);
      return null;
    }

    if (metadata.maxReads !== undefined && metadata.readCount >= metadata.maxReads) {
      this.events?.emit('max-reads-reached', {
        keyAlias: alias,
        backend: 'session',
        reads: metadata.readCount,
      });
      await this.removeItem(alias);
      return null;
    }

    if (
      metadata.halfLifeHard !== undefined &&
      Date.now() - metadata.writeTime > metadata.halfLifeHard
    ) {
      this.events?.emit('key-expired', {
        keyAlias: alias,
        backend: 'session',
        expiredAt: metadata.writeTime + metadata.halfLifeHard,
      });
      await this.removeItem(alias);
      return null;
    }

    if (
      metadata.halfLifeSoft !== undefined &&
      Date.now() - metadata.writeTime > metadata.halfLifeSoft
    ) {
      this.events?.emit('reconfirmation-required', {
        keyAlias: alias,
        softThresholdMs: metadata.halfLifeSoft,
        elapsedMs: Date.now() - metadata.writeTime,
      });
      return null;
    }

    const valueResult = await decryptFull(cryptoKey, valueB64);
    if (!valueResult.ok) {
      this.suspicion?.recordHmacFailure();
      this.events?.emit('hmac-failure', { keyAlias: alias, backend: 'session' });
      await this.applyOnSuspicion(metadata.onSuspicion, alias, 'session');
      return null;
    }

    const exported: ExportedItem = {
      value: valueResult.value,
      writeTime: metadata.writeTime,
      readCount: metadata.readCount,
    };
    if (metadata.sensitivity !== undefined) exported.sensitivity = metadata.sensitivity;
    if (metadata.ttl !== undefined) exported.ttl = metadata.ttl;
    if (metadata.maxReads !== undefined) exported.maxReads = metadata.maxReads;
    if (metadata.onSuspicion !== undefined) exported.onSuspicion = metadata.onSuspicion;
    if (metadata.halfLifeSoft !== undefined) exported.halfLifeSoft = metadata.halfLifeSoft;
    if (metadata.halfLifeHard !== undefined) exported.halfLifeHard = metadata.halfLifeHard;
    return exported;
  }

  private async handleSplitWrite(
    cryptoKey: CryptoKey,
    value: string,
    _key: string,
    storageKey: string,
    options?: StorageItemOptions,
  ): Promise<void> {
    // IDB is required for split mode — share B cannot be stored without it.
    // Throwing here prevents a silent write that would appear to succeed but is
    // permanently unreadable on getItem.
    if (!this.idb) {
      throw new TesseraError(
        TesseraErrorCode.UNSUPPORTED_ENV,
        'split mode requires IndexedDB. IDB is unavailable in this environment (private/incognito mode or security policy).',
      );
    }

    const { shareA, shareB } = splitValue(value);
    const shareABase64 = shareToBase64(shareA);

    // FIX 3: Encrypt Share A before storing in sessionStorage.
    const encryptedShareA = await encryptWithSalt(cryptoKey, shareABase64);
    this.rawSetItem(storageKey, `${SPLIT_PREFIX}${encryptedShareA}`);

    if (this.idb) {
      const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
      const meta = this.buildMeta(sensitivity, options);
      const packedShareB = await this.packageValue(cryptoKey, shareToBase64(shareB), meta);
      await this.idb.put('_splits', storageKey, packedShareB);
    }
  }

  private async handleSplitRead(
    _cryptoKey: CryptoKey,
    raw: string,
    _key: string,
    _backend: string,
    storageKey: string,
  ): Promise<string | null> {
    /* v8 ignore next */
    if (!raw || !this.idb) return null;

    // FIX 3: Decrypt Share A before using it.
    const encryptedShareA = raw.slice(SPLIT_PREFIX.length);
    /* v8 ignore next */
    if (!encryptedShareA) return null;
    const decryptResult = await decryptFull(_cryptoKey, encryptedShareA);
    /* v8 ignore next */
    if (!decryptResult.ok) return null;
    const shareABase64 = decryptResult.value;

    const packedShareB = (await this.idb.get('_splits', storageKey)) as string | undefined;
    /* v8 ignore next */
    if (!packedShareB) return null;

    const shareBResult = await this.readWithMetadata(_cryptoKey, packedShareB, _key, 'session');
    /* v8 ignore next */
    if (shareBResult === null) return null;

    const shareA = base64ToShare(shareABase64);
    const shareB = base64ToShare(shareBResult);
    return reconstructValue(shareA, shareB);
  }

  private async handleClaimWrite(
    cryptoKey: CryptoKey,
    value: string,
    _key: string,
    storageKey: string,
    options?: StorageItemOptions,
  ): Promise<void> {
    // IDB is required for claim mode — the actual value lives in IDB.
    if (!this.idb) {
      throw new TesseraError(
        TesseraErrorCode.UNSUPPORTED_ENV,
        'claim mode requires IndexedDB. IDB is unavailable in this environment (private/incognito mode or security policy).',
      );
    }

    const token = generateClaimToken();
    this.rawSetItem(storageKey, `${CLAIM_TOKEN_PREFIX}${token}`);

    const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
    const meta = this.buildMeta(sensitivity, options);
    const packed = await this.packageValue(cryptoKey, value, meta);
    await this.idb.put('_claims', token, packed);
  }

  private async handleClaimRead(
    cryptoKey: CryptoKey,
    raw: string,
    key: string,
    _backend: string,
  ): Promise<string | null> {
    const token = raw.slice(CLAIM_TOKEN_PREFIX.length);
    /* v8 ignore next */
    if (!token || !this.idb) return null;

    const packed = (await this.idb.get('_claims', token)) as string | undefined;
    /* v8 ignore next */
    if (!packed) return null;

    return this.readWithMetadata(cryptoKey, packed as string, key, 'session');
  }

  private async readWithMetadata(
    cryptoKey: CryptoKey,
    raw: string,
    keyAlias: string,
    backend: string,
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
      await this.removeItem(keyAlias);
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
      await this.removeItem(keyAlias);
      return null;
    }

    if (metadata.maxReads !== undefined && metadata.readCount >= metadata.maxReads) {
      this.events?.emit('max-reads-reached', { keyAlias, backend, reads: metadata.readCount });
      await this.removeItem(keyAlias);
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
      await this.removeItem(keyAlias);
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
      await this.applyOnSuspicion(metadata.onSuspicion, keyAlias, backend);
      return null;
    }

    metadata.readCount += 1;
    await this.updateMetadata(cryptoKey, keyAlias, metadata, backend);

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
    _backend: string,
  ): Promise<void> {
    const storageKey = await this.session.rotateKeyNameSafe(keyAlias);
    /* v8 ignore next */
    if (storageKey === null) return;
    const raw = this.rawGetItem(storageKey);
    /* v8 ignore next */
    if (raw === null) return;
    const dotIdx = raw.indexOf('.');
    /* v8 ignore next */
    if (dotIdx === -1) return;
    const valueB64 = raw.slice(dotIdx + 1);
    const metaStr = JSON.stringify(metadata);
    const encryptedMeta = await encryptWithSalt(cryptoKey, metaStr);
    this.rawSetItem(storageKey, `${encryptedMeta}.${valueB64}`);
  }

  private prepareHoneyKeys(backend: string): string[] {
    const mgr = this.honeyManager as HoneyKeyManager | null;
    if (!mgr?.isEnabled) return [];
    const needed = this.config.honeyKeys.count;
    if (needed <= 0) return [];
    const existingAliases = [...this.keyRegistry];
    const honeyStorageKeys = mgr.generateHoneyKeys(backend, existingAliases, needed);
    for (const storageKey of honeyStorageKeys) {
      mgr.assignDecoyAlias(backend, storageKey, existingAliases);
    }
    return honeyStorageKeys;
  }

  /** For split/claim modes: honey keys have no natural interleave point, so write them after. */
  private async writeHoneyKeysInterleaved(
    backend: string,
    _realStorageKey: string,
    cryptoKey: CryptoKey,
  ): Promise<void> {
    const honeyKeys = this.prepareHoneyKeys(backend);
    if (honeyKeys.length === 0) return;
    const honeyCts = await Promise.all(honeyKeys.map(() => generateHoneyCiphertext(cryptoKey)));
    for (const [i, hk] of honeyKeys.entries()) {
      // eslint-disable-next-line security/detect-object-injection
      this.rawSetItem(hk, honeyCts[i]!);
    }
  }

  private async applyOnSuspicion(
    action: SuspicionAction | undefined,
    keyAlias: string,
    backend: string,
  ): Promise<void> {
    if (action === 'lock') {
      this.session.lock();
      this.events?.emit('vault-locked', { reason: `suspicion: hmac-failure on ${keyAlias}` });
    } else if (action === 'throw') {
      // Leave the key intact; caller returns null.
    } else {
      await this.removeItem(keyAlias);
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
}
