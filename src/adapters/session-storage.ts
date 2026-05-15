import {
  type IStorageAdapter,
  type StorageItemOptions,
  type ValueMetadata,
  type ResolvedConfig,
  type SensitivityLevel,
  type SuspicionAction,
  type HoneyKeyManagerIsh,
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
const CLAIM_PREFIX = 'ref:';

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

    if (raw.startsWith(CLAIM_PREFIX)) {
      return this.handleClaimRead(cryptoKey, raw, key, 'session');
    }

    const result = await this.readWithMetadata(cryptoKey, raw, key, 'session');
    return result;
  }

  async setItem(key: string, value: string, options?: StorageItemOptions): Promise<void> {
    const cryptoKey = this.session.getKey();
    const storageKey = await this.session.rotateKeyName(key);

    const mode = options?.mode ?? 'direct';

    if (mode === 'split') {
      await this.handleSplitWrite(cryptoKey, value, key, storageKey, options);
      this.keyRegistry.add(key);
      await this.addHoneyKeys('session');
      return;
    }

    if (mode === 'claim') {
      await this.handleClaimWrite(cryptoKey, value, key, storageKey, options);
      this.keyRegistry.add(key);
      await this.addHoneyKeys('session');
      return;
    }

    const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
    const metadata = this.buildMeta(sensitivity, options);

    const packed = await this.packageValue(cryptoKey, value, metadata);
    this.rawSetItem(storageKey, packed);
    this.keyRegistry.add(key);
    this.sensitivityRegistry.set(key, sensitivity);
    this.session.touch();
    await this.addHoneyKeys('session');
  }

  async removeItem(key: string): Promise<void> {
    if (this.session.isLocked()) return;
    const storageKey = await this.session.rotateKeyNameSafe(key);
    if (storageKey === null) return;
    const raw = this.rawGetItem(storageKey);

    if (raw?.startsWith(CLAIM_PREFIX) && this.idb) {
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

  async clear(): Promise<void> {
    sessionStorage.clear();
    this.keyRegistry.clear();
    if (this.honeyManager && 'clearBackend' in this.honeyManager) {
      (this.honeyManager as HoneyKeyManager).clearBackend('session');
    }
  }

  async keys(): Promise<string[]> {
    return [...this.keyRegistry];
  }

  async getRawKey(developerKey: string): Promise<string> {
    if (this.session.isLocked()) return developerKey;
    return this.session.rotateKeyName(developerKey);
  }

  private async handleSplitWrite(
    cryptoKey: CryptoKey,
    value: string,
    _key: string,
    storageKey: string,
    options?: StorageItemOptions,
  ): Promise<void> {
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
    if (!raw || !this.idb) return null;

    // FIX 3: Decrypt Share A before using it.
    const encryptedShareA = raw.slice(SPLIT_PREFIX.length);
    if (!encryptedShareA) return null;
    const decryptResult = await decryptFull(_cryptoKey, encryptedShareA);
    if (!decryptResult.ok) return null;
    const shareABase64 = decryptResult.value;

    const packedShareB = (await this.idb.get('_splits', storageKey)) as string | undefined;
    if (!packedShareB) return null;

    const shareBResult = await this.readWithMetadata(_cryptoKey, packedShareB, _key, 'session');
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
    const token = generateClaimToken();
    this.rawSetItem(storageKey, `${CLAIM_PREFIX}${token}`);

    if (this.idb) {
      const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
      const meta = this.buildMeta(sensitivity, options);
      const packed = await this.packageValue(cryptoKey, value, meta);
      await this.idb.put('_claims', token, packed);
    }
  }

  private async handleClaimRead(
    cryptoKey: CryptoKey,
    raw: string,
    key: string,
    _backend: string,
  ): Promise<string | null> {
    const token = raw.slice(CLAIM_PREFIX.length);
    if (!token || !this.idb) return null;

    const packed = (await this.idb.get('_claims', token)) as string | undefined;
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
      return null;
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
    if (storageKey === null) return;
    const raw = this.rawGetItem(storageKey);
    if (raw === null) return;
    const dotIdx = raw.indexOf('.');
    if (dotIdx === -1) return;
    const valueB64 = raw.slice(dotIdx + 1);
    const metaStr = JSON.stringify(metadata);
    const encryptedMeta = await encryptWithSalt(cryptoKey, metaStr);
    this.rawSetItem(storageKey, `${encryptedMeta}.${valueB64}`);
  }

  private async addHoneyKeys(backend: string): Promise<void> {
    const mgr = this.honeyManager as HoneyKeyManager | null;
    if (!mgr?.isEnabled) return;
    const needed = this.config.honeyKeys.count - mgr.allKeys(backend).length;
    if (needed <= 0) return;
    const cryptoKey = this.session.getKeySafe();
    if (!cryptoKey) return;
    const existing = await this.keys();
    const honeyKeys = mgr.generateHoneyKeys(backend, existing, needed);
    for (const honeyKey of honeyKeys) {
      const ct = await generateHoneyCiphertext(cryptoKey);
      this.rawSetItem(honeyKey, ct);
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
