import {
  type ICookieAdapter,
  type CookieOptions,
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
import { type IndexedDbAdapter } from './indexed-db';
import { type HoneyKeyManager } from '../storage/honey';
import { hardWipe } from '../core/wipe';
import { generateClaimToken, extractTokenId } from '../storage/claim';
import { SENSITIVITY_DEFAULTS } from '../types';

const DEFAULT_ON_SUSPICION: SuspicionAction = 'wipe';
const CLAIM_PREFIX = 'ref:';

export class CookieAdapter implements ICookieAdapter {
  private idb: IndexedDbAdapter | null = null;
  private honeyManager: HoneyKeyManagerIsh | null = null;
  private cookieNames = new Set<string>();
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

  async get(name: string): Promise<string | null> {
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

    const raw = this.readRaw(name);
    if (raw === null) return null;

    const value = decodeURIComponent(raw);

    if (value.startsWith(CLAIM_PREFIX)) {
      return this.handleClaimRead(cryptoKey, value, name);
    }

    const dotIdx = value.indexOf('.');
    if (dotIdx === -1) {
      const legacyResult = await decryptFull(cryptoKey, value);
      if (legacyResult.ok) return legacyResult.value;
      return null;
    }

    const result = await this.readWithMetadata(cryptoKey, value, name, 'cookie');
    return result;
  }

  async set(
    name: string,
    value: string,
    options?: CookieOptions & StorageItemOptions,
  ): Promise<void> {
    const cryptoKey = this.session.getKey();
    this.cookieNames.add(name);

    const mode = options?.mode ?? 'direct';

    if (mode === 'claim') {
      await this.handleClaimWrite(cryptoKey, value, name, options);
      this.scheduleHoneyKeys();
      return;
    }

    const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
    const metadata = this.buildMeta(sensitivity, options);
    this.sensitivityRegistry.set(name, sensitivity);

    const packed = await this.packageValue(cryptoKey, value, metadata);
    this.writeCookie(name, packed, options);
    this.session.touch();
    this.scheduleHoneyKeys();
  }

  private scheduleHoneyKeys(): void {
    const mgr = this.honeyManager as HoneyKeyManager | null;
    if (!mgr?.isEnabled) return;
    const needed = this.config.honeyKeys.count - mgr.allKeys('cookie').length;
    if (needed <= 0) return;
    const existingAliases = [...this.cookieNames];
    const honeyStorageKeys = mgr.generateHoneyKeys('cookie', existingAliases, needed);
    for (const storageKey of honeyStorageKeys) {
      mgr.assignDecoyAlias('cookie', storageKey, existingAliases);
      const delay = 50 + Math.floor(Math.random() * 1950);
      setTimeout(() => {
        void this.writeHoneyCookie(storageKey);
      }, delay);
    }
  }

  private async writeHoneyCookie(storageKey: string): Promise<void> {
    const cryptoKey = this.session.getKeySafe();
    if (!cryptoKey) return;
    const ct = await generateHoneyCiphertext(cryptoKey);
    // Don't write if wipeAll cleared the registry (e.g. lockdown fired during crypto)
    if (!this.honeyManager?.isHoney('cookie', storageKey)) return;
    this.writeCookieRaw(storageKey, ct);
  }

  async remove(name: string): Promise<void> {
    const raw = this.readRaw(name);

    if (raw && this.idb) {
      const value = decodeURIComponent(raw);
      if (value.startsWith(CLAIM_PREFIX)) {
        const token = extractTokenId(value);
        await this.idb.remove('_claims', token).catch(() => {});
      }
    }

    // Overwrite with noise before expiring for best-effort forensic mitigation.
    await hardWipe(
      {
        setItem: (k, v) => this.writeCookieRaw(k, v),
        removeItem: (k) => this.writeCookieExpired(k),
      },
      name,
    );

    this.events?.emit('key-wiped', { keyAlias: name, backend: 'cookie', reason: 'removed' });
  }

  private async handleClaimWrite(
    cryptoKey: CryptoKey,
    value: string,
    name: string,
    options?: CookieOptions & StorageItemOptions,
  ): Promise<void> {
    const token = generateClaimToken();
    this.writeCookie(name, `${CLAIM_PREFIX}${token}`, options);

    if (this.idb) {
      const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
      const meta = this.buildMeta(sensitivity, options);
      const packed = await this.packageValue(cryptoKey, value, meta);
      await this.idb.put('_claims', token, packed);
    }
  }

  private async handleClaimRead(
    cryptoKey: CryptoKey,
    value: string,
    name: string,
  ): Promise<string | null> {
    const token = value.slice(CLAIM_PREFIX.length);
    if (!token || !this.idb) return null;

    const packed = (await this.idb.get('_claims', token)) as string | undefined;
    if (!packed) return null;

    return this.readWithMetadata(cryptoKey, packed as string, name, 'cookie');
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
      await this.remove(keyAlias);
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
      await this.remove(keyAlias);
      return null;
    }

    if (metadata.maxReads !== undefined && metadata.readCount >= metadata.maxReads) {
      this.events?.emit('max-reads-reached', { keyAlias, backend, reads: metadata.readCount });
      await this.remove(keyAlias);
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
      await this.remove(keyAlias);
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
    await this.updateMetadata(cryptoKey, keyAlias, metadata);

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
  ): Promise<void> {
    const raw = this.readRaw(keyAlias);
    /* v8 ignore next */
    if (raw === null) return;
    const value = decodeURIComponent(raw);
    const dotIdx = value.indexOf('.');
    /* v8 ignore next */
    if (dotIdx === -1) return;
    const valueB64 = value.slice(dotIdx + 1);
    const metaStr = JSON.stringify(metadata);
    const encryptedMeta = await encryptWithSalt(cryptoKey, metaStr);
    this.writeCookie(keyAlias, `${encryptedMeta}.${valueB64}`);
  }

  private writeCookie(name: string, value: string, options?: CookieOptions): void {
    const parts: string[] = [];
    parts.push(`${encodeURIComponent(name)}=${encodeURIComponent(value)}`);

    if (options?.expires !== undefined) {
      const date = new Date();
      date.setDate(date.getDate() + options.expires);
      parts.push(`expires=${date.toUTCString()}`);
    }

    if (options?.path !== undefined) {
      parts.push(`path=${options.path}`);
    }

    if (options?.domain !== undefined) {
      parts.push(`domain=${options.domain}`);
    }

    if (options?.sameSite !== undefined) {
      parts.push(`SameSite=${options.sameSite}`);
    }

    if (options?.secure === true) {
      parts.push('Secure');
    }

    document.cookie = parts.join('; ');
  }

  private writeCookieRaw(key: string, value: string): void {
    document.cookie = `${encodeURIComponent(key)}=${encodeURIComponent(value)}; path=/`;
  }

  private writeCookieExpired(key: string): void {
    document.cookie = `${encodeURIComponent(key)}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  }

  readRaw(name: string): string | null {
    const encodedName = encodeURIComponent(name);
    const cookies = document.cookie.split('; ');
    for (const cookie of cookies) {
      const eqIdx = cookie.indexOf('=');
      if (eqIdx === -1) continue;
      const cookieName = cookie.slice(0, eqIdx);
      if (cookieName === encodedName) {
        return cookie.slice(eqIdx + 1);
      }
    }
    return null;
  }

  async wipeAll(wiped: string[]): Promise<void> {
    const backend = {
      setItem: (k: string, v: string): void => this.writeCookieRaw(k, v),
      removeItem: (k: string): void => this.writeCookieExpired(k),
    };
    // Wipe real cookies tracked in the in-session registry
    for (const name of this.cookieNames) {
      await hardWipe(backend, name);
      wiped.push(`cookie:${name}`);
    }
    // Wipe honey cookies (t_-prefixed, not in cookieNames)
    for (const name of this.allTCookieNames()) {
      if (!this.cookieNames.has(name)) {
        await hardWipe(backend, name);
        wiped.push(`cookie:${name}`);
      }
    }
    this.cookieNames.clear();
    this.sensitivityRegistry.clear();
    if (this.honeyManager && 'clearBackend' in this.honeyManager) {
      (this.honeyManager as import('../storage/honey').HoneyKeyManager).clearBackend('cookie');
    }
  }

  async wipeHighSensitivity(wiped: string[]): Promise<void> {
    for (const [name, sensitivity] of this.sensitivityRegistry) {
      if (sensitivity === 'high' || sensitivity === 'critical') {
        await this.remove(name);
        wiped.push(`cookie:${name}`);
        this.cookieNames.delete(name);
        this.sensitivityRegistry.delete(name);
      }
    }
  }

  async cleanOrphanedHoneyKeys(): Promise<void> {
    try {
      const cryptoKey = this.session.getKeySafe();
      if (!cryptoKey) return;
      const cookieNames = this.allTCookieNames();
      for (const name of cookieNames) {
        if (this.session.getKeySafe() === null) return;
        if (this.honeyManager?.isHoney('cookie', name)) continue;
        const raw = this.readRaw(name);
        if (!raw) continue;
        const value = decodeURIComponent(raw);
        if (value.startsWith(CLAIM_PREFIX)) continue;
        const dotIdx = value.indexOf('.');
        if (dotIdx === -1) continue;
        const metaResult = await decryptFull(cryptoKey, value.slice(0, dotIdx));
        if (!metaResult.ok) continue;
        try {
          JSON.parse(metaResult.value);
        } catch {
          await hardWipe(
            {
              setItem: (k, v) => this.writeCookieRaw(k, v),
              removeItem: (k) => this.writeCookieExpired(k),
            },
            name,
          );
        }
      }
    } catch {
      // Background task — never propagate errors
    }
  }

  private allTCookieNames(): string[] {
    const names: string[] = [];
    if (!document?.cookie) return names;
    for (const cookie of document.cookie.split('; ')) {
      const eqIdx = cookie.indexOf('=');
      if (eqIdx === -1) continue;
      const name = decodeURIComponent(cookie.slice(0, eqIdx));
      if (name.startsWith('t_')) names.push(name);
    }
    return names;
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
      await this.remove(keyAlias);
      this.events?.emit('key-wiped', { keyAlias, backend, reason: 'hmac-failure' });
    }
  }

  private buildMeta(
    sensitivity: SensitivityLevel,
    options?: CookieOptions & StorageItemOptions,
  ): ValueMetadata {
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
