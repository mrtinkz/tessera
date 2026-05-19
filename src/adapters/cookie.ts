import {
  type ICookieAdapter,
  type CookieOptions,
  type StorageItemOptions,
  type ValueMetadata,
  type ResolvedConfig,
  type SensitivityLevel,
  type SuspicionAction,
  type HoneyKeyManagerIsh,
  CLAIM_TOKEN_PREFIX,
  TesseraError,
  TesseraErrorCode,
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
// CLAIM_TOKEN_PREFIX ('ref:') is the canonical constant from types.ts — no local duplicate.

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

    // Decoy alias: a developer-visible fake name that maps to a honey storage key.
    if (this.honeyManager?.isDecoyAlias('cookie', name)) {
      this.suspicion?.recordHoneyHit('cookie');
      return null;
    }

    const raw = this.readRaw(name);
    if (raw === null) return null;

    // Storage-level honey check: catches direct access via the raw t_<hex> cookie name.
    if (this.honeyManager?.isHoney('cookie', name)) {
      this.suspicion?.recordHoneyHit('cookie');
      return null;
    }

    const value = decodeURIComponent(raw);

    if (value.startsWith(CLAIM_TOKEN_PREFIX)) {
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

    if (this.config.maxValueBytes !== undefined) {
      const byteLength = new TextEncoder().encode(value).byteLength;
      if (byteLength > this.config.maxValueBytes) {
        throw new TesseraError(
          TesseraErrorCode.VALIDATION_ERROR,
          `Value for '${name}' is ${byteLength} bytes, exceeds maxValueBytes (${this.config.maxValueBytes}).`,
        );
      }
    }
    if (this.config.onBeforeWrite !== undefined && !this.config.onBeforeWrite(name, value)) {
      throw new TesseraError(
        TesseraErrorCode.VALIDATION_ERROR,
        `Write for key '${name}' was rejected by onBeforeWrite.`,
      );
    }

    this.cookieNames.add(name);
    const mode = options?.mode ?? 'direct';

    if (mode === 'claim') {
      await this.handleClaimWrite(cryptoKey, value, name, options);
      await this.writeHoneyKeysInterleaved(cryptoKey);
      return;
    }

    const sensitivity = options?.sensitivity ?? this.config.defaultSensitivity ?? 'medium';
    const metadata = this.buildMeta(sensitivity, options);
    this.sensitivityRegistry.set(name, sensitivity);

    // Prepare honey keys and generate all ciphertexts in parallel with the real key.
    const honeyKeys = this.prepareHoneyKeys();
    const allCts = await Promise.all([
      this.packageValue(cryptoKey, value, metadata),
      ...honeyKeys.map(() => generateHoneyCiphertext(cryptoKey)),
    ]);
    const packed = allCts[0]!;
    const honeyCts = allCts.slice(1);

    // Write real cookie. Honey cookies use t_-prefixed names (already distinguishable by name)
    // but we still randomise write order to avoid a fixed timing pattern.
    const honeyWrites = honeyKeys.map((hk, i) => [hk, honeyCts[i]!] as [string, string]);
    for (let i = honeyWrites.length - 1; i > 0; i--) {
      const j = crypto.getRandomValues(new Uint8Array(1))[0]! % (i + 1);
      // eslint-disable-next-line security/detect-object-injection
      [honeyWrites[i]!, honeyWrites[j]!] = [honeyWrites[j]!, honeyWrites[i]!];
    }
    // Random insertion point for the real cookie among honey cookies.
    const pos =
      honeyWrites.length === 0
        ? 0
        : crypto.getRandomValues(new Uint8Array(1))[0]! % (honeyWrites.length + 1);
    for (let i = 0; i < pos; i++) this.writeCookieRaw(honeyWrites[i]![0], honeyWrites[i]![1]);
    this.writeCookie(name, packed, options);
    for (let i = pos; i < honeyWrites.length; i++)
      this.writeCookieRaw(honeyWrites[i]![0], honeyWrites[i]![1]);

    this.session.touch();
  }

  private prepareHoneyKeys(): string[] {
    const mgr = this.honeyManager as HoneyKeyManager | null;
    if (!mgr?.isEnabled) return [];
    const needed = this.config.honeyKeys.count;
    if (needed <= 0) return [];
    const existingAliases = [...this.cookieNames];
    const honeyStorageKeys = mgr.generateHoneyKeys('cookie', existingAliases, needed);
    for (const storageKey of honeyStorageKeys) {
      mgr.assignDecoyAlias('cookie', storageKey, existingAliases);
    }
    return honeyStorageKeys;
  }

  /** For claim mode: write honey cookies after the real write completes. */
  private async writeHoneyKeysInterleaved(cryptoKey: CryptoKey): Promise<void> {
    const honeyKeys = this.prepareHoneyKeys();
    if (honeyKeys.length === 0) return;
    const honeyCts = await Promise.all(honeyKeys.map(() => generateHoneyCiphertext(cryptoKey)));
    for (const [i, hk] of honeyKeys.entries()) {
      this.writeCookieRaw(hk, honeyCts[i]!);
    }
  }

  async remove(name: string): Promise<void> {
    const raw = this.readRaw(name);

    if (raw && this.idb) {
      const value = decodeURIComponent(raw);
      if (value.startsWith(CLAIM_TOKEN_PREFIX)) {
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
    this.writeCookie(name, `${CLAIM_TOKEN_PREFIX}${token}`, options);

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
    const token = value.slice(CLAIM_TOKEN_PREFIX.length);
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

    // Default SameSite to 'Strict' — tessera cookies are never needed on cross-site
    // requests. Developer can override by passing options.sameSite explicitly.
    const effectiveSameSite = options?.sameSite ?? 'Strict';
    parts.push(`SameSite=${effectiveSameSite}`);

    // Auto-apply Secure on HTTPS pages. The Secure flag only controls browser
    // HTTP transmission — it has zero effect on document.cookie reads, so tessera's
    // decrypt path is unaffected. Developer can override via options.secure.
    const effectiveSecure = options?.secure ?? globalThis.location?.protocol === 'https:';
    if (effectiveSecure) {
      parts.push('Secure');
    }

    document.cookie = parts.join('; ');
  }

  private writeCookieRaw(key: string, value: string): void {
    // Honey cookies receive the same security defaults as real cookies
    // so they are indistinguishable in size, flags, and transmission behaviour.
    const sameSite = 'Strict';
    const secureFlag = globalThis.location?.protocol === 'https:' ? '; Secure' : '';
    document.cookie = `${encodeURIComponent(key)}=${encodeURIComponent(value)}; path=/${secureFlag}; SameSite=${sameSite}`;
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
        if (value.startsWith(CLAIM_TOKEN_PREFIX)) continue;
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
