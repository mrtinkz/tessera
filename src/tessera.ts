import {
  type IEnhancedVault,
  type IScopedVault,
  type EnhancedTesseraConfig,
  type TesseraEventName,
  type TesseraEventHandler,
  type HoneyKeyManagerIsh,
  type StorageItemOptions,
  type CookieOptions,
  TesseraError,
  TesseraErrorCode,
} from './types';
import {
  deriveKey,
  deriveHmacKey,
  getSalt,
  unsecuredGetSalt,
  encrypt,
  decrypt,
  validatePasscode,
} from './core/crypto';
import { KeySession } from './core/session';
import {
  checkLockout,
  recordFailedAttempt,
  resetLockout,
  getRemainingAttempts,
  performWipe,
  signLockoutRecord,
  verifyLockoutRecord,
} from './core/lockout';
import { TesseraEmitter } from './core/events';
import { resolveConfig, type ResolvedConfig } from './core/config';
import { SuspicionEngine } from './core/suspicion';
import { HoneyKeyManager } from './storage/honey';
import { LocalStorageAdapter } from './adapters/local-storage';
import { SessionStorageAdapter } from './adapters/session-storage';
import { CookieAdapter } from './adapters/cookie';
import { IndexedDbAdapter } from './adapters/indexed-db';

export { TesseraError, TesseraErrorCode } from './types';
export type {
  TesseraConfig,
  EnhancedTesseraConfig,
  IVault,
  IEnhancedVault,
  IScopedVault,
  IStorageAdapter,
  ICookieAdapter,
  IIDBAdapter,
  CookieOptions,
  StorageItemOptions,
  PinPadConfig,
  SensitivityLevel,
  SuspicionAction,
  StorageMode,
  TesseraEventName,
  TesseraEventPayloads,
  TesseraEventHandler,
  ExportedItem,
} from './types';
export {
  deriveKey,
  decrypt,
  encrypt,
  encryptWithSalt,
  decryptFull,
  validatePasscode,
} from './core/crypto';
export { renderPinPad } from './ui/pin-pad';

// XSS mitigation: CSP detection helper.
// Tessera cannot SET a CSP — headers must come from the server and
// <meta http-equiv> must be in the initial HTML. What we can do is check
// for a CSP meta tag (or Trusted Types, which implies CSP3 is active) and
// warn/throw when neither is present so developers are informed early.
// A CSP delivered as an HTTP response header is NOT detectable from JS.
function hasCsp(): boolean {
  /* v8 ignore next 1 */
  if (typeof document === 'undefined') return true; // SSR — no DOM to check
  if (document.querySelector('meta[http-equiv="Content-Security-Policy"]')) return true;
  // Trusted Types API presence implies `require-trusted-types-for` CSP directive is active.
  const gt = globalThis as Record<string, unknown>;
  return gt['trustedTypes'] !== undefined;
}

// Storage key names are computed per vault. 'default' maps to the legacy
// names so existing single-vault apps require zero migration.
function vaultStorageKey(vaultId: string, suffix: string): string {
  return vaultId === 'default' ? `tessera_vault_${suffix}` : `tessera_${vaultId}_vault_${suffix}`;
}

const VAULT_SENTINEL = '\u0000tessera-vault-verifier\u0000';

// P6: HMAC-SHA256 over UTF-8 text → lowercase hex string.
// Used for HMAC-signing suspicion score snapshots (same pattern as lockout records).
async function hmacText(key: CryptoKey, text: string): Promise<string> {
  const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(text));
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

// P7: Draw a 5×5 symmetric identicon derived from a 32-byte HMAC seed.
// Bytes 0-1  → hue (0-359).
// Bytes 2-13 → 15 unique cells (3 columns × 5 rows, mirrored horizontally).
// No key material is exposed — only pixels are written to the canvas.
function drawIdenticon(
  canvas: HTMLCanvasElement,
  seed: Uint8Array,
  position: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'full',
): void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const GRID = 5;
  const hue = (seed[0]! * 256 + seed[1]!) % 360;
  const color = `hsl(${hue}, 60%, 45%)`;
  const bg = `hsl(${hue}, 15%, 90%)`;

  // Build 5×5 symmetric grid; bits packed from byte 2 onward.
  const grid: boolean[][] = Array.from({ length: GRID }, () =>
    Array.from({ length: GRID }, () => false),
  );
  let bitIdx = 0;
  for (let row = 0; row < GRID; row++) {
    for (let col = 0; col < 3; col++) {
      // eslint-disable-next-line security/detect-object-injection
      const filled = ((seed[2 + Math.floor(bitIdx / 8)]! >> bitIdx % 8) & 1) === 1;
      // eslint-disable-next-line security/detect-object-injection
      grid[row]![col] = filled;
      // eslint-disable-next-line security/detect-object-injection
      grid[row]![GRID - 1 - col] = filled;
      bitIdx++;
    }
  }

  let cellSize: number, offsetX: number, offsetY: number;
  if (position === 'full') {
    cellSize = Math.floor(Math.min(canvas.width, canvas.height) / GRID);
    offsetX = Math.floor((canvas.width - cellSize * GRID) / 2);
    offsetY = Math.floor((canvas.height - cellSize * GRID) / 2);
  } else {
    cellSize = Math.floor(Math.min(canvas.width, canvas.height) / 8);
    const span = cellSize * GRID;
    offsetX = position.includes('right') ? canvas.width - span : 0;
    offsetY = position.includes('bottom') ? canvas.height - span : 0;
  }

  ctx.fillStyle = bg;
  ctx.fillRect(offsetX, offsetY, cellSize * GRID, cellSize * GRID);
  ctx.fillStyle = color;
  for (let row = 0; row < GRID; row++) {
    for (let col = 0; col < GRID; col++) {
      // eslint-disable-next-line security/detect-object-injection
      if (grid[row]![col]) {
        ctx.fillRect(
          offsetX + col * cellSize + 1,
          offsetY + row * cellSize + 1,
          cellSize - 2,
          cellSize - 2,
        );
      }
    }
  }
}

// Module-level registry so multiple concurrent vaults share one prototype patch.
// Each entry is { storage, backend, honeyManager, suspicion }.
type ProxyEntry = {
  storage: Storage;
  backend: string;
  honeyManager: HoneyKeyManagerIsh;
  suspicion: SuspicionEngine;
};
const _protoRegistry: ProxyEntry[] = [];
let _originalProtoGetItem: ((key: string) => string | null) | null = null;
/** Cached result of whether Storage.prototype patches are intercepted by storage objects. */
let _protoInterceptsStorage: boolean | null = null;

function _ensureProtoPatch(): void {
  if (_originalProtoGetItem !== null) return; // already patched
  _originalProtoGetItem = Storage.prototype.getItem;
  Object.defineProperty(Storage.prototype, 'getItem', {
    configurable: true,
    writable: true,
    /* v8 ignore start */
    value(this: Storage, key: string): string | null {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const value = _originalProtoGetItem!.call(this, key);
      if (value !== null) {
        for (const entry of _protoRegistry) {
          if (entry.storage === this && entry.honeyManager.isHoney(entry.backend, key)) {
            entry.suspicion.recordHoneyHit(entry.backend);
          }
        }
      }
      return value;
    },
    /* v8 ignore stop */
  });
}

/**
 * Probes whether patching Storage.prototype.getItem actually intercepts calls
 * on `storage`. Real browsers: yes (prototype chain). Proxy-wrapped environments
 * (e.g. Vitest + happy-dom): no (Proxy GET trap bypasses prototype lookup).
 * Result is cached — the environment doesn't change at runtime.
 */
function _protoInterceptsStorage_check(storage: Storage): boolean {
  if (_protoInterceptsStorage !== null) return _protoInterceptsStorage;
  const saved = Storage.prototype.getItem as (this: Storage, key: string) => string | null;
  let hit = false;
  const PROBE = '__tessera_proto_probe__';
  Object.defineProperty(Storage.prototype, 'getItem', {
    configurable: true,
    writable: true,
    /* v8 ignore next 1 */
    value(this: Storage, k: string): string | null {
      if (k === PROBE) hit = true;
      return saved.call(this, k);
    },
  });
  try {
    storage.getItem(PROBE);
  } catch {
    /* ignore — unavailable in SSR */
  }
  Object.defineProperty(Storage.prototype, 'getItem', {
    configurable: true,
    writable: true,
    value: saved,
  });
  return (_protoInterceptsStorage = hit);
}

function _removePatchIfEmpty(): void {
  if (_protoRegistry.length > 0) return;
  if (_originalProtoGetItem === null) return;
  Object.defineProperty(Storage.prototype, 'getItem', {
    configurable: true,
    writable: true,
    value: _originalProtoGetItem,
  });
  _originalProtoGetItem = null;
}

function installStorageProxy(
  storage: Storage,
  backend: string,
  honeyManager: HoneyKeyManagerIsh,
  suspicion: SuspicionEngine,
): () => void {
  const entry: ProxyEntry = { storage, backend, honeyManager, suspicion };
  _protoRegistry.push(entry);

  // Probe whether patching Storage.prototype intercepts calls on this storage
  // object BEFORE we install the prototype patch (so the probe sees the raw env).
  const useProto = _protoInterceptsStorage_check(storage);
  _ensureProtoPatch();

  // In environments where the prototype patch is NOT intercepted (e.g. Vitest +
  // happy-dom, where localStorage is a Proxy whose GET trap bypasses prototype
  // chain lookup), we fall back to an instance-level own-property patch.
  //
  // This is safe in those environments because `Object.defineProperty` on the
  // Proxy only creates a new Proxy-own-property descriptor — it does NOT write
  // to the underlying storage backend.
  //
  // In real browsers the prototype patch works correctly and this branch is
  // skipped. Skipping is essential: `Object.defineProperty` on a native Storage
  // goes through the exotic [[DefineOwnProperty]] trap and writes a literal
  // "getItem" key into the storage backend — which is the bug this guard prevents.
  const originalInstance = useProto
    ? null
    : ((storage as unknown as Record<string, unknown>)['getItem'] as
        | ((key: string) => string | null)
        | null);

  if (originalInstance !== null) {
    Object.defineProperty(storage, 'getItem', {
      configurable: true,
      value(key: string): string | null {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const value = _originalProtoGetItem!.call(storage, key);
        if (value !== null && honeyManager.isHoney(backend, key)) {
          suspicion.recordHoneyHit(backend);
        }
        return value;
      },
    });
  }

  return (): void => {
    const idx = _protoRegistry.indexOf(entry);
    if (idx !== -1) _protoRegistry.splice(idx, 1);
    _removePatchIfEmpty();

    if (originalInstance !== null) {
      // Restore the pre-patch method as the own property so that normal
      // dispatch resumes (Proxy GET trap will find this before the prototype).
      Object.defineProperty(storage, 'getItem', { configurable: true, value: originalInstance });
    }
  };
}

/**
 * The main entry point for tessera.
 *
 * @example
 * ```ts
 * const vault = await Tessera.unlock('my-passcode', { idleTimeout: 600_000 });
 * await vault.local.setItem('key', 'value');
 * vault.lock();
 * ```
 */
export const Tessera = {
  /**
   * Derives an AES-256-GCM key from the passcode, verifies it against the
   * persisted vault verifier, and returns an {@link IEnhancedVault} with four
   * encrypted storage adapters.
   *
   * **First unlock**: generates a random 128-bit salt, derives the key, and
   * stores both the salt and an encrypted sentinel (`tessera_vault_verifier`)
   * in `localStorage`. The sentinel is used to reject wrong passcodes on all
   * subsequent unlocks.
   *
   * **Subsequent unlocks**: reads the persisted salt, re-derives the key, and
   * decrypts the sentinel. If the sentinel does not match, `INVALID_PASSCODE`
   * is thrown — the vault does not open.
   *
   * @param passcode - The user's passcode. Minimum 6 characters. No maximum.
   *   For human-entered PINs use {@link renderPinPad}; for programmatic use
   *   any string of sufficient entropy works (GUID, random hex, passphrase).
   * @param config   - Optional vault configuration. All fields have safe defaults.
   *
   * @returns A fully initialised {@link IEnhancedVault}.
   *
   * @throws {TesseraError} `UNSUPPORTED_ENV`  — `crypto.subtle` is unavailable
   *   (SSR, old browser). Use tessera only in client-side code.
   * @throws {TesseraError} `INVALID_PASSCODE` — passcode is shorter than 6
   *   characters, or does not match the persisted vault verifier.
   * @throws {TesseraError} `LOCKOUT`          — too many failed attempts;
   *   the lockout window has not expired yet.
   * @throws {TesseraError} `DECRYPT_FAILED`   — wrong passcode (bad verifier).
   *
   * @example Basic unlock
   * ```ts
   * const vault = await Tessera.unlock('246813');
   * await vault.local.setItem('username', 'alice');
   * ```
   *
   * @example With security config
   * ```ts
   * const vault = await Tessera.unlock('my-passphrase', {
   *   lockoutAttempts: 5,
   *   lockoutAction:   'wipe',
   *   idleTimeout:     600_000,
   *   defaultSensitivity: 'high',
   * });
   * ```
   *
   * @security
   * - Key derivation: PBKDF2-SHA-256 with a cryptographically random 128-bit
   *   salt and ≥ 310 000 iterations (OWASP 2024 minimum).
   * - The derived `CryptoKey` is `extractable: false` — raw bytes never leave
   *   the Web Crypto engine (T7).
   * - Wrong passcode detection: a sentinel encrypted with the vault key is
   *   persisted on first unlock; decryption failure rejects the passcode before
   *   any storage is touched.
   * - The in-memory key is held in a `KeySession` closure and is never assigned
   *   to a module-level variable.
   *
   * @security **IMPORTANT — Do NOT expose the vault reference globally.**
   * Assigning the returned `IEnhancedVault` to a module-level variable,
   * `window` property, or any other globally accessible reference makes it
   * reachable by XSS-injected scripts. Keep the vault in the narrowest possible
   * scope (e.g. a React context, a function local, or a service class field):
   *
   * ```ts
   * // ❌ BAD — any injected script can call window.vault.local.getItem()
   * window.vault = await Tessera.unlock(passcode);
   *
   * // ✅ GOOD — vault lives only inside this async function's closure
   * async function doWork(passcode: string): Promise<void> {
   *   const vault = await Tessera.unlock(passcode);
   *   await vault.local.setItem('key', 'value');
   *   vault.lock();
   * }
   * ```
   */
  async unlock(passcode: string, config?: EnhancedTesseraConfig): Promise<IEnhancedVault> {
    // Validate passcode BEFORE any side-effects (salt write, lockout count).
    // A passcode that is too short is a caller error, not a failed attempt.
    validatePasscode(passcode);

    const resolved: ResolvedConfig = resolveConfig(config);
    const { vaultId } = resolved;
    const SALT_STORAGE_KEY = vaultStorageKey(vaultId, 'salt');
    const VERIFIER_STORAGE_KEY = vaultStorageKey(vaultId, 'verifier');

    // Throw early for 'require' mode so no resources are acquired.
    if (resolved.cspCheck === 'require' && !hasCsp()) {
      throw new TesseraError(
        TesseraErrorCode.UNSUPPORTED_ENV,
        'No Content-Security-Policy detected. XSS can bypass tessera encryption. ' +
          'Set a CSP via HTTP header or <meta http-equiv="Content-Security-Policy">. ' +
          'If CSP is already set via HTTP header, pass `cspCheck: false` to silence this.',
      );
    }

    checkLockout(resolved.lockoutAttempts, vaultId);

    // Read the honey-cleanup gate synchronously — before the first `await` in this
    // function. Any earlier background cleanup's .then() callback (which writes a
    // fresh timestamp) runs as a microtask on the first await yield, which would
    // overwrite a test reset if we read the gate later.
    const HONEY_CLEANUP_KEY =
      vaultId === 'default' ? 'tessera_honey_cleaned' : `tessera_${vaultId}_honey_cleaned`;
    const HONEY_CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 h
    let shouldCleanHoney = true;
    try {
      const lastCleaned = localStorage.getItem(HONEY_CLEANUP_KEY);
      if (lastCleaned !== null) {
        shouldCleanHoney = Date.now() - Number(lastCleaned) >= HONEY_CLEANUP_INTERVAL_MS;
      }
    } catch {
      // localStorage unavailable — run cleanup anyway (best-effort).
    }

    const session = new KeySession();
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(resolved, events);

    // 'warn' mode: emit after the emitter is ready so caller-registered handlers fire.
    if (resolved.cspCheck === 'warn' && !hasCsp()) {
      const msg =
        'No Content-Security-Policy detected. XSS can bypass tessera encryption. ' +
        'Set a CSP via HTTP header or <meta http-equiv="Content-Security-Policy">. ' +
        'If CSP is already set via HTTP header, pass `cspCheck: false` to silence this warning.';
      void Promise.resolve().then(() => {
        events.emit('csp-warning', { httpHeaderCspUndetectable: true, message: msg });
      });
    }

    try {
      let salt: Uint8Array;
      let isNewVault = false;
      try {
        const stored = localStorage.getItem(SALT_STORAGE_KEY);
        if (stored === null) {
          salt = await getSalt();
          const binary = [...salt].map((b) => String.fromCodePoint(b)).join('');
          localStorage.setItem(SALT_STORAGE_KEY, btoa(binary));
          isNewVault = true;
        } else {
          const raw = atob(stored);
          salt = new Uint8Array(raw.length);
          // eslint-disable-next-line security/detect-object-injection
          for (let i = 0; i < raw.length; i++) salt[i] = raw.codePointAt(i)!;
        }
      } catch {
        salt = unsecuredGetSalt();
        isNewVault = true;
      }

      const key = await deriveKey(passcode, salt, resolved.iterations);
      const hmacKey = await deriveHmacKey(passcode, salt, resolved.iterations);

      // Verify passcode against the persisted verifier, or create one for new/upgraded vaults.
      let storedVerifier: string | null = null;
      if (!isNewVault) {
        try {
          storedVerifier = localStorage.getItem(VERIFIER_STORAGE_KEY);
        } catch {
          /* unavailable */
        }
      }
      if (storedVerifier === null) {
        // New vault or pre-verifier vault being upgraded — store verifier now.
        const verifier = await encrypt(key, VAULT_SENTINEL);
        try {
          localStorage.setItem(VERIFIER_STORAGE_KEY, verifier);
        } catch {
          /* best-effort */
        }
      } else {
        const verifyResult = await decrypt(key, storedVerifier);
        if (!verifyResult.ok || verifyResult.value !== VAULT_SENTINEL) {
          throw new TesseraError(TesseraErrorCode.INVALID_PASSCODE, 'Incorrect passcode.');
        }
        // FIX 2: Verify the lockout record has not been tampered with.
        const lockoutIntact = await verifyLockoutRecord(hmacKey, vaultId);
        if (!lockoutIntact) {
          throw new TesseraError(
            TesseraErrorCode.LOCKOUT,
            'Lockout record tampered. Access denied.',
          );
        }
      }

      // Encrypt a sentinel with the vault key. Used to verify reconfirm passcodes.
      const reconfirmSentinel = await encrypt(key, '\u0000tessera-verify\u0000');

      // P6: Seed the suspicion engine with a decayed score from a persisted snapshot,
      // if the developer opted in. The snapshot is HMAC-signed with hmacKey so any
      // tampering (e.g. score reset) is detected and ignored.
      if (resolved.suspicion.persistScore) {
        const snapKey = `tessera_${vaultId}_suspicion_snapshot`;
        const sigKey = `tessera_${vaultId}_suspicion_sig`;
        try {
          const raw = localStorage.getItem(snapKey);
          const sig = localStorage.getItem(sigKey);
          if (raw !== null && sig !== null) {
            const expectedSig = await hmacText(hmacKey, raw);
            if (expectedSig === sig) {
              const parsed = JSON.parse(raw) as { score: number; timestamp: number };
              const elapsed = Date.now() - parsed.timestamp;
              const halfLife = resolved.suspicion.scoreDecayHalfLifeMs;
              const decayed =
                halfLife > 0
                  ? parsed.score * Math.exp((-Math.LN2 * elapsed) / halfLife)
                  : parsed.score;
              suspicion.seedInitialScore(Math.max(0, decayed));
            }
            // If sig mismatch: snapshot was tampered — silently start fresh.
          }
        } catch {
          // localStorage unavailable or JSON parse error — start fresh.
        }
      }

      // P8: WebAuthn context binding gate. Performs a biometric presence check
      // (device auth) after the passcode has been verified. This is a second
      // factor: an attacker with the correct passcode but without the device
      // biometric / device PIN cannot activate the derived key.
      if (resolved.contextBinding?.webauthn === true) {
        /* v8 ignore next 4 */
        if (typeof navigator === 'undefined' || !navigator.credentials) {
          throw new TesseraError(
            TesseraErrorCode.UNSUPPORTED_ENV,
            'WebAuthn (navigator.credentials) is not available in this environment.',
          );
        }
        /* v8 ignore start */
        const credKey = `tessera_${vaultId}_webauthn_cid`;
        const rpId =
          typeof location !== 'undefined' && location.hostname ? location.hostname : undefined;
        const mismatch = resolved.contextBinding.onMismatch;

        const applyMismatch = (err: unknown): never => {
          if (mismatch === 'wipe') {
            performWipe(vaultId);
            throw new TesseraError(
              TesseraErrorCode.LOCKOUT,
              'WebAuthn assertion failed — vault wiped.',
              err,
            );
          }
          if (mismatch === 'lock') {
            throw new TesseraError(
              TesseraErrorCode.LOCKED,
              'WebAuthn assertion failed — vault locked.',
              err,
            );
          }
          throw new TesseraError(
            TesseraErrorCode.UNSUPPORTED_ENV,
            'WebAuthn assertion failed.',
            err,
          );
        };

        let storedCid: string | null = null;
        try {
          storedCid = localStorage.getItem(credKey);
        } catch {
          /* unavailable */
        }

        if (storedCid === null) {
          // First unlock: enroll a resident credential tied to this origin.
          try {
            const cred = (await navigator.credentials.create({
              publicKey: {
                rp: { name: 'tessera vault', ...(rpId === undefined ? {} : { id: rpId }) },
                user: {
                  id: crypto.getRandomValues(new Uint8Array(16)),
                  name: 'vault',
                  displayName: 'Vault',
                },
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                pubKeyCredParams: [
                  { type: 'public-key', alg: -7 }, // ES256
                  { type: 'public-key', alg: -257 }, // RS256
                ],
                authenticatorSelection: { userVerification: 'required' },
                timeout: 60_000,
              },
            })) as PublicKeyCredential | null;
            if (cred?.rawId) {
              const cidB64 = btoa(
                [...new Uint8Array(cred.rawId)].map((b) => String.fromCodePoint(b)).join(''),
              );
              try {
                localStorage.setItem(credKey, cidB64);
              } catch {
                /* best-effort */
              }
            }
          } catch (error) {
            applyMismatch(error);
          }
        } else {
          // Subsequent unlock: assert the stored credential.
          try {
            const cidBytes = Uint8Array.from(atob(storedCid), (c) => c.codePointAt(0)!);
            await navigator.credentials.get({
              publicKey: {
                ...(rpId === undefined ? {} : { rpId }),
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                allowCredentials: [{ type: 'public-key', id: cidBytes }],
                userVerification: 'required',
                timeout: 60_000,
              },
            });
          } catch (error) {
            applyMismatch(error);
          }
        }
        /* v8 ignore stop */
      }

      // Filled in after cleanupProxies / suspicion / honeyManager are initialised.
      // The callback fires from a timer (never synchronously), so the const bindings
      // it references are always initialised by the time it runs.
      let onAutoLockCleanup: (() => void) | null = null;
      session.setKey(
        key,
        resolved.idleTimeout,
        () => {
          onAutoLockCleanup?.();
          events.emit('auto-locked', { reason: 'idle-timeout' });
          events.emit('vault-locked', { reason: 'idle-timeout' });
        },
        resolved.maxUnlockDurationMs,
      );
      session.setHmacKey(hmacKey);
      session.touch();

      resetLockout(vaultId);
      // FIX 2: Sign the lockout record after a successful unlock.
      await signLockoutRecord(hmacKey, vaultId);

      // P6: Register score-persistence callback so future score increments
      // are HMAC-signed and written to localStorage for cross-session survival.
      if (resolved.suspicion.persistScore) {
        const snapKey = `tessera_${vaultId}_suspicion_snapshot`;
        const sigKey = `tessera_${vaultId}_suspicion_sig`;
        suspicion.setScoreUpdateCallback((score, timestamp): void => {
          void (async (): Promise<void> => {
            try {
              const raw = JSON.stringify({ score, timestamp });
              const sig = await hmacText(hmacKey, raw);
              localStorage.setItem(snapKey, raw);
              localStorage.setItem(sigKey, sig);
            } catch {
              /* best-effort */
            }
          })();
        });
      }

      // FIX 5: Create a lock proof for authenticated BroadcastChannel lock messages.
      const lockProof = await encrypt(key, '\u0000tessera-lock\u0000');
      session.setLockProof(lockProof);

      events.emit('vault-unlocked', { mode: 'normal' });

      const honeyManager = new HoneyKeyManager(resolved);

      const localAdapter = new LocalStorageAdapter(resolved, session, events, suspicion);
      const sessionAdapter = new SessionStorageAdapter(resolved, session, events, suspicion);
      const cookieAdapter = new CookieAdapter(resolved, session, events, suspicion);
      const idbAdapter = new IndexedDbAdapter(resolved, session, events, suspicion);

      localAdapter.setHoneyManager(honeyManager);
      sessionAdapter.setHoneyManager(honeyManager);
      cookieAdapter.setHoneyManager(honeyManager);
      idbAdapter.setHoneyManager(honeyManager);
      sessionAdapter.setIdbAdapter(idbAdapter);
      cookieAdapter.setIdbAdapter(idbAdapter);

      const proxyCleanups: Array<() => void> = [];
      /* v8 ignore next 6 */
      try {
        proxyCleanups.push(
          installStorageProxy(localStorage, 'local', honeyManager, suspicion),
          installStorageProxy(sessionStorage, 'session', honeyManager, suspicion),
        );
      } catch {
        // Non-browser or restricted environment — proxy installation is best-effort
      }

      const cleanupProxies = (): void => {
        for (const fn of proxyCleanups) fn();
        proxyCleanups.length = 0;
      };

      // Now that all resources are initialised, wire up the idle-timeout cleanup.
      // Without this, every re-unlock leaks a proxy entry in _protoRegistry and
      // leaves the SuspicionEngine's visibilitychange listener attached.
      onAutoLockCleanup = (): void => {
        cleanupProxies();
        suspicion.destroy();
        honeyManager.clearAll();
        idbAdapter.close();
      };

      suspicion.setOnLockdown(async () => {
        // Destroy the crypto key and remove the storage proxy immediately —
        // synchronously, before any await. Async functions run synchronously up to
        // their first await, so these execute as part of the increment() call that
        // crossed the threshold. Storage wipes are best-effort forensic overwrite
        // and proceed async afterwards (hardWipe uses random noise, not the key).
        session.lock();
        cleanupProxies();
        const wiped: string[] = [];
        await localAdapter.wipeAll(wiped);
        await sessionAdapter.wipeAll(wiped);
        await cookieAdapter.wipeAll(wiped);
        await idbAdapter.wipeAll(wiped);
        idbAdapter.close();
        events.emit('vault-locked', { reason: 'suspicion-lockdown' });
        return wiped;
      });

      const vaultSalt = salt;

      const enhancedVault: IEnhancedVault = {
        local: localAdapter,
        session: sessionAdapter,
        cookie: cookieAdapter,
        idb: idbAdapter,

        on<E extends TesseraEventName>(event: E, handler: TesseraEventHandler<E>): void {
          events.on(event, handler);
        },

        off<E extends TesseraEventName>(event: E, handler?: TesseraEventHandler<E>): void {
          events.off(event, handler);
        },

        lock(): void {
          session.lock();
          suspicion.destroy();
          honeyManager.clearAll();
          cleanupProxies();
          idbAdapter.close();
          events.emit('vault-locked', { reason: 'user' });
        },

        isLocked(): boolean {
          return session.isLocked();
        },

        async signChallenge(challenge: Uint8Array, expiresAt: number): Promise<Uint8Array> {
          // Guard: vault must be unlocked to sign.
          const hmacKey = session.getHmacKeySafe();
          if (hmacKey === null) {
            throw new TesseraError(
              TesseraErrorCode.LOCKED,
              'Vault is locked. Call Tessera.unlock() before signChallenge().',
            );
          }
          // Enforce the time window — proof cannot be produced after the challenge expires.
          if (Date.now() >= expiresAt) {
            throw new TesseraError(
              TesseraErrorCode.LOCKOUT,
              'Challenge has expired. Request a new challenge from the server.',
            );
          }
          // Validate challenge size: 8–64 bytes (prevents trivially short nonces).
          if (challenge.length < 8 || challenge.length > 64) {
            throw new TesseraError(
              TesseraErrorCode.INVALID_PASSCODE,
              'Challenge must be between 8 and 64 bytes.',
            );
          }
          // Build the signed payload: challenge bytes ‖ expiresAt as little-endian u64.
          const payload = new Uint8Array(challenge.length + 8);
          payload.set(challenge, 0);
          // Encode expiresAt (ms) as 8-byte little-endian.
          const view = new DataView(payload.buffer, challenge.length, 8);
          // Use two u32 writes — DataView.setBigUint64 requires BigInt64Array support
          // which is not guaranteed in all ES2020 environments.
          view.setUint32(0, expiresAt >>> 0, true); // low 32 bits
          view.setUint32(4, Math.floor(expiresAt / 0x1_00_00_00_00), true); // high 32 bits
          const signature = await crypto.subtle.sign('HMAC', hmacKey, payload);
          return new Uint8Array(signature);
        },

        async renderFingerprint(
          canvas: HTMLCanvasElement,
          position:
            | 'top-left'
            | 'top-right'
            | 'bottom-left'
            | 'bottom-right'
            | 'full' = 'bottom-right',
        ): Promise<void> {
          const hk = session.getHmacKeySafe();
          if (hk === null) {
            throw new TesseraError(
              TesseraErrorCode.LOCKED,
              'Vault is locked. Call Tessera.unlock() before renderFingerprint().',
            );
          }
          // Derive a 32-byte seed: HMAC-SHA256(hmacKey, 'visual-fingerprint').
          // The hmacKey never leaves the vault closure — only pixels are written.
          const seed = new Uint8Array(
            await crypto.subtle.sign('HMAC', hk, new TextEncoder().encode('visual-fingerprint')),
          );
          drawIdenticon(canvas, seed, position);
        },

        async reconfirm(passcode: string): Promise<void> {
          // Same guard: reconfirm with a too-short passcode is a caller error.
          validatePasscode(passcode);
          const confirmKey = await deriveKey(passcode, vaultSalt, resolved.iterations);
          const verifyResult = await decrypt(confirmKey, reconfirmSentinel);
          if (!verifyResult.ok || verifyResult.value !== '\u0000tessera-verify\u0000') {
            suspicion.recordPasscodeFailure();
            throw new TesseraError(
              TesseraErrorCode.INVALID_PASSCODE,
              'Incorrect passcode for reconfirmation.',
            );
          }
          // Guard: if the vault locked while deriveKey was running, do not store
          // the reconfirm key on a locked session.
          if (session.isLocked()) {
            throw new TesseraError(TesseraErrorCode.LOCKED, 'Vault locked during reconfirmation.');
          }
          session.setReconfirmKey(confirmKey);
          events.emit('vault-unlocked', { mode: 'reconfirm' });
        },

        terminate(): void {
          session.lock();
          events.clear();
          suspicion.destroy();
          honeyManager.clearAll();
          cleanupProxies();
          idbAdapter.close(); // release the persistent IDB connection
        },

        async destroy(): Promise<void> {
          // Wipe all backends while the crypto key is still accessible.
          const wiped: string[] = [];
          try {
            await localAdapter.wipeAll(wiped);
          } catch {
            /* best-effort */
          }
          try {
            await sessionAdapter.wipeAll(wiped);
          } catch {
            /* best-effort */
          }
          try {
            await cookieAdapter.wipeAll(wiped);
          } catch {
            /* best-effort */
          }
          try {
            await idbAdapter.wipeAll(wiped);
          } catch {
            /* best-effort */
          }

          // Remove vault metadata keys (salt, verifier, cleanup timestamp).
          try {
            localStorage.removeItem(SALT_STORAGE_KEY);
            localStorage.removeItem(VERIFIER_STORAGE_KEY);
            localStorage.removeItem(HONEY_CLEANUP_KEY);
          } catch {
            /* best-effort */
          }

          // Delete the IDB database entirely.
          idbAdapter.close();
          const dbName = vaultId === 'default' ? 'tessera_vault' : `tessera_vault_${vaultId}`;
          try {
            indexedDB.deleteDatabase(dbName);
          } catch {
            /* best-effort */
          }

          // Lock and clean up.
          session.lock();
          events.clear();
          suspicion.destroy();
          honeyManager.clearAll();
          cleanupProxies();
        },

        // Capability-limited frozen proxy
        scope(
          allowedKeys: string[],
          allowedOps: ('read' | 'write')[] = ['read', 'write'],
        ): IScopedVault {
          const keySet = new Set(allowedKeys);
          const canRead = allowedOps.includes('read');
          const canWrite = allowedOps.includes('write');

          function guardKey(key: string): void {
            if (!keySet.has(key)) {
              throw new TesseraError(
                TesseraErrorCode.PERMISSION_DENIED,
                `Key "${key}" is not in scope`,
              );
            }
          }
          function guardRead(key: string): void {
            guardKey(key);
            if (!canRead)
              throw new TesseraError(
                TesseraErrorCode.PERMISSION_DENIED,
                'read not permitted in this scope',
              );
          }
          function guardWrite(key: string): void {
            guardKey(key);
            if (!canWrite)
              throw new TesseraError(
                TesseraErrorCode.PERMISSION_DENIED,
                'write not permitted in this scope',
              );
          }

          return Object.freeze({
            keys: Object.freeze([...allowedKeys]),
            operations: Object.freeze([...allowedOps]),
            local: Object.freeze({
              getItem: (key: string) => {
                guardRead(key);
                return localAdapter.getItem(key);
              },
              setItem: (key: string, value: string, opts?: StorageItemOptions) => {
                guardWrite(key);
                return localAdapter.setItem(key, value, opts);
              },
              removeItem: (key: string) => {
                guardWrite(key);
                return localAdapter.removeItem(key);
              },
              exportItem: (key: string) => {
                guardRead(key);
                return localAdapter.exportItem(key);
              },
            }),
            session: Object.freeze({
              getItem: (key: string) => {
                guardRead(key);
                return sessionAdapter.getItem(key);
              },
              setItem: (key: string, value: string, opts?: StorageItemOptions) => {
                guardWrite(key);
                return sessionAdapter.setItem(key, value, opts);
              },
              removeItem: (key: string) => {
                guardWrite(key);
                return sessionAdapter.removeItem(key);
              },
              exportItem: (key: string) => {
                guardRead(key);
                return sessionAdapter.exportItem(key);
              },
            }),
            cookie: Object.freeze({
              get: (key: string) => {
                guardRead(key);
                return cookieAdapter.get(key);
              },
              set: (key: string, value: string, opts?: CookieOptions) => {
                guardWrite(key);
                return cookieAdapter.set(key, value, opts);
              },
              remove: (key: string) => {
                guardWrite(key);
                return cookieAdapter.remove(key);
              },
            }),
            idb: Object.freeze({
              get: (storeName: string, key: string) => {
                guardRead(key);
                return idbAdapter.get(storeName, key);
              },
              put: (storeName: string, key: string, value: unknown, opts?: StorageItemOptions) => {
                guardWrite(key);
                return idbAdapter.put(storeName, key, value, opts);
              },
              remove: (storeName: string, key: string) => {
                guardWrite(key);
                return idbAdapter.remove(storeName, key);
              },
            }),
          });
        },

        _simulateHoneyHit(backend: 'local' | 'session' | 'cookie'): void {
          if (!resolved.debug) return;
          if (session.isLocked()) return;
          suspicion.recordHoneyHit(backend);
        },

        _honeyStorageKeys(backend: 'local' | 'session' | 'cookie'): string[] {
          if (!resolved.debug) return [];
          return honeyManager.allKeys(backend);
        },
      };

      // Timestamp-gate orphan honey-key cleanup. Running O(n × crypto) on
      // every unlock is expensive. One run per 24 hours is sufficient to prevent
      // unbounded accumulation while eliminating the per-unlock crypto overhead
      // for the common case (clean session, no stale honey keys).
      // NOTE: shouldCleanHoney and HONEY_CLEANUP_KEY were evaluated synchronously
      // at the top of unlock() to capture the gate value before any microtask
      // yields could let a background cleanup's .then() overwrite the timestamp.
      if (shouldCleanHoney) {
        void Promise.all([
          localAdapter.cleanOrphanedHoneyKeys(),
          sessionAdapter.cleanOrphanedHoneyKeys(),
          cookieAdapter.cleanOrphanedHoneyKeys(),
          idbAdapter.cleanOrphanedHoneyKeys(),
          // Also clean orphaned split/claim IDB entries in the same gated pass.
          idbAdapter.cleanOrphanedSplits(),
          idbAdapter.cleanOrphanedClaims(),
        ]).then(() => {
          try {
            localStorage.setItem(HONEY_CLEANUP_KEY, String(Date.now()));
          } catch {
            /* best-effort */
          }
        });
      }

      return enhancedVault;
    } catch (error) {
      session.reset();
      events.clear();

      if (error instanceof TesseraError && error.code === TesseraErrorCode.LOCKOUT) {
        throw error;
      }

      recordFailedAttempt(resolved.lockoutAttempts, resolved.lockoutDelay, resolved.vaultId);
      const remaining = getRemainingAttempts(resolved.lockoutAttempts, resolved.vaultId);

      if (remaining === 0) {
        if (resolved.lockoutAction === 'wipe') {
          performWipe(resolved.vaultId);
          throw new TesseraError(
            TesseraErrorCode.LOCKOUT,
            'Too many failed attempts. All vault data has been wiped.',
          );
        }

        if (resolved.lockoutAction === 'throw') {
          throw new TesseraError(
            TesseraErrorCode.LOCKOUT,
            'Too many failed attempts. Access is permanently locked.',
          );
        }
      }

      const attemptMsg =
        remaining > 0
          ? ` ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
          : ' No attempts remaining — a delay has been applied.';

      throw new TesseraError(
        TesseraErrorCode.DECRYPT_FAILED,
        `Incorrect passcode.${attemptMsg}`,
        error,
      );
    }
  },
};
