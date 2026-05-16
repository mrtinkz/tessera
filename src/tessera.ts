import {
  type IEnhancedVault,
  type EnhancedTesseraConfig,
  type TesseraEventName,
  type TesseraEventHandler,
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
} from './types';
export { deriveKey, decrypt, encrypt, encryptWithSalt, decryptFull } from './core/crypto';
export { renderPinPad } from './ui/pin-pad';

const SALT_STORAGE_KEY = 'tessera_vault_salt';
const VERIFIER_STORAGE_KEY = 'tessera_vault_verifier';
const VAULT_SENTINEL = '\u0000tessera-vault-verifier\u0000';

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
   */
  async unlock(passcode: string, config?: EnhancedTesseraConfig): Promise<IEnhancedVault> {
    const resolved: ResolvedConfig = resolveConfig(config);

    checkLockout(resolved.lockoutAttempts);

    const session = new KeySession();
    const events = new TesseraEmitter();
    const suspicion = new SuspicionEngine(resolved, events);

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
        const lockoutIntact = await verifyLockoutRecord(hmacKey);
        if (!lockoutIntact) {
          throw new TesseraError(
            TesseraErrorCode.LOCKOUT,
            'Lockout record tampered. Access denied.',
          );
        }
      }

      // Encrypt a sentinel with the vault key. Used to verify reconfirm passcodes.
      const reconfirmSentinel = await encrypt(key, '\u0000tessera-verify\u0000');

      session.setKey(key, resolved.idleTimeout, () => {
        events.emit('auto-locked', { reason: 'idle-timeout' });
        events.emit('vault-locked', { reason: 'idle-timeout' });
      });
      session.setHmacKey(hmacKey);
      session.touch();

      resetLockout();
      // FIX 2: Sign the lockout record after a successful unlock.
      await signLockoutRecord(hmacKey);

      // FIX 5: Create a lock proof for authenticated BroadcastChannel lock messages.
      const lockProof = await encrypt(key, '\u0000tessera-lock\u0000');
      session.setLockProof(lockProof);

      events.emit('vault-unlocked', { mode: 'normal' });

      const honeyManager = new HoneyKeyManager(resolved);

      const localAdapter = new LocalStorageAdapter(resolved, session, events, suspicion);
      const sessionAdapter = new SessionStorageAdapter(resolved, session, events, suspicion);
      const cookieAdapter = new CookieAdapter(resolved, session, events, suspicion);
      const idbAdapter = new IndexedDbAdapter(resolved, session, events, suspicion);

      suspicion.setOnLockdown(async () => {
        // Nuke all t_ entries across every backend while the crypto key is still
        // accessible, then lock. This prevents an attacker from identifying honey
        // keys by elimination (survivors would otherwise reveal which keys were decoys).
        const wiped: string[] = [];
        await localAdapter.wipeAll(wiped);
        await sessionAdapter.wipeAll(wiped);
        await cookieAdapter.wipeAll(wiped);
        await idbAdapter.wipeAll(wiped);
        session.lock();
        events.emit('vault-locked', { reason: 'suspicion-lockdown' });
        return wiped;
      });

      localAdapter.setHoneyManager(honeyManager);
      sessionAdapter.setHoneyManager(honeyManager);
      cookieAdapter.setHoneyManager(honeyManager);
      sessionAdapter.setIdbAdapter(idbAdapter);
      cookieAdapter.setIdbAdapter(idbAdapter);

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
          events.emit('vault-locked', { reason: 'user' });
        },

        isLocked(): boolean {
          return session.isLocked();
        },

        async reconfirm(passcode: string): Promise<void> {
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
        },

        _simulateHoneyHit(backend: 'local' | 'session' | 'cookie'): void {
          if (session.isLocked()) return;
          suspicion.recordHoneyHit(backend);
        },

        _honeyStorageKeys(backend: 'local' | 'session' | 'cookie'): string[] {
          return honeyManager.allKeys(backend);
        },
      };

      // Fire orphan honey key cleanup in the background. Orphans are honey entries
      // from previous sessions whose in-memory tracking was lost on page reload.
      // Wiping them prevents unbounded storage accumulation and ensures the honey
      // count stays accurate. Errors are swallowed inside each adapter.
      void Promise.all([
        localAdapter.cleanOrphanedHoneyKeys(),
        sessionAdapter.cleanOrphanedHoneyKeys(),
        cookieAdapter.cleanOrphanedHoneyKeys(),
      ]);

      return enhancedVault;
    } catch (error) {
      session.reset();
      events.clear();

      if (error instanceof TesseraError && error.code === TesseraErrorCode.LOCKOUT) {
        throw error;
      }

      recordFailedAttempt(resolved.lockoutAttempts);
      const remaining = getRemainingAttempts(resolved.lockoutAttempts);

      if (remaining === 0) {
        if (resolved.lockoutAction === 'wipe') {
          performWipe();
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
