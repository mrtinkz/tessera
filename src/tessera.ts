import {
  type IVault,
  type TesseraConfig,
  TesseraError,
  TesseraErrorCode,
  DEFAULT_CONFIG,
} from './types';
import { deriveKey, getSalt, unsecuredGetSalt } from './core/crypto';
import { KeySession } from './core/session';
import { checkLockout, recordFailedAttempt, resetLockout, getRemainingAttempts, performWipe } from './core/lockout';
import { LocalStorageAdapter } from './adapters/local-storage';
import { SessionStorageAdapter } from './adapters/session-storage';
import { CookieAdapter } from './adapters/cookie';
import { IndexedDbAdapter } from './adapters/indexed-db';

export { TesseraError, TesseraErrorCode } from './types';
export type { TesseraConfig, IVault, IStorageAdapter, ICookieAdapter, IIDBAdapter, CookieOptions, PinPadConfig } from './types';
export { deriveKey, decrypt, encrypt, encryptWithSalt, decryptFull } from './core/crypto';
export { renderPinPad } from './ui/pin-pad';

/**
 * The primary tessera API.
 *
 * @example Vanilla JS / TypeScript
 * ```ts
 * import { Tessera } from 'tessera';
 *
 * const vault = await Tessera.unlock('abc123', { iterations: 310_000 });
 * await vault.local.setItem('cart', JSON.stringify(cart));
 * const cart = await vault.local.getItem('cart');
 * vault.lock();
 * ```
 */
export const Tessera = {
  /**
   * Derives an AES-256-GCM key from `passcode` via PBKDF2-SHA-256 and returns
   * an `IVault` whose adapters transparently encrypt and decrypt all storage
   * operations.
   *
   * Each call creates a **new**, isolated `KeySession`. Multiple concurrent
   * vaults with different passcodes are supported.
   *
   * @param passcode - The user's passcode (6–8 characters).
   * @param config   - Optional configuration overrides; see {@link TesseraConfig}.
   * @returns An `IVault` with encrypted `local`, `session`, `cookie`, and `idb`
   *   adapters, plus `lock()` and `isLocked()` helpers.
   *
   * @throws {TesseraError} `INVALID_PASSCODE` if passcode is outside 6–8 chars.
   * @throws {TesseraError} `LOCKOUT` if the lockout threshold has been exceeded.
   * @throws {TesseraError} `UNSUPPORTED_ENV` if `crypto.subtle` is unavailable.
   *
   * @example
   * ```ts
   * const vault = await Tessera.unlock('abc123');
   * await vault.local.setItem('theme', 'dark');
   * const theme = await vault.local.getItem('theme'); // 'dark'
   * vault.lock();
   * vault.isLocked(); // true
   * ```
   *
   * @security
   *   - Key derivation uses PBKDF2 at ≥ 310 000 iterations (OWASP 2024, T5).
   *   - The derived `CryptoKey` is non-extractable and lives only in memory (T7).
   *   - All storage values are encrypted with `salt ‖ iv ‖ ciphertext ‖ tag` (T1).
   */
  async unlock(
    passcode: string,
    config?: TesseraConfig,
  ): Promise<IVault> {
    const resolvedConfig = { ...DEFAULT_CONFIG, ...config };

    checkLockout(resolvedConfig.lockoutAttempts);

    // Each unlock() creates an isolated KeySession — the derived key lives
    // only in this closure and never in a module-level variable (PLAN §5).
    const session = new KeySession();

    try {
      // Persist the vault salt in localStorage so the same key is re-derived
      // across sessions. The salt is not secret — PBKDF2 salts are designed
      // to be public; security comes from the passcode and iteration count.
      // If the salt record is absent (first unlock or after wipe), generate
      // a new one and save it. If localStorage is unavailable, fall back to
      // a fresh random salt (ephemeral session only).
      const SALT_STORAGE_KEY = 'tessera_vault_salt';
      let salt: Uint8Array;
      try {
        const stored = localStorage.getItem(SALT_STORAGE_KEY);
        if (stored === null) {
          // First unlock — generate, persist, and use a fresh salt.
          salt = await getSalt();
          const binary = [...salt].map((b) => String.fromCodePoint(b)).join('');
          localStorage.setItem(SALT_STORAGE_KEY, btoa(binary));
        } else {
          // Reuse the stored salt so the same passcode re-derives the same key.
          const raw = atob(stored);
          salt = new Uint8Array(raw.length);
          for (let i = 0; i < raw.length; i++) salt[i] = raw.codePointAt(i)!;
        }
      } catch {
        // localStorage unavailable (private browsing restriction, etc.) —
        // derive a fresh ephemeral salt. Cross-session persistence won't work
        // but all in-session operations are fully functional.
        salt = unsecuredGetSalt();
      }

      const key = await deriveKey(passcode, salt, resolvedConfig.iterations);

      session.setKey(key, resolvedConfig.idleTimeout);
      session.touch();

      resetLockout();

      return {
        local: new LocalStorageAdapter(resolvedConfig, session),
        session: new SessionStorageAdapter(resolvedConfig, session),
        cookie: new CookieAdapter(resolvedConfig, session),
        idb: new IndexedDbAdapter(session),
        lock: () => session.lock(),
        isLocked: () => session.isLocked(),
      };
    } catch (error) {
      session.reset();

      // Re-throw LOCKOUT errors from checkLockout() immediately — do not
      // record an additional failed attempt for an already-locked session.
      if (error instanceof TesseraError && error.code === TesseraErrorCode.LOCKOUT) {
        throw error;
      }

      recordFailedAttempt(resolvedConfig.lockoutAttempts);
      const remaining = getRemainingAttempts(resolvedConfig.lockoutAttempts);

      if (remaining === 0) {
        if (resolvedConfig.lockoutAction === 'wipe') {
          performWipe();
          throw new TesseraError(
            TesseraErrorCode.LOCKOUT,
            'Too many failed attempts. All vault data has been wiped.',
          );
        }

        if (resolvedConfig.lockoutAction === 'throw') {
          throw new TesseraError(
            TesseraErrorCode.LOCKOUT,
            'Too many failed attempts. Access is permanently locked.',
          );
        }

        // 'delay': next call to checkLockout() will enforce the backoff window.
        // Fall through and throw the original error with attempt context.
      }

      const attemptMsg = remaining > 0
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
