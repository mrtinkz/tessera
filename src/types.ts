/**
 * Discriminated error codes returned by every tessera operation.
 * Using a `const` object rather than `const enum` prevents value inlining
 * across module boundaries — consumers retain a runtime reference that
 * remains correct if the library upgrades a value.
 */
export const TesseraErrorCode = {
  /** The vault is locked; call `Tessera.unlock()` before reading or writing. */
  LOCKED: 'LOCKED',
  /** AES-GCM decryption failed — wrong key, tampered ciphertext, or corrupt data. */
  DECRYPT_FAILED: 'DECRYPT_FAILED',
  /** Too many failed unlock attempts; a lockout window is in effect. */
  LOCKOUT: 'LOCKOUT',
  /** A storage operation failed, typically due to a quota limit. */
  STORAGE_QUOTA: 'STORAGE_QUOTA',
  /**
   * `crypto.subtle` is unavailable in the current runtime.
   * Use tessera only in browser or browser-compatible environments.
   *
   * @security Mitigates accidental server-side use that would expose plaintext.
   */
  UNSUPPORTED_ENV: 'UNSUPPORTED_ENV',
  /** The supplied passcode does not meet the 6–8 character length requirement. */
  INVALID_PASSCODE: 'INVALID_PASSCODE',
  /** A requested storage key was not found (reserved for future use). */
  STORAGE_KEY_NOT_FOUND: 'STORAGE_KEY_NOT_FOUND',
} as const;

/** Union type of all `TesseraErrorCode` string literals. */
export type TesseraErrorCode = (typeof TesseraErrorCode)[keyof typeof TesseraErrorCode];

/**
 * Typed error thrown by every tessera operation.
 * Consumers can switch on `error.code` using {@link TesseraErrorCode} values.
 *
 * @example
 * ```ts
 * try {
 *   await vault.local.setItem('key', 'value');
 * } catch (err) {
 *   if (err instanceof TesseraError && err.code === TesseraErrorCode.LOCKED) {
 *     showUnlockPrompt();
 *   }
 * }
 * ```
 */
export class TesseraError extends Error {
  /** Machine-readable error code. @see {@link TesseraErrorCode} */
  public readonly code: TesseraErrorCode;
  /** The original caught error, if any, that caused this TesseraError. */
  public readonly cause?: unknown;

  constructor(code: TesseraErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'TesseraError';
    this.code = code;
    this.cause = cause;
  }
}

/**
 * A discriminated union for operations that can fail without throwing.
 * Internal adapters return `Result<string>` from decrypt paths so callers
 * receive typed errors rather than catching exceptions.
 *
 * @typeParam T - The success value type.
 * @typeParam E - The error type; defaults to {@link TesseraError}.
 */
export type Result<T, E = TesseraError> =
  | { ok: true; value: T }
  | { ok: false; error: E };

/**
 * Configuration options for `Tessera.unlock()`.
 * All fields are optional; sensible OWASP-compliant defaults are applied.
 *
 * @see {@link DEFAULT_CONFIG} for the default values.
 */
export interface TesseraConfig {
  /**
   * PBKDF2-SHA-256 iteration count.
   * Must be ≥ 310 000 (OWASP 2024 minimum).
   * @default 310_000
   * @security Higher values increase brute-force cost (T5).
   */
  iterations?: number;

  /**
   * Number of failed `Tessera.unlock()` calls before `lockoutAction` fires.
   * @default 5
   */
  lockoutAttempts?: number;

  /**
   * Action taken when `lockoutAttempts` is exhausted.
   * - `'delay'` — applies an exponential backoff window; subsequent calls will
   *   throw `LOCKOUT` until the window elapses (default).
   * - `'throw'` — throws `LOCKOUT` immediately and permanently.
   * - `'wipe'`  — clears all storage then throws `LOCKOUT`.
   * @default 'delay'
   */
  lockoutAction?: 'wipe' | 'delay' | 'throw';

  /**
   * Initial backoff delay in milliseconds for `lockoutAction: 'delay'`.
   * Doubles on each subsequent lockout trigger (exponential backoff).
   * @default 30_000
   */
  lockoutDelay?: number;

  /**
   * Milliseconds of inactivity before the vault auto-locks.
   * Any read or write operation resets the idle timer.
   * @default 900_000 (15 minutes)
   */
  idleTimeout?: number;

  /**
   * Whitelist of storage keys to encrypt. When provided, only these keys are
   * encrypted; all others are stored as plaintext. When omitted (the default),
   * **every** key is encrypted.
   * @default [] (encrypt all)
   */
  selectiveKeys?: string[];
}

/**
 * Resolved configuration with all fields required.
 * Applied by `Tessera.unlock()` when spreading over the user's partial config.
 */
export const DEFAULT_CONFIG: Required<TesseraConfig> = {
  iterations: 310_000,
  lockoutAttempts: 5,
  lockoutAction: 'delay',
  lockoutDelay: 30_000,
  idleTimeout: 900_000,
  selectiveKeys: [],
};

/**
 * A drop-in encrypted replacement for the `localStorage` / `sessionStorage` API.
 * All methods are async because AES-GCM operations are performed before each
 * read/write.
 */
export interface IStorageAdapter {
  /**
   * Retrieves and decrypts a value by key.
   * @param key - The storage key.
   * @returns The plaintext value, or `null` if the key does not exist or the
   *   vault is locked.
   */
  getItem(key: string): Promise<string | null>;

  /**
   * Encrypts and stores a value.
   * @param key - The storage key.
   * @param value - The plaintext value to store.
   * @throws {TesseraError} `LOCKED` if the vault is locked.
   */
  setItem(key: string, value: string): Promise<void>;

  /**
   * Removes a stored key/value pair.
   * @param key - The storage key to remove.
   */
  removeItem(key: string): Promise<void>;

  /** Removes all key/value pairs from the underlying store. */
  clear(): Promise<void>;

  /** Returns all storage keys currently in the underlying store. */
  keys(): Promise<string[]>;
}

/**
 * The vault object returned by `Tessera.unlock()`.
 * All storage adapters share the same in-memory derived key and auto-lock
 * simultaneously when `lock()` is called or the idle timeout expires.
 */
export interface IVault {
  /** Encrypted localStorage adapter. */
  local: IStorageAdapter;
  /** Encrypted sessionStorage adapter. */
  session: IStorageAdapter;
  /** Encrypted cookie adapter. */
  cookie: ICookieAdapter;
  /** Encrypted IndexedDB adapter. */
  idb: IIDBAdapter;

  /**
   * Immediately locks the vault, zeroing the in-memory derived key.
   * All subsequent read/write operations will return `null` or throw `LOCKED`
   * until `Tessera.unlock()` is called again.
   *
   * @security Minimises the window of key exposure in memory (T7).
   */
  lock(): void;

  /** Returns `true` if the vault is currently locked. */
  isLocked(): boolean;
}

/**
 * Encrypted cookie adapter. Encrypts the cookie **value** only; the name,
 * path, domain, `SameSite`, and `Secure` attributes remain in plaintext.
 *
 * @security Note: cookies written by this adapter cannot be `httpOnly` because
 *   JavaScript must read and write them. The value is encrypted, but the
 *   cookie itself is readable by any script on the origin.
 */
export interface ICookieAdapter {
  /**
   * Reads and decrypts a cookie by name.
   * @param name - The cookie name.
   * @returns The plaintext value, or `null` if the cookie does not exist or
   *   the vault is locked.
   */
  get(name: string): Promise<string | null>;

  /**
   * Encrypts and sets a cookie.
   * @param name    - The cookie name.
   * @param value   - The plaintext value to store.
   * @param options - Optional cookie attributes (expiry, path, domain, etc.).
   * @throws {TesseraError} `LOCKED` if the vault is locked.
   */
  set(name: string, value: string, options?: CookieOptions): Promise<void>;

  /**
   * Expires (removes) a cookie.
   * @param name - The cookie name to remove.
   */
  remove(name: string): Promise<void>;
}

/** Attributes for a cookie set by {@link ICookieAdapter.set}. */
export interface CookieOptions {
  /** Number of **days** until the cookie expires. */
  expires?: number;
  /** Cookie path attribute. */
  path?: string;
  /** Cookie domain attribute. */
  domain?: string;
  /** SameSite policy. `'None'` requires `secure: true`. */
  sameSite?: 'Strict' | 'Lax' | 'None';
  /** When `true`, the `Secure` flag is appended. */
  secure?: boolean;
}

/**
 * Encrypted IndexedDB adapter.
 * Values are JSON-serialised, then AES-256-GCM encrypted with a per-value
 * salt before being written to IndexedDB. Key names are stored in plaintext.
 */
export interface IIDBAdapter {
  /**
   * Encrypts and stores a value in a named object store.
   * @param storeName - A logical namespace (stored as a plain key component).
   * @param key       - The record key within the store.
   * @param value     - Any JSON-serialisable value.
   * @throws {TesseraError} `LOCKED` if the vault is locked.
   */
  put(storeName: string, key: string, value: unknown): Promise<void>;

  /**
   * Retrieves and decrypts a value.
   * @param storeName - The logical namespace.
   * @param key       - The record key.
   * @returns The deserialised value, or `undefined` if the key does not exist
   *   or the vault is locked.
   */
  get(storeName: string, key: string): Promise<unknown>;

  /**
   * Deletes a single record.
   * @param storeName - The logical namespace.
   * @param key       - The record key to remove.
   */
  remove(storeName: string, key: string): Promise<void>;

  /**
   * Deletes all records in a named store (other stores are unaffected).
   * @param storeName - The logical namespace to clear.
   */
  clear(storeName: string): Promise<void>;
}

/** Configuration for the Canvas-based PIN pad UI. */
export interface PinPadConfig {
  /**
   * Called with the entered passcode string when the required number of digits
   * has been tapped. The passcode bytes are zeroed in a `finally` block
   * immediately after this callback returns.
   *
   * @param passcode - The plaintext passcode entered by the user.
   * @security Never log or persist this value.
   */
  onUnlock: (passcode: string) => void;

  /**
   * Called after a failed unlock attempt with the number of remaining tries.
   * Use this to update your error UI.
   * @param attemptsRemaining - Number of attempts left before lockout fires.
   */
  onError?: (attemptsRemaining: number) => void;

  /**
   * When `true`, digit positions are re-randomized after every completed
   * passcode entry. The digits are always visible — the security property is
   * that a click-position recorder captures coordinates, not digit labels.
   * Recommended for shared/public devices (anti-shoulder-surf, T4).
   * @default false
   */
  randomize?: boolean;

  /**
   * Expected passcode length. The `onUnlock` callback fires after this many
   * digits have been entered. Must be 6 or 8 to satisfy `Tessera.unlock()`
   * validation (passcode length must be between 6 and 8 characters).
   *
   * **Note:** The built-in PIN pad renders digits 0–9 only. If you need
   * alphanumeric passcodes, build a custom input and call `Tessera.unlock()`
   * directly — alphanumeric passcodes offer significantly more entropy.
   * @default 6
   */
  length?: number;

  /**
   * Reserved for a future theme name. Consumers should prefer CSS custom
   * properties (`--tessera-*`) to override visual styles.
   */
  theme?: string;
}
