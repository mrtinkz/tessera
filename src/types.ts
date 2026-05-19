export const TesseraErrorCode = {
  LOCKED: 'LOCKED',
  DECRYPT_FAILED: 'DECRYPT_FAILED',
  LOCKOUT: 'LOCKOUT',
  STORAGE_QUOTA: 'STORAGE_QUOTA',
  /** Storage is blocked by private mode or a browser security policy — not a storage quota issue. */
  STORAGE_UNAVAILABLE: 'STORAGE_UNAVAILABLE',
  UNSUPPORTED_ENV: 'UNSUPPORTED_ENV',
  INVALID_PASSCODE: 'INVALID_PASSCODE',
  STORAGE_KEY_NOT_FOUND: 'STORAGE_KEY_NOT_FOUND',
  /** Thrown by getItem when a soft half-life threshold is crossed and reconfirmation has not been completed. */
  RECONFIRMATION_REQUIRED: 'RECONFIRMATION_REQUIRED',
  /** Thrown by a scoped vault reference when the key or operation is outside the declared scope. */
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  /** Thrown when onBeforeWrite returns false or maxValueBytes is exceeded. */
  VALIDATION_ERROR: 'VALIDATION_ERROR',
} as const;

export type TesseraErrorCode = (typeof TesseraErrorCode)[keyof typeof TesseraErrorCode];

export class TesseraError extends Error {
  public readonly code: TesseraErrorCode;
  public readonly cause?: unknown;

  constructor(code: TesseraErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'TesseraError';
    this.code = code;
    this.cause = cause;
  }
}

export type Result<T, E = TesseraError> = { ok: true; value: T } | { ok: false; error: E };

/** Sensitivity levels with cascading default profiles. */
export type SensitivityLevel = 'low' | 'medium' | 'high' | 'critical';

/** Action taken when suspicion anomaly is detected. */
export type SuspicionAction = 'wipe' | 'lock' | 'throw';

/** Storage mode for session and cookie backends. */
export type StorageMode = 'direct' | 'claim' | 'split';

/** Self-destruct and half-life config per key. */
export interface StorageItemOptions {
  mode?: StorageMode;
  sensitivity?: SensitivityLevel;
  ttl?: number;
  maxReads?: number;
  onSuspicion?: SuspicionAction;
  halfLife?: HalfLifeConfig;
}

/** Half-life access thresholds. soft = reconfirmation required, hard = wipe. */
export interface HalfLifeConfig {
  soft: number;
  hard: number;
}

/** Honey key configuration. */
export interface HoneyKeyConfig {
  count: number;
  sensitivity?: SensitivityLevel;
  /**
   * Override the synthetic decoy-alias generator with one that matches your
   * app's exact key naming convention. Called once per honey slot with a
   * zero-based index. Return a string that looks like a real storage key in
   * your app (e.g. `oidc_nonce_bak`, `stripePublicKeyCache`). Tessera still
   * deduplicates against real aliases; if a collision occurs the generator is
   * called again with the same index until a unique alias is produced.
   */
  aliasGenerator?: (index: number) => string;
  /**
   * Maximum number of honey key storage entries tracked per backend.
   * When the cap is reached the oldest entry is evicted (FIFO).
   * Default 500. Prevents unbounded memory growth in long sessions.
   */
  maxPerBackend?: number;
}

/** Suspicion scoring and platform-aware visibility change configuration. */
export interface SuspicionConfig {
  platform?: 'auto' | 'desktop' | 'mobile';
  visibilityChange?: {
    duration?: {
      desktop?: number;
      mobile?: number;
      floor?: number;
    };
    score?: number;
  };
  thresholds?: {
    /** Score at which a `suspicion-cautious` event fires (informational). Default 25. */
    cautious?: number;
    /** Score at which a `suspicion-guarded` event fires (informational). Default 50. */
    guarded?: number;
    /** Score at which a `suspicion-critical` event fires (informational). Default 75. */
    critical?: number;
    /** Score at which the vault locks down and wipes. Default 100. */
    lockdown?: number;
  };
  /** Half-life for score decay in ms. Score decays continuously toward 0.
   * Set to 0 to disable decay. Default 120_000 (2 min). */
  scoreDecayHalfLifeMs?: number;
  rateLimit?: {
    callsPerSecond?: number;
    scorePerExcess?: number;
  };
  /**
   * Persist the suspicion score across page reloads. The score is
   * HMAC-signed before writing to `localStorage` so tampering is detected.
   * On the next `unlock()` the stored score is loaded, verified, and
   * exponential-decay is applied from the stored timestamp.
   * Default `false`.
   */
  persistScore?: boolean;
  passcodeFailure?: {
    scorePerAttempt?: number;
  };
}

/** Worker rate limits. */
export interface WorkerRateLimits {
  maxReadsPerSession: number;
  maxMessagesPerSecond: number;
}

/** Base config (existing). */
export interface TesseraConfig {
  iterations?: number;
  lockoutAttempts?: number;
  lockoutAction?: 'wipe' | 'delay' | 'throw';
  lockoutDelay?: number;
  idleTimeout?: number;
  /**
   * @remarks Reserved for a future per-key encryption filter — currently not enforced by any adapter.
   * Configure `sensitivity` per item instead for access-control-style behaviour.
   */
  selectiveKeys?: string[];
}

/** Enhanced config with protection features. */
export interface EnhancedTesseraConfig extends TesseraConfig {
  /**
   * Vault namespace identifier. Isolates all storage keys, the IDB
   * database, and lockout records so multiple independent vaults can coexist
   * on the same origin without collision.
   *
   * Defaults to `'default'` — existing single-vault apps continue to work
   * with zero migration.
   *
   * @example Multi-user app
   * ```ts
   * const vault = await Tessera.unlock(passcode, { vaultId: user.id });
   * ```
   */
  vaultId?: string;
  defaultSensitivity?: SensitivityLevel;
  defaults?: {
    ttl?: number;
    maxReads?: number;
    onSuspicion?: SuspicionAction;
  };
  honeyKeys?: HoneyKeyConfig;
  halfLife?: HalfLifeConfig;
  suspicion?: SuspicionConfig;
  workerRateLimits?: WorkerRateLimits;
  /**
   * Controls what tessera does when it cannot detect a Content-Security-Policy
   * at `unlock()` time.
   *
   * - `'warn'` *(default)*: emits a `csp-warning` event so you can surface the
   *   issue in your monitoring. No exception is thrown.
   * - `'require'`: throws `UNSUPPORTED_ENV` if no CSP meta tag is found.
   *   Useful in security-hardened apps that want to enforce deployment hygiene.
   * - `false`: disables the check entirely (e.g. when CSP is set via HTTP
   *   header and you don't want the warning).
   *
   * > **Note**: tessera can only detect CSP set via a
   * > `<meta http-equiv="Content-Security-Policy">` tag or the presence of the
   * > Trusted Types API. A CSP delivered as an HTTP response header is **not
   * > detectable from JavaScript** — use `cspCheck: false` in that case.
   */
  cspCheck?: 'warn' | 'require' | false;
  debug?: boolean;
  /**
   * Called before every `setItem` write, after the size check but before
   * encryption. Return `false` to abort the write with `VALIDATION_ERROR`.
   * Use this to enforce app-specific policies (e.g. block writes when offline,
   * reject values that fail a schema check, or log every write attempt).
   *
   * @param key   - The developer-supplied alias (before key-name rotation).
   * @param value - The plaintext value being stored.
   */
  onBeforeWrite?: (key: string, value: string) => boolean;
  /**
   * Reject writes where the UTF-8 byte length of `value` exceeds this limit.
   * Throws `VALIDATION_ERROR`. Useful for enforcing size budgets without
   * relying on per-item checks.
   */
  maxValueBytes?: number;
  /**
   * Hard upper bound on how long the vault can remain unlocked after a
   * successful `Tessera.unlock()` call, in milliseconds. Unlike `idleTimeout`,
   * this timer is NOT reset by activity — the vault locks unconditionally when
   * the duration elapses. Useful for compliance requirements (e.g. "lock after
   * 30 minutes regardless of activity"). Omit or set to `undefined` to disable.
   */
  maxUnlockDurationMs?: number;
  /**
   * Bind the vault to the current browser context using a WebAuthn assertion.
   * When `webauthn: true`, `Tessera.unlock()` will:
   * 1. On first unlock: create a WebAuthn credential and store its ID.
   * 2. On subsequent unlocks: require a successful WebAuthn assertion before
   *    activating the derived key.
   *
   * This acts as a second factor: an attacker with the user's passcode but
   * without the device (biometric/PIN) cannot unlock the vault.
   */
  contextBinding?: {
    webauthn: boolean;
    /** Action when the WebAuthn assertion fails or is unavailable.
     * - `'throw'` *(default)*: throws `UNSUPPORTED_ENV`.
     * - `'lock'`: leaves the vault locked.
     * - `'wipe'`: calls `hardWipe` on all vault keys and throws `LOCKOUT`. */
    onMismatch?: 'throw' | 'lock' | 'wipe';
  };
}

export const DEFAULT_CONFIG: Required<TesseraConfig> = {
  iterations: 310_000,
  lockoutAttempts: 5,
  lockoutAction: 'delay',
  lockoutDelay: 30_000,
  idleTimeout: 900_000,
  selectiveKeys: [],
};

export const DEFAULT_ENHANCED_CONFIG: {
  defaultSensitivity: SensitivityLevel;
  defaults: { ttl: number; maxReads: number; onSuspicion: SuspicionAction };
  honeyKeys: { count: number; sensitivity: SensitivityLevel };
  halfLife: { soft: number; hard: number };
  suspicion: ResolvedSuspicionConfig;
  workerRateLimits: { maxReadsPerSession: number; maxMessagesPerSecond: number };
} = {
  defaultSensitivity: 'medium',
  defaults: {
    ttl: 3_600_000,
    maxReads: 50,
    onSuspicion: 'wipe',
  },
  honeyKeys: { count: 3, sensitivity: 'high' },
  halfLife: {
    soft: 300_000,
    hard: 900_000,
  },
  suspicion: {
    platform: 'auto',
    visibilityChange: {
      duration: {
        desktop: 500,
        mobile: 3000,
        floor: 200,
      },
      score: 5,
    },
    thresholds: {
      cautious: 25,
      guarded: 50,
      critical: 75,
      lockdown: 100,
    },
    scoreDecayHalfLifeMs: 120_000,
    rateLimit: {
      callsPerSecond: 10,
      scorePerExcess: 10,
    },
    passcodeFailure: {
      scorePerAttempt: 20,
    },
    persistScore: false,
  },
  workerRateLimits: {
    maxReadsPerSession: 20,
    maxMessagesPerSecond: 50,
  },
};

/** Sensitivity default profiles. */
export const SENSITIVITY_DEFAULTS: Record<
  SensitivityLevel,
  {
    ttl?: number;
    maxReads?: number;
    halfLifeSoft?: number;
    honeyKeys: boolean;
  }
> = {
  low: { honeyKeys: false },
  medium: { ttl: 3_600_000, maxReads: 50, honeyKeys: true },
  high: { ttl: 900_000, maxReads: 10, halfLifeSoft: 300_000, honeyKeys: true },
  critical: { ttl: 300_000, maxReads: 3, halfLifeSoft: 60_000, honeyKeys: true },
};

/** Enforced floors for critical settings. */
export const ENFORCED_FLOORS: Record<string, number> = {
  visibilityChangeDuration: 200,
  lockdownThreshold: 10,
  maxReadsPerSession: 5,
  maxMessagesPerSecond: 5,
  honeyKeyCount: 1,
  /** Minimum value for lockoutAttempts — below 3 is functionally no brute-force protection. */
  lockoutAttemptsMin: 3,
  /** Maximum value for lockoutAttempts — above 20 gives attackers too many free guesses. */
  lockoutAttemptsMax: 20,
};

/** Fully resolved suspicion config with all fields filled in. */
export interface ResolvedSuspicionConfig {
  platform: 'auto' | 'desktop' | 'mobile';
  visibilityChange: {
    duration: {
      desktop: number;
      mobile: number;
      floor: number;
    };
    score: number;
  };
  thresholds: {
    cautious: number;
    guarded: number;
    critical: number;
    lockdown: number;
  };
  /** Half-life for score decay in ms. 0 = no decay. */
  scoreDecayHalfLifeMs: number;
  rateLimit: {
    callsPerSecond: number;
    scorePerExcess: number;
  };
  passcodeFailure: {
    scorePerAttempt: number;
  };
  persistScore: boolean;
}

/** Fully resolved configuration combining TesseraConfig + enhanced defaults. */
export interface ResolvedConfig {
  /** Resolved vault namespace. Always a non-empty string; defaults to 'default'. */
  vaultId: string;
  iterations: number;
  lockoutAttempts: number;
  lockoutAction: 'wipe' | 'delay' | 'throw';
  lockoutDelay: number;
  idleTimeout: number;
  selectiveKeys: string[];
  defaultSensitivity: SensitivityLevel;
  defaults: {
    ttl: number;
    maxReads: number;
    onSuspicion: SuspicionAction;
  };
  honeyKeys: {
    count: number;
    sensitivity: SensitivityLevel;
    aliasGenerator?: (index: number) => string;
    maxPerBackend: number;
  };
  halfLife: Required<HalfLifeConfig>;
  suspicion: ResolvedSuspicionConfig;
  workerRateLimits: Required<WorkerRateLimits>;
  cspCheck: 'warn' | 'require' | false;
  debug: boolean;
  onBeforeWrite?: (key: string, value: string) => boolean;
  maxValueBytes?: number;
  maxUnlockDurationMs?: number;
  contextBinding?: {
    webauthn: boolean;
    onMismatch: 'throw' | 'lock' | 'wipe';
  };
}

/** Per-value metadata stored encrypted alongside the value. */
export interface ValueMetadata {
  writeTime: number;
  readCount: number;
  sensitivity?: SensitivityLevel;
  ttl?: number;
  maxReads?: number;
  onSuspicion?: SuspicionAction;
  halfLifeSoft?: number;
  halfLifeHard?: number;
}

/** Inspectable snapshot of a stored item returned by exportItem. */
export interface ExportedItem {
  value: string;
  writeTime: number;
  readCount: number;
  sensitivity?: SensitivityLevel;
  ttl?: number;
  maxReads?: number;
  onSuspicion?: SuspicionAction;
  halfLifeSoft?: number;
  halfLifeHard?: number;
}

// === Event system types ===

export type TesseraEventName =
  | 'csp-warning'
  | 'suspicion-cautious'
  | 'suspicion-guarded'
  | 'suspicion-critical'
  | 'suspicion-lockdown'
  | 'key-wiped'
  | 'key-expired'
  | 'max-reads-reached'
  | 'hmac-failure'
  | 'honey-triggered'
  | 'reconfirmation-required'
  | 'auto-locked'
  | 'rate-limit-warning'
  | 'storage-quota-warning'
  | 'vault-locked'
  | 'vault-unlocked'
  | 'handler-error';

export interface TesseraEventPayloads {
  'csp-warning': {
    /** Always false — HTTP-header CSP cannot be detected from JavaScript. */
    httpHeaderCspUndetectable: true;
    /** A human-readable message explaining the issue and how to silence it. */
    message: string;
  };
  'suspicion-lockdown': { reason: string; score: number; keysWiped: string[] };
  'suspicion-cautious': { score: number };
  'suspicion-guarded': { score: number };
  'suspicion-critical': { score: number };
  'key-wiped': { keyAlias: string; backend: string; reason: string };
  'key-expired': { keyAlias: string; backend: string; expiredAt: number };
  'max-reads-reached': { keyAlias: string; backend: string; reads: number };
  'hmac-failure': { keyAlias: string; backend: string };
  'honey-triggered': { backend: string; score: number };
  'reconfirmation-required': { keyAlias: string; softThresholdMs: number; elapsedMs: number };
  'auto-locked': { reason: 'idle-timeout' };
  'rate-limit-warning': { callsPerSecond: number; threshold: number };
  'storage-quota-warning': { backend: string; usedBytes: number; quotaBytes: number };
  'vault-locked': { reason: string };
  'vault-unlocked': { mode: string };
  'handler-error': { sourceEvent: string; error: unknown };
}

export type TesseraEventHandler<E extends TesseraEventName> = (
  payload: TesseraEventPayloads[E],
) => void;

export interface ITesseraEmitter {
  on<E extends TesseraEventName>(event: E, handler: TesseraEventHandler<E>): void;
  off<E extends TesseraEventName>(event: E, handler?: TesseraEventHandler<E>): void;
}

// === Existing storage interfaces (enhanced with options) ===

export interface IStorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string, options?: StorageItemOptions): Promise<void>;
  removeItem(key: string): Promise<void>;
  clear(): Promise<void>;
  keys(): Promise<string[]>;

  getRawKey?(developerKey: string): Promise<string>;
  exportItem(alias: string): Promise<ExportedItem | null>;
  setHoneyManager?(manager: HoneyKeyManagerIsh): void;
}

export interface HoneyKeyManagerIsh {
  add(backend: string, key: string): void;
  remove(backend: string, key: string): void;
  isHoney(backend: string, key: string): boolean;
  isDecoyAlias(backend: string, alias: string): boolean;
  allDecoyAliases(backend: string): string[];
}

export interface ICookieAdapter {
  get(name: string): Promise<string | null>;
  set(name: string, value: string, options?: CookieOptions & StorageItemOptions): Promise<void>;
  remove(name: string): Promise<void>;
}

export interface IIDBAdapter {
  put(storeName: string, key: string, value: unknown, options?: StorageItemOptions): Promise<void>;
  get(storeName: string, key: string): Promise<unknown>;
  remove(storeName: string, key: string): Promise<void>;
  clear(storeName: string): Promise<void>;
  /** Close the persistent IDB connection. Called when the vault is locked or destroyed. */
  close(): void;
}

export interface CookieOptions {
  expires?: number;
  path?: string;
  domain?: string;
  sameSite?: 'Strict' | 'Lax' | 'None';
  secure?: boolean;
}

/** Capability-limited view of a vault's adapters, restricted to a declared set of keys and operations. */
export interface IScopedVault {
  /** Keys accessible through this scope. */
  readonly keys: readonly string[];
  /** Operations permitted in this scope. */
  readonly operations: ReadonlyArray<'read' | 'write'>;
  local: Pick<IStorageAdapter, 'getItem' | 'setItem' | 'removeItem' | 'exportItem'>;
  session: Pick<IStorageAdapter, 'getItem' | 'setItem' | 'removeItem' | 'exportItem'>;
  cookie: Pick<ICookieAdapter, 'get' | 'set' | 'remove'>;
  idb: Pick<IIDBAdapter, 'get' | 'put' | 'remove'>;
}

/** Enhanced vault with event system, lock, reconfirm, and terminate. */
export interface IEnhancedVault extends ITesseraEmitter {
  local: IStorageAdapter;
  session: IStorageAdapter;
  cookie: ICookieAdapter;
  idb: IIDBAdapter;

  lock(): void;
  isLocked(): boolean;
  reconfirm(passcode: string): Promise<void>;
  terminate(): void;
  /**
   * Permanently destroy this vault — wipes all encrypted data, removes
   * the vault salt/verifier, closes the IDB connection, and deletes the IDB
   * database. After this call the vault is permanently unusable.
   *
   * @security Intended for log-out / account-deletion flows. Irreversible.
   */
  destroy(): Promise<void>;

  /**
   * Signs a server-issued challenge with the vault's HMAC key, producing a
   * time-stamped proof that the vault was opened at a specific moment.
   *
   * The proof is: `HMAC-SHA256(hmacKey, challenge ‖ expiresAt_u64_le)`.
   * The server can verify that:
   *   - The correct passcode was used (only the right key produces a valid HMAC).
   *   - The vault was unlocked before `expiresAt` (tessera throws if already expired).
   *   - The challenge cannot be replayed (server-controlled nonce).
   *
   * The vault key never leaves the browser — this is a zero-knowledge proof
   * of vault possession.
   *
   * @param challenge - Server-issued nonce (8–64 bytes).
   * @param expiresAt - Unix timestamp in milliseconds. Tessera throws
   *   `LOCKED` if `Date.now() >= expiresAt` to enforce the time window.
   * @returns Raw HMAC-SHA256 bytes (32 bytes) as a `Uint8Array`.
   * @throws {TesseraError} `LOCKED`  — vault is locked or key is not set.
   * @throws {TesseraError} `LOCKOUT` — challenge window has already expired.
   *
   * @example
   * ```ts
   * // Server sends: { nonce: Uint8Array, expiresAt: number }
   * const proof = await vault.signChallenge(nonce, expiresAt);
   * // Send proof to server for verification
   * ```
   */
  signChallenge(challenge: Uint8Array, expiresAt: number): Promise<Uint8Array>;

  /**
   * Draws a deterministic 5×5 identicon on `canvas`, derived from
   * `HMAC-SHA256(hmacKey, 'visual-fingerprint')`. The identicon is stable
   * across sessions for the same passcode and vault, so the user can use it
   * as a visual trust signal after entering their PIN.
   *
   * The HMAC seed is computed internally and never returned — only pixels are
   * written to the canvas.
   *
   * @param canvas - Target canvas. Rendered at whatever `width`/`height` are
   *   currently set on the element.
   * @param position - Which corner to draw in. Defaults to `'bottom-right'`.
   *   Pass `'full'` to fill the entire canvas.
   * @throws {TesseraError} `LOCKED` — vault must be unlocked to derive the seed.
   */
  renderFingerprint(
    canvas: HTMLCanvasElement,
    position?: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'full',
  ): Promise<void>;

  /**
   * Returns a capability-limited, frozen view of the vault restricted to
   * a declared set of keys and operations. Accessing any key not in `keys`, or
   * performing an operation not in `operations`, throws `PERMISSION_DENIED`.
   *
   * @example Read-only scoped vault for a display component
   * ```ts
   * const readOnly = vault.scope(['profile', 'theme'], ['read']);
   * const profile = await readOnly.local.getItem('profile'); // ok
   * await readOnly.local.setItem('profile', '…');             // throws PERMISSION_DENIED
   * ```
   */
  scope(keys: string[], operations?: ('read' | 'write')[]): IScopedVault;

  /** Directly trigger a honey-hit for testing/demo purposes. */
  _simulateHoneyHit(backend: 'local' | 'session' | 'cookie'): void;

  /** Returns the raw storage keys currently registered as honey keys for a backend. For demo/debug use only. */
  _honeyStorageKeys(backend: 'local' | 'session' | 'cookie'): string[];
}

/** Legacy IVault for backwards compat (without event methods). */
export interface IVault {
  local: IStorageAdapter;
  session: IStorageAdapter;
  cookie: ICookieAdapter;
  idb: IIDBAdapter;
  lock(): void;
  isLocked(): boolean;
}

export interface PinPadConfig {
  onUnlock: (passcode: string) => void;
  onError?: (attemptsRemaining: number) => void;
  randomize?: boolean;
  /** Digits required. Clamped to [6, 16] by renderPinPad — human cognitive limit. Default 6. */
  length?: number;
  theme?: string;
}

export const CLAIM_TOKEN_PREFIX = 'ref:';
