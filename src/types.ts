export const TesseraErrorCode = {
  LOCKED: 'LOCKED',
  DECRYPT_FAILED: 'DECRYPT_FAILED',
  LOCKOUT: 'LOCKOUT',
  STORAGE_QUOTA: 'STORAGE_QUOTA',
  UNSUPPORTED_ENV: 'UNSUPPORTED_ENV',
  INVALID_PASSCODE: 'INVALID_PASSCODE',
  STORAGE_KEY_NOT_FOUND: 'STORAGE_KEY_NOT_FOUND',
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
    lockdown?: number;
  };
  rateLimit?: {
    callsPerSecond?: number;
    scorePerExcess?: number;
  };
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
  selectiveKeys?: string[];
}

/** Enhanced config with protection features. */
export interface EnhancedTesseraConfig extends TesseraConfig {
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
      lockdown: 100,
    },
    rateLimit: {
      callsPerSecond: 10,
      scorePerExcess: 10,
    },
    passcodeFailure: {
      scorePerAttempt: 20,
    },
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
    lockdown: number;
  };
  rateLimit: {
    callsPerSecond: number;
    scorePerExcess: number;
  };
  passcodeFailure: {
    scorePerAttempt: number;
  };
}

/** Fully resolved configuration combining TesseraConfig + enhanced defaults. */
export interface ResolvedConfig {
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
  honeyKeys: Required<HoneyKeyConfig>;
  halfLife: Required<HalfLifeConfig>;
  suspicion: ResolvedSuspicionConfig;
  workerRateLimits: Required<WorkerRateLimits>;
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

// === Event system types ===

export type TesseraEventName =
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
  'suspicion-lockdown': { reason: string; score: number; keysWiped: string[] };
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
  setHoneyManager?(manager: HoneyKeyManagerIsh): void;
}

export interface HoneyKeyManagerIsh {
  add(backend: string, key: string): void;
  remove(backend: string, key: string): void;
  isHoney(backend: string, key: string): boolean;
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
}

export interface CookieOptions {
  expires?: number;
  path?: string;
  domain?: string;
  sameSite?: 'Strict' | 'Lax' | 'None';
  secure?: boolean;
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
