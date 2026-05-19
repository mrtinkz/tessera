import {
  type EnhancedTesseraConfig,
  type ResolvedConfig,
  DEFAULT_CONFIG,
  DEFAULT_ENHANCED_CONFIG,
  ENFORCED_FLOORS,
} from '../types';

/** Regex that every non-default vaultId must satisfy. */
const VAULT_ID_PATTERN = /^[\w-]{1,64}$/;

export function resolveConfig(config?: EnhancedTesseraConfig): ResolvedConfig {
  const base = { ...DEFAULT_CONFIG };

  // Validate vaultId before any other work so storage key injection is caught early.
  const rawVaultId = config?.vaultId ?? 'default';
  if (rawVaultId !== 'default' && !VAULT_ID_PATTERN.test(rawVaultId)) {
    throw new Error(
      `vaultId "${rawVaultId}" is invalid. ` +
        'Use only letters, digits, underscores, and hyphens (1–64 characters). ' +
        'Invalid vaultId values are rejected to prevent storage-key injection.',
    );
  }

  const enhanced: ResolvedConfig = {
    ...base,
    // Default to 'default' vault ID so existing single-vault apps are unchanged.
    vaultId: rawVaultId,
    defaultSensitivity: DEFAULT_ENHANCED_CONFIG.defaultSensitivity,
    defaults: {
      ttl: DEFAULT_ENHANCED_CONFIG.defaults.ttl,
      maxReads: DEFAULT_ENHANCED_CONFIG.defaults.maxReads,
      onSuspicion: DEFAULT_ENHANCED_CONFIG.defaults.onSuspicion,
    },
    honeyKeys: {
      count: DEFAULT_ENHANCED_CONFIG.honeyKeys.count,
      sensitivity: DEFAULT_ENHANCED_CONFIG.honeyKeys.sensitivity,
      maxPerBackend: 500,
    },
    halfLife: {
      soft: DEFAULT_ENHANCED_CONFIG.halfLife.soft,
      hard: DEFAULT_ENHANCED_CONFIG.halfLife.hard,
    },
    suspicion: {
      platform: DEFAULT_ENHANCED_CONFIG.suspicion.platform,
      visibilityChange: {
        duration: {
          desktop: DEFAULT_ENHANCED_CONFIG.suspicion.visibilityChange.duration.desktop,
          mobile: DEFAULT_ENHANCED_CONFIG.suspicion.visibilityChange.duration.mobile,
          floor: DEFAULT_ENHANCED_CONFIG.suspicion.visibilityChange.duration.floor,
        },
        score: DEFAULT_ENHANCED_CONFIG.suspicion.visibilityChange.score,
      },
      thresholds: {
        cautious: DEFAULT_ENHANCED_CONFIG.suspicion.thresholds.cautious,
        guarded: DEFAULT_ENHANCED_CONFIG.suspicion.thresholds.guarded,
        critical: DEFAULT_ENHANCED_CONFIG.suspicion.thresholds.critical,
        lockdown: DEFAULT_ENHANCED_CONFIG.suspicion.thresholds.lockdown,
      },
      scoreDecayHalfLifeMs: DEFAULT_ENHANCED_CONFIG.suspicion.scoreDecayHalfLifeMs,
      rateLimit: {
        callsPerSecond: DEFAULT_ENHANCED_CONFIG.suspicion.rateLimit.callsPerSecond,
        scorePerExcess: DEFAULT_ENHANCED_CONFIG.suspicion.rateLimit.scorePerExcess,
      },
      passcodeFailure: {
        scorePerAttempt: DEFAULT_ENHANCED_CONFIG.suspicion.passcodeFailure.scorePerAttempt,
      },
      persistScore: false,
    },
    workerRateLimits: {
      maxReadsPerSession: DEFAULT_ENHANCED_CONFIG.workerRateLimits.maxReadsPerSession,
      maxMessagesPerSecond: DEFAULT_ENHANCED_CONFIG.workerRateLimits.maxMessagesPerSecond,
    },
    debug: false,
    cspCheck: 'warn',
  };

  if (config) {
    if (config.iterations !== undefined) enhanced.iterations = config.iterations;
    if (config.lockoutAttempts !== undefined) enhanced.lockoutAttempts = config.lockoutAttempts;
    if (config.lockoutAction !== undefined) enhanced.lockoutAction = config.lockoutAction;
    if (config.lockoutDelay !== undefined) enhanced.lockoutDelay = config.lockoutDelay;
    if (config.idleTimeout !== undefined) enhanced.idleTimeout = config.idleTimeout;
    if (enhanced.idleTimeout < 1000) {
      // Warn but do not throw — very short timeouts may be intentional in test
      // environments. An idleTimeout shorter than a single async adapter call
      // will cause silent null returns from getItem, which is surprising.
      console.warn(
        `tessera: idleTimeout is ${enhanced.idleTimeout}ms — vault will lock between ` +
          'async adapter operations, causing silent null returns from getItem.',
      );
    }
    if (config.selectiveKeys !== undefined) enhanced.selectiveKeys = config.selectiveKeys;
    if (config.defaultSensitivity !== undefined)
      enhanced.defaultSensitivity = config.defaultSensitivity;
    if (config.defaults?.ttl !== undefined) {
      if (config.defaults.ttl <= 0) {
        throw new Error('config.defaults.ttl must be a positive number of milliseconds.');
      }
      enhanced.defaults.ttl = config.defaults.ttl;
    }
    if (config.defaults?.maxReads !== undefined) {
      if (config.defaults.maxReads <= 0 || !Number.isInteger(config.defaults.maxReads)) {
        throw new Error('config.defaults.maxReads must be a positive integer.');
      }
      enhanced.defaults.maxReads = config.defaults.maxReads;
    }
    if (config.defaults?.onSuspicion !== undefined)
      enhanced.defaults.onSuspicion = config.defaults.onSuspicion;
    if (config.honeyKeys?.count !== undefined) enhanced.honeyKeys.count = config.honeyKeys.count;
    if (config.honeyKeys?.sensitivity !== undefined)
      enhanced.honeyKeys.sensitivity = config.honeyKeys.sensitivity;
    if (config.honeyKeys?.aliasGenerator !== undefined)
      enhanced.honeyKeys.aliasGenerator = config.honeyKeys.aliasGenerator;
    if (config.honeyKeys?.maxPerBackend !== undefined) {
      if (config.honeyKeys.maxPerBackend < 1 || !Number.isInteger(config.honeyKeys.maxPerBackend)) {
        throw new Error('config.honeyKeys.maxPerBackend must be a positive integer.');
      }
      enhanced.honeyKeys.maxPerBackend = config.honeyKeys.maxPerBackend;
    }
    if (config.halfLife?.soft !== undefined) enhanced.halfLife.soft = config.halfLife.soft;
    if (config.halfLife?.hard !== undefined) enhanced.halfLife.hard = config.halfLife.hard;
    if (config.suspicion) {
      const s = config.suspicion;
      if (s.platform !== undefined) enhanced.suspicion.platform = s.platform;
      const vc = s.visibilityChange;
      if (vc) {
        const dur = vc.duration;
        if (dur) {
          if (dur.desktop !== undefined)
            enhanced.suspicion.visibilityChange.duration.desktop = dur.desktop;
          if (dur.mobile !== undefined)
            enhanced.suspicion.visibilityChange.duration.mobile = dur.mobile;
          if (dur.floor !== undefined)
            enhanced.suspicion.visibilityChange.duration.floor = dur.floor;
        }
        if (vc.score !== undefined) enhanced.suspicion.visibilityChange.score = vc.score;
      }
      const th = s.thresholds;
      if (th?.cautious !== undefined) enhanced.suspicion.thresholds.cautious = th.cautious;
      if (th?.guarded !== undefined) enhanced.suspicion.thresholds.guarded = th.guarded;
      if (th?.critical !== undefined) enhanced.suspicion.thresholds.critical = th.critical;
      if (th?.lockdown !== undefined) enhanced.suspicion.thresholds.lockdown = th.lockdown;
      if (s.scoreDecayHalfLifeMs !== undefined)
        enhanced.suspicion.scoreDecayHalfLifeMs = s.scoreDecayHalfLifeMs;
      const rl = s.rateLimit;
      if (rl) {
        if (rl.callsPerSecond !== undefined)
          enhanced.suspicion.rateLimit.callsPerSecond = rl.callsPerSecond;
        if (rl.scorePerExcess !== undefined)
          enhanced.suspicion.rateLimit.scorePerExcess = rl.scorePerExcess;
      }
      const pf = s.passcodeFailure;
      if (pf?.scorePerAttempt !== undefined)
        enhanced.suspicion.passcodeFailure.scorePerAttempt = pf.scorePerAttempt;
      if (s.persistScore !== undefined) enhanced.suspicion.persistScore = s.persistScore;
    }
    const wrl = config.workerRateLimits;
    if (wrl?.maxReadsPerSession !== undefined)
      enhanced.workerRateLimits.maxReadsPerSession = wrl.maxReadsPerSession;
    if (wrl?.maxMessagesPerSecond !== undefined)
      enhanced.workerRateLimits.maxMessagesPerSecond = wrl.maxMessagesPerSecond;
    if (config.debug !== undefined) enhanced.debug = config.debug;
    if (config.cspCheck !== undefined) enhanced.cspCheck = config.cspCheck;
    if (config.onBeforeWrite !== undefined) enhanced.onBeforeWrite = config.onBeforeWrite;
    if (config.maxValueBytes !== undefined) {
      if (config.maxValueBytes < 1 || !Number.isInteger(config.maxValueBytes)) {
        throw new Error('config.maxValueBytes must be a positive integer.');
      }
      enhanced.maxValueBytes = config.maxValueBytes;
    }
    if (config.maxUnlockDurationMs !== undefined) {
      if (config.maxUnlockDurationMs <= 0) {
        throw new Error('config.maxUnlockDurationMs must be a positive number of milliseconds.');
      }
      enhanced.maxUnlockDurationMs = config.maxUnlockDurationMs;
    }
    if (config.contextBinding !== undefined) {
      enhanced.contextBinding = {
        webauthn: config.contextBinding.webauthn,
        onMismatch: config.contextBinding.onMismatch ?? 'throw',
      };
    }
  }

  applyFloors(enhanced);

  return enhanced;
}

function applyFloors(enhanced: {
  suspicion: {
    visibilityChange: { duration: { floor: number } };
    thresholds: { lockdown: number };
  };
  workerRateLimits: { maxReadsPerSession: number; maxMessagesPerSecond: number };
  honeyKeys: { count: number };
  lockoutAttempts: number;
}): void {
  /* v8 ignore next 7 */
  const vcFloor = ENFORCED_FLOORS['visibilityChangeDuration'] ?? 200;
  const ldThreshold = ENFORCED_FLOORS['lockdownThreshold'] ?? 10;
  const maxReads = ENFORCED_FLOORS['maxReadsPerSession'] ?? 5;
  const maxMsgs = ENFORCED_FLOORS['maxMessagesPerSecond'] ?? 5;
  const honeyMin = ENFORCED_FLOORS['honeyKeyCount'] ?? 1;
  const lockoutMin = ENFORCED_FLOORS['lockoutAttemptsMin'] ?? 3;
  const lockoutMax = ENFORCED_FLOORS['lockoutAttemptsMax'] ?? 20;

  const d = enhanced.suspicion.visibilityChange.duration;
  if (d.floor < vcFloor) {
    d.floor = vcFloor;
  }
  if (enhanced.suspicion.thresholds.lockdown < ldThreshold) {
    enhanced.suspicion.thresholds.lockdown = ldThreshold;
  }
  if (enhanced.workerRateLimits.maxReadsPerSession < maxReads) {
    enhanced.workerRateLimits.maxReadsPerSession = maxReads;
  }
  if (enhanced.workerRateLimits.maxMessagesPerSecond < maxMsgs) {
    enhanced.workerRateLimits.maxMessagesPerSecond = maxMsgs;
  }
  if (enhanced.honeyKeys.count > 0 && enhanced.honeyKeys.count < honeyMin) {
    enhanced.honeyKeys.count = honeyMin;
  }
  // Enforce floor and ceiling on lockoutAttempts to prevent accidental
  // disabling of brute-force protection (too high) or excessive lockouts (too low).
  if (enhanced.lockoutAttempts < lockoutMin) {
    enhanced.lockoutAttempts = lockoutMin;
  }
  if (enhanced.lockoutAttempts > lockoutMax) {
    enhanced.lockoutAttempts = lockoutMax;
  }
}

export { type ResolvedConfig } from '../types';
