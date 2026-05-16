import {
  type EnhancedTesseraConfig,
  type ResolvedConfig,
  DEFAULT_CONFIG,
  DEFAULT_ENHANCED_CONFIG,
  ENFORCED_FLOORS,
} from '../types';

export function resolveConfig(config?: EnhancedTesseraConfig): ResolvedConfig {
  const base = { ...DEFAULT_CONFIG };
  const enhanced: ResolvedConfig = {
    ...base,
    defaultSensitivity: DEFAULT_ENHANCED_CONFIG.defaultSensitivity,
    defaults: {
      ttl: DEFAULT_ENHANCED_CONFIG.defaults.ttl,
      maxReads: DEFAULT_ENHANCED_CONFIG.defaults.maxReads,
      onSuspicion: DEFAULT_ENHANCED_CONFIG.defaults.onSuspicion,
    },
    honeyKeys: {
      count: DEFAULT_ENHANCED_CONFIG.honeyKeys.count,
      sensitivity: DEFAULT_ENHANCED_CONFIG.honeyKeys.sensitivity,
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
        lockdown: DEFAULT_ENHANCED_CONFIG.suspicion.thresholds.lockdown,
      },
      rateLimit: {
        callsPerSecond: DEFAULT_ENHANCED_CONFIG.suspicion.rateLimit.callsPerSecond,
        scorePerExcess: DEFAULT_ENHANCED_CONFIG.suspicion.rateLimit.scorePerExcess,
      },
      passcodeFailure: {
        scorePerAttempt: DEFAULT_ENHANCED_CONFIG.suspicion.passcodeFailure.scorePerAttempt,
      },
    },
    workerRateLimits: {
      maxReadsPerSession: DEFAULT_ENHANCED_CONFIG.workerRateLimits.maxReadsPerSession,
      maxMessagesPerSecond: DEFAULT_ENHANCED_CONFIG.workerRateLimits.maxMessagesPerSecond,
    },
    debug: false,
  };

  if (config) {
    if (config.iterations !== undefined) enhanced.iterations = config.iterations;
    if (config.lockoutAttempts !== undefined) enhanced.lockoutAttempts = config.lockoutAttempts;
    if (config.lockoutAction !== undefined) enhanced.lockoutAction = config.lockoutAction;
    if (config.lockoutDelay !== undefined) enhanced.lockoutDelay = config.lockoutDelay;
    if (config.idleTimeout !== undefined) enhanced.idleTimeout = config.idleTimeout;
    if (config.selectiveKeys !== undefined) enhanced.selectiveKeys = config.selectiveKeys;
    if (config.defaultSensitivity !== undefined)
      enhanced.defaultSensitivity = config.defaultSensitivity;
    if (config.defaults?.ttl !== undefined) enhanced.defaults.ttl = config.defaults.ttl;
    if (config.defaults?.maxReads !== undefined)
      enhanced.defaults.maxReads = config.defaults.maxReads;
    if (config.defaults?.onSuspicion !== undefined)
      enhanced.defaults.onSuspicion = config.defaults.onSuspicion;
    if (config.honeyKeys?.count !== undefined) enhanced.honeyKeys.count = config.honeyKeys.count;
    if (config.honeyKeys?.sensitivity !== undefined)
      enhanced.honeyKeys.sensitivity = config.honeyKeys.sensitivity;
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
      if (th?.lockdown !== undefined) enhanced.suspicion.thresholds.lockdown = th.lockdown;
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
    }
    const wrl = config.workerRateLimits;
    if (wrl?.maxReadsPerSession !== undefined)
      enhanced.workerRateLimits.maxReadsPerSession = wrl.maxReadsPerSession;
    if (wrl?.maxMessagesPerSecond !== undefined)
      enhanced.workerRateLimits.maxMessagesPerSecond = wrl.maxMessagesPerSecond;
    if (config.debug !== undefined) enhanced.debug = config.debug;
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
}): void {
  const vcFloor = ENFORCED_FLOORS['visibilityChangeDuration'] ?? 200;
  const ldThreshold = ENFORCED_FLOORS['lockdownThreshold'] ?? 10;
  const maxReads = ENFORCED_FLOORS['maxReadsPerSession'] ?? 5;
  const maxMsgs = ENFORCED_FLOORS['maxMessagesPerSecond'] ?? 5;
  const honeyMin = ENFORCED_FLOORS['honeyKeyCount'] ?? 1;

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
}

export { type ResolvedConfig } from '../types';
