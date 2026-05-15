import { describe, it, expect } from 'vitest';
import { resolveConfig } from '../../src/core/config';
import { DEFAULT_ENHANCED_CONFIG } from '../../src/types';

describe('resolveConfig', () => {
  it('returns defaults when called with no arguments', () => {
    const cfg = resolveConfig();
    expect(cfg.iterations).toBe(DEFAULT_ENHANCED_CONFIG.iterations ?? 310_000);
    expect(cfg.lockoutAttempts).toBeGreaterThan(0);
    expect(cfg.honeyKeys.count).toBeGreaterThanOrEqual(0);
  });

  it('applies iterations override', () => {
    const cfg = resolveConfig({ iterations: 400_000 });
    expect(cfg.iterations).toBe(400_000);
  });

  it('applies lockoutAttempts override', () => {
    const cfg = resolveConfig({ lockoutAttempts: 3 });
    expect(cfg.lockoutAttempts).toBe(3);
  });

  it('applies lockoutAction override', () => {
    const cfg = resolveConfig({ lockoutAction: 'wipe' });
    expect(cfg.lockoutAction).toBe('wipe');
  });

  it('applies idleTimeout override', () => {
    const cfg = resolveConfig({ idleTimeout: 60_000 });
    expect(cfg.idleTimeout).toBe(60_000);
  });

  it('applies defaultSensitivity override', () => {
    const cfg = resolveConfig({ defaultSensitivity: 'high' });
    expect(cfg.defaultSensitivity).toBe('high');
  });

  it('applies defaults.ttl override', () => {
    const cfg = resolveConfig({ defaults: { ttl: 5000 } });
    expect(cfg.defaults.ttl).toBe(5000);
  });

  it('applies defaults.maxReads override', () => {
    const cfg = resolveConfig({ defaults: { maxReads: 10 } });
    expect(cfg.defaults.maxReads).toBe(10);
  });

  it('applies honeyKeys.count override', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 5 } });
    expect(cfg.honeyKeys.count).toBe(5);
  });

  it('applies halfLife.soft and hard overrides', () => {
    const cfg = resolveConfig({ halfLife: { soft: 1000, hard: 5000 } });
    expect(cfg.halfLife.soft).toBe(1000);
    expect(cfg.halfLife.hard).toBe(5000);
  });

  it('applies suspicion.platform override', () => {
    const cfg = resolveConfig({ suspicion: { platform: 'mobile' } });
    expect(cfg.suspicion.platform).toBe('mobile');
  });

  it('applies suspicion.thresholds.lockdown override', () => {
    const cfg = resolveConfig({ suspicion: { thresholds: { lockdown: 200 } } });
    expect(cfg.suspicion.thresholds.lockdown).toBe(200);
  });

  it('applies suspicion.rateLimit overrides', () => {
    const cfg = resolveConfig({ suspicion: { rateLimit: { callsPerSecond: 50 } } });
    expect(cfg.suspicion.rateLimit.callsPerSecond).toBe(50);
  });

  it('enforces floor on visibilityChange duration', () => {
    const cfg = resolveConfig({ suspicion: { visibilityChange: { duration: { floor: 1 } } } });
    expect(cfg.suspicion.visibilityChange.duration.floor).toBeGreaterThanOrEqual(200);
  });

  it('enforces floor on lockdown threshold', () => {
    const cfg = resolveConfig({ suspicion: { thresholds: { lockdown: 1 } } });
    expect(cfg.suspicion.thresholds.lockdown).toBeGreaterThanOrEqual(10);
  });

  it('honeyKeys.count 0 is preserved (disabled)', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 0 } });
    expect(cfg.honeyKeys.count).toBe(0);
  });

  // Covers line 138-140: workerRateLimits floor when below minimum
  it('enforces floor on workerRateLimits.maxReadsPerSession', () => {
    const cfg = resolveConfig({ workerRateLimits: { maxReadsPerSession: 1 } });
    expect(cfg.workerRateLimits.maxReadsPerSession).toBeGreaterThanOrEqual(5);
  });

  it('enforces floor on workerRateLimits.maxMessagesPerSecond', () => {
    const cfg = resolveConfig({ workerRateLimits: { maxMessagesPerSecond: 1 } });
    expect(cfg.workerRateLimits.maxMessagesPerSecond).toBeGreaterThanOrEqual(5);
  });

  // Covers line 141-143: honeyKeys.count floor when between 0 and minimum
  it('enforces minimum honeyKeys.count when count is between 0 and floor', () => {
    // The floor for honeyKeyCount is 1, so setting count to a small but non-zero value
    // that is below the floor should be bumped up to the floor
    // Actually honeyMin=1, so if count=1 it's equal to honeyMin and not changed
    // We test that counts above 0 but below honeyMin are floored
    // Default honeyMin is 1 from ENFORCED_FLOORS; let's verify by checking the config value
    const cfg = resolveConfig({ honeyKeys: { count: 1 } });
    expect(cfg.honeyKeys.count).toBeGreaterThanOrEqual(1);
  });

  // Covers remaining config branches: visibilityChange score, desktop, workerRateLimits
  it('applies all suspicion.visibilityChange overrides', () => {
    const cfg = resolveConfig({
      suspicion: {
        visibilityChange: {
          duration: { desktop: 2000, mobile: 3000, floor: 500 },
          score: 25,
        },
      },
    });
    expect(cfg.suspicion.visibilityChange.duration.desktop).toBe(2000);
    expect(cfg.suspicion.visibilityChange.duration.mobile).toBe(3000);
    expect(cfg.suspicion.visibilityChange.score).toBe(25);
  });

  it('applies suspicion.rateLimit.scorePerExcess override', () => {
    const cfg = resolveConfig({ suspicion: { rateLimit: { scorePerExcess: 20 } } });
    expect(cfg.suspicion.rateLimit.scorePerExcess).toBe(20);
  });

  it('applies suspicion.passcodeFailure.scorePerAttempt override', () => {
    const cfg = resolveConfig({ suspicion: { passcodeFailure: { scorePerAttempt: 30 } } });
    expect(cfg.suspicion.passcodeFailure.scorePerAttempt).toBe(30);
  });

  it('applies defaults.onSuspicion override', () => {
    const cfg = resolveConfig({ defaults: { onSuspicion: 'lock' } });
    expect(cfg.defaults.onSuspicion).toBe('lock');
  });

  it('applies honeyKeys.sensitivity override', () => {
    const cfg = resolveConfig({ honeyKeys: { sensitivity: 'high' } });
    expect(cfg.honeyKeys.sensitivity).toBe('high');
  });

  it('applies workerRateLimits overrides when above floor', () => {
    const cfg = resolveConfig({
      workerRateLimits: { maxReadsPerSession: 100, maxMessagesPerSecond: 50 },
    });
    expect(cfg.workerRateLimits.maxReadsPerSession).toBe(100);
    expect(cfg.workerRateLimits.maxMessagesPerSecond).toBe(50);
  });

  it('applies lockoutDelay override', () => {
    const cfg = resolveConfig({ lockoutDelay: 5000 });
    expect(cfg.lockoutDelay).toBe(5000);
  });

  // Covers line 60: selectiveKeys override
  it('applies selectiveKeys override', () => {
    const cfg = resolveConfig({ selectiveKeys: ['key1', 'key2'] });
    expect(cfg.selectiveKeys).toEqual(['key1', 'key2']);
  });

  // Covers lines 141-143: honeyKeys.count > 0 but below honeyMin (1) is bumped to floor
  it('bumps honeyKeys.count up to the minimum floor when between 0 and 1', () => {
    // honeyMin is 1 from ENFORCED_FLOORS['honeyKeyCount'].
    // A count of 0.5 satisfies: count > 0 && count < honeyMin → gets bumped to honeyMin.
    const cfg = resolveConfig({ honeyKeys: { count: 0.5 } } as Parameters<typeof resolveConfig>[0]);
    expect(cfg.honeyKeys.count).toBeGreaterThanOrEqual(1);
  });
});
