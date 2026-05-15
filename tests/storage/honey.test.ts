import { describe, it, expect } from 'vitest';
import { HoneyKeyManager } from '../../src/storage/honey';
import { resolveConfig } from '../../src/core/config';

function makeManager(count = 3): HoneyKeyManager {
  const config = resolveConfig({ honeyKeys: { count } });
  return new HoneyKeyManager(config);
}

describe('HoneyKeyManager', () => {
  it('isEnabled returns true when count > 0', () => {
    const mgr = makeManager(3);
    expect(mgr.isEnabled).toBe(true);
  });

  it('isEnabled returns false when count is 0', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 0 } });
    const mgr = new HoneyKeyManager(cfg);
    expect(mgr.isEnabled).toBe(false);
  });

  // Covers lines 17-19: count getter
  it('count getter returns honeyKeys.count when enabled', () => {
    const mgr = makeManager(3);
    expect(mgr.count).toBe(3);
  });

  it('count getter returns 0 when disabled', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 0 } });
    const mgr = new HoneyKeyManager(cfg);
    expect(mgr.count).toBe(0);
  });

  it('add() and isHoney() work for a registered key', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_abcdef1234567890abcdef1234567890');
    expect(mgr.isHoney('local', 't_abcdef1234567890abcdef1234567890')).toBe(true);
  });

  it('isHoney() returns false for an unknown key', () => {
    const mgr = makeManager(3);
    expect(mgr.isHoney('local', 't_unknown')).toBe(false);
  });

  it('add() is a no-op when manager is disabled', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 0 } });
    const mgr = new HoneyKeyManager(cfg);
    mgr.add('local', 't_somekey');
    expect(mgr.isHoney('local', 't_somekey')).toBe(false);
  });

  // Covers lines 31-36: remove() when set exists
  it('remove() deletes a previously added honey key', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_aaaa');
    mgr.remove('local', 't_aaaa');
    expect(mgr.isHoney('local', 't_aaaa')).toBe(false);
  });

  // Covers lines 31-36: remove() when set does NOT exist (no-op, should not throw)
  it('remove() is a no-op when the backend has no registered keys', () => {
    const mgr = makeManager(3);
    expect(() => mgr.remove('nonexistent-backend', 't_aaaa')).not.toThrow();
  });

  it('generateHoneyKeys() returns the requested count of keys', () => {
    const mgr = makeManager(3);
    const keys = mgr.generateHoneyKeys('local', [], 3);
    expect(keys).toHaveLength(3);
    expect(keys.every((k) => k.startsWith('t_'))).toBe(true);
  });

  it('generateHoneyKeys() returns [] when disabled', () => {
    const cfg = resolveConfig({ honeyKeys: { count: 0 } });
    const mgr = new HoneyKeyManager(cfg);
    expect(mgr.generateHoneyKeys('local', [], 3)).toHaveLength(0);
  });

  it('generateHoneyKeys() returns [] when count <= 0', () => {
    const mgr = makeManager(3);
    expect(mgr.generateHoneyKeys('local', [], 0)).toHaveLength(0);
  });

  // Covers lines 58-60: clearBackend()
  it('clearBackend() removes all honey keys for the specified backend', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_aaaa');
    mgr.add('local', 't_bbbb');
    mgr.clearBackend('local');
    expect(mgr.isHoney('local', 't_aaaa')).toBe(false);
    expect(mgr.allKeys('local')).toHaveLength(0);
  });

  it('clearBackend() is a no-op for an unknown backend', () => {
    const mgr = makeManager(3);
    expect(() => mgr.clearBackend('unknown')).not.toThrow();
  });

  it('clearAll() removes all honey keys across all backends', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_aaaa');
    mgr.add('session', 't_bbbb');
    mgr.clearAll();
    expect(mgr.isHoney('local', 't_aaaa')).toBe(false);
    expect(mgr.isHoney('session', 't_bbbb')).toBe(false);
  });

  it('allKeys() returns all honey keys for a backend', () => {
    const mgr = makeManager(3);
    mgr.add('local', 't_aaaa');
    mgr.add('local', 't_bbbb');
    const keys = mgr.allKeys('local');
    expect(keys).toContain('t_aaaa');
    expect(keys).toContain('t_bbbb');
  });

  it('allKeys() returns [] for an unknown backend', () => {
    const mgr = makeManager(3);
    expect(mgr.allKeys('unknown')).toHaveLength(0);
  });

  it('generateHoneyKeys() excludes existing real keys', () => {
    const mgr = makeManager(5);
    const existing = ['t_existing0000000000000000000000000'];
    const keys = mgr.generateHoneyKeys('local', existing, 2);
    expect(keys.every((k) => !existing.includes(k))).toBe(true);
  });
});
