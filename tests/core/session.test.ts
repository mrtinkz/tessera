import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { KeySession, keySession } from '../../src/core/session';

describe('KeySession', () => {
  beforeEach(() => {
    keySession.reset();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should be locked initially', () => {
    expect(keySession.isLocked()).toBe(true);
  });

  it('should accept a key and become unlocked', async () => {
    const fakeKey = {} as CryptoKey;
    keySession.setKey(fakeKey, 900_000);
    expect(keySession.isLocked()).toBe(false);
    expect(keySession.getKey()).toBe(fakeKey);
  });

  it('should lock when lock() is called', () => {
    keySession.setKey({} as CryptoKey, 900_000);
    keySession.lock();
    expect(keySession.isLocked()).toBe(true);
    expect(() => keySession.getKey()).toThrow();
  });

  it('should auto-lock after idle timeout', () => {
    keySession.setKey({} as CryptoKey, 10_000);
    expect(keySession.isLocked()).toBe(false);

    vi.advanceTimersByTime(10_001);
    expect(keySession.isLocked()).toBe(true);
  });

  it('should reset the timer on touch()', () => {
    keySession.setKey({} as CryptoKey, 10_000);
    vi.advanceTimersByTime(5_000);
    keySession.touch();
    vi.advanceTimersByTime(5_000);
    expect(keySession.isLocked()).toBe(false);
  });

  it('should throw when getKey() is called without a key set', () => {
    expect(() => keySession.getKey()).toThrow();
  });

  it('should reset() fully clear state', () => {
    keySession.setKey({} as CryptoKey, 900_000);
    keySession.reset();
    expect(keySession.isLocked()).toBe(true);
    expect(() => keySession.getKey()).toThrow();
  });

  it('should return null from getKeySafe() when locked', () => {
    keySession.setKey({} as CryptoKey, 900_000);
    keySession.lock();
    expect(keySession.getKeySafe()).toBeNull();
  });

  it('should return null from getKeySafe() when no key set', () => {
    expect(keySession.getKeySafe()).toBeNull();
  });

  it('should not throw when lock() is called on a fresh KeySession', () => {
    const s = new KeySession();
    expect(() => s.lock()).not.toThrow();
  });
});
