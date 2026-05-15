import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { KeySession } from '../../src/core/session';

let session: KeySession;

describe('KeySession', () => {
  beforeEach(() => {
    session = new KeySession();
    vi.useFakeTimers();
  });

  afterEach(() => {
    session.reset();
    vi.useRealTimers();
  });

  it('should be locked initially', () => {
    expect(session.isLocked()).toBe(true);
  });

  it('should accept a key and become unlocked', async () => {
    const fakeKey = {} as CryptoKey;
    session.setKey(fakeKey, 900_000);
    expect(session.isLocked()).toBe(false);
    expect(session.getKey()).toBe(fakeKey);
  });

  it('should lock when lock() is called', () => {
    session.setKey({} as CryptoKey, 900_000);
    session.lock();
    expect(session.isLocked()).toBe(true);
    expect(() => session.getKey()).toThrow();
  });

  it('should auto-lock after idle timeout', () => {
    session.setKey({} as CryptoKey, 10_000);
    expect(session.isLocked()).toBe(false);

    vi.advanceTimersByTime(10_001);
    expect(session.isLocked()).toBe(true);
  });

  it('should reset the timer on touch()', () => {
    session.setKey({} as CryptoKey, 10_000);
    vi.advanceTimersByTime(5000);
    session.touch();
    vi.advanceTimersByTime(5000);
    expect(session.isLocked()).toBe(false);
  });

  it('should throw when getKey() is called without a key set', () => {
    expect(() => session.getKey()).toThrow();
  });

  it('should reset() fully clear state', () => {
    session.setKey({} as CryptoKey, 900_000);
    session.reset();
    expect(session.isLocked()).toBe(true);
    expect(() => session.getKey()).toThrow();
  });

  it('should return null from getKeySafe() when locked', () => {
    session.setKey({} as CryptoKey, 900_000);
    session.lock();
    expect(session.getKeySafe()).toBeNull();
  });

  it('should return null from getKeySafe() when no key set', () => {
    expect(session.getKeySafe()).toBeNull();
  });

  it('should not throw when lock() is called on a fresh KeySession', () => {
    const s = new KeySession();
    expect(() => s.lock()).not.toThrow();
  });
});
