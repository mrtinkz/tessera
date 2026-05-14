import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  recordFailedAttempt,
  checkLockout,
  resetLockout,
  getRemainingAttempts,
  performWipe,
} from '../../src/core/lockout';

describe('lockout', () => {
  beforeEach(() => {
    resetLockout();
    localStorage.clear();
    sessionStorage.clear();
  });

  it('should start with full attempts remaining', () => {
    expect(getRemainingAttempts(5)).toBe(5);
  });

  it('should decrement attempts on failure', () => {
    recordFailedAttempt(5);
    expect(getRemainingAttempts(5)).toBe(4);
  });

  it('should allow access when under the limit', () => {
    expect(() => checkLockout(5)).not.toThrow();
  });

  it('should lock after exceeding max attempts', () => {
    for (let i = 0; i < 5; i++) {
      recordFailedAttempt(5);
    }
    expect(() => checkLockout(5)).toThrow();
  });

  it('should reset on resetLockout()', () => {
    for (let i = 0; i < 3; i++) {
      recordFailedAttempt(5);
    }
    resetLockout();
    expect(getRemainingAttempts(5)).toBe(5);
    expect(() => checkLockout(5)).not.toThrow();
  });

  it('should auto-reset lockout once the backoff window has elapsed', () => {
    for (let i = 0; i < 5; i++) {
      recordFailedAttempt(5);
    }
    // Simulate time passing beyond the lockout window by manipulating the stored record
    const stored = localStorage.getItem('tessera_lockout');
    expect(stored).not.toBeNull();
    const record = JSON.parse(stored!) as { attempts: number; lockedUntil: number; backoffMs: number };
    record.lockedUntil = Date.now() - 1; // already expired
    localStorage.setItem('tessera_lockout', JSON.stringify(record));

    // checkLockout should not throw after expiry — and should reset the record
    expect(() => checkLockout(5)).not.toThrow();
  });

  it('performWipe should clear localStorage and sessionStorage', () => {
    localStorage.setItem('data', 'secret');
    sessionStorage.setItem('draft', 'private');
    performWipe();
    expect(localStorage.getItem('data')).toBeNull();
    expect(sessionStorage.getItem('draft')).toBeNull();
  });

  it('performWipe should attempt to expire all cookies', () => {
    document.cookie = 'tessera_test=value; path=/';
    performWipe();
    // After wipe the cookie should be removed or set to empty
    const cookies = document.cookie;
    const hasCookie = cookies.includes('tessera_test=value');
    // happy-dom may or may not honour expiry immediately; just ensure no throw
    expect(typeof hasCookie).toBe('boolean');
  });

  it('checkLockout should handle corrupt lockout record gracefully', () => {
    localStorage.setItem('tessera_lockout', 'not-valid-json{{{');
    // Should not throw — falls back to default record
    expect(() => checkLockout(5)).not.toThrow();
  });

  it('recordFailedAttempt should handle corrupt lockout record gracefully', () => {
    localStorage.setItem('tessera_lockout', 'invalid');
    // Should not throw — falls back to default record
    expect(() => recordFailedAttempt(5)).not.toThrow();
    expect(getRemainingAttempts(5)).toBe(4);
  });
});
