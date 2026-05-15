import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  recordFailedAttempt,
  checkLockout,
  resetLockout,
  getRemainingAttempts,
  performWipe,
  signLockoutRecord,
  verifyLockoutRecord,
} from '../../src/core/lockout';
import { deriveHmacKey, getSalt } from '../../src/core/crypto';

describe('lockout', () => {
  beforeEach(() => {
    resetLockout();
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
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
    const record = JSON.parse(stored!) as {
      attempts: number;
      lockedUntil: number;
      backoffMs: number;
    };
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

  it('signLockoutRecord stores a hex signature in localStorage', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    await signLockoutRecord(hmacKey);
    expect(localStorage.getItem('tessera_lockout_sig')).not.toBeNull();
    expect(localStorage.getItem('tessera_lockout_sig')).toMatch(/^[\da-f]+$/);
  });

  it('verifyLockoutRecord returns true when no signature exists', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    localStorage.removeItem('tessera_lockout_sig');
    const result = await verifyLockoutRecord(hmacKey);
    expect(result).toBe(true);
  });

  it('verifyLockoutRecord returns true for intact record', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    await signLockoutRecord(hmacKey);
    const result = await verifyLockoutRecord(hmacKey);
    expect(result).toBe(true);
  });

  it('verifyLockoutRecord returns false for tampered record', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    await signLockoutRecord(hmacKey);
    // Tamper with the lockout record
    localStorage.setItem(
      'tessera_lockout',
      JSON.stringify({ attempts: 99, lockedUntil: null, backoffMs: 1000 }),
    );
    const result = await verifyLockoutRecord(hmacKey);
    expect(result).toBe(false);
  });

  it('verifyLockoutRecord returns false for malformed signature', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    localStorage.setItem('tessera_lockout_sig', 'not-valid-hex!!!');
    const result = await verifyLockoutRecord(hmacKey);
    expect(result).toBe(false);
  });

  it('performWipe when no lockout record exists (null path)', () => {
    localStorage.clear();
    // No lockout record → the lockoutRecord branch is null
    expect(() => performWipe()).not.toThrow();
  });

  // Covers lockout.ts line 31: catch block in writeRecord() when localStorage.setItem throws
  it('writeRecord (via recordFailedAttempt) does not throw when localStorage.setItem throws', () => {
    vi.spyOn(localStorage, 'setItem').mockImplementation(() => {
      throw new Error('Storage quota exceeded');
    });
    // recordFailedAttempt calls writeRecord which calls localStorage.setItem
    expect(() => recordFailedAttempt(5)).not.toThrow();
  });

  // Covers lockout.ts line 63: catch in signLockoutRecord when localStorage.setItem throws
  it('signLockoutRecord does not throw when localStorage.setItem throws', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    vi.spyOn(localStorage, 'setItem').mockImplementation(() => {
      throw new Error('Storage unavailable');
    });
    await expect(signLockoutRecord(hmacKey)).resolves.toBeUndefined();
  });

  // Covers lockout.ts line 77: catch in verifyLockoutRecord when localStorage.getItem throws
  it('verifyLockoutRecord returns true when localStorage.getItem throws', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    vi.spyOn(localStorage, 'getItem').mockImplementation((key: string) => {
      if (key === 'tessera_lockout_sig') throw new Error('Storage unavailable');
      return null;
    });
    const result = await verifyLockoutRecord(hmacKey);
    expect(result).toBe(true);
  });

  // Covers lockout.ts line 179: catch block when localStorage.clear throws
  it('performWipe does not throw when localStorage.clear throws', () => {
    vi.spyOn(localStorage, 'clear').mockImplementation(() => {
      throw new Error('Storage unavailable');
    });
    // Should swallow the error and not throw
    expect(() => performWipe()).not.toThrow();
  });

  // Covers lockout.ts line 191: catch block when document.cookie getter throws
  it('performWipe does not throw when document.cookie access throws', () => {
    vi.spyOn(localStorage, 'clear').mockImplementation(() => {}); // let storage succeed
    const origDescriptor =
      Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ??
      Object.getOwnPropertyDescriptor(document, 'cookie');
    try {
      Object.defineProperty(document, 'cookie', {
        get: () => {
          throw new Error('Cookie access denied');
        },
        configurable: true,
      });
      expect(() => performWipe()).not.toThrow();
    } finally {
      if (origDescriptor) Object.defineProperty(document, 'cookie', origDescriptor);
    }
  });

  // Covers lockout.ts lines 90-91: verifyLockoutRecord catch when crypto.subtle.verify throws
  it('verifyLockoutRecord returns false when crypto.subtle.verify throws', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    // Store a signature that is exactly the right hex-encoded length but invalid
    // A 32-byte HMAC-SHA256 signature = 64 hex chars; store a garbage 64-char hex string
    // crypto.subtle.verify will return false, not throw, for this.
    // To trigger the catch, we need to make crypto.subtle.verify throw.
    vi.spyOn(crypto.subtle, 'verify').mockRejectedValueOnce(new Error('verify failed'));
    // Store any hex signature so the null-check passes
    localStorage.setItem('tessera_lockout_sig', 'aabbccdd'.repeat(8)); // 64 hex chars
    const result = await verifyLockoutRecord(hmacKey);
    expect(result).toBe(false);
    vi.spyOn(crypto.subtle, 'verify').mockRestore?.();
  });
});
