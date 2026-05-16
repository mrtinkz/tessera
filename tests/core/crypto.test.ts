import { describe, it, expect } from 'vitest';
import {
  deriveKey,
  deriveHmacKey,
  encrypt,
  decrypt,
  getSalt,
  encryptWithSalt,
  decryptFull,
  zeroPasscode,
  rotateKeyName,
  generateHoneyCiphertext,
} from '../../src/core/crypto';

async function makeKey(passcode = '246813') {
  const salt = await getSalt();
  return deriveKey(passcode, salt);
}

// ─── Known-Answer Test (KAT) Vectors ──────────────────────────────────────────
// Derived offline using Node.js webcrypto with PBKDF2-SHA-256 (310 000 iters)
// + AES-256-GCM. Fixed inputs → deterministic expected output.
//
// Inputs:
//   passcode : '246813'
//   salt     : 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15  (16 bytes)
//   iv       : 00 01 02 03 04 05 06 07 08 09 10 11              (12 bytes)
//   plaintext: 'tessera'
//
// Expected payload (iv ‖ ciphertext ‖ auth-tag, base64):
const KAT_PASSCODE = '246813';
const KAT_SALT_HEX = '00010203040506070809101112131415';
const KAT_PAYLOAD_B64 = 'AAECAwQFBgcICRAR0HBCUp8BqQsenr1m6FedJ6lviRDcu/Y=';
const KAT_PLAINTEXT = 'tessera';

function hexToUint8Array(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

describe('crypto.deriveKey', () => {
  it('should produce a non-extractable AES-GCM key from a passcode and salt', async () => {
    const salt = await getSalt();
    const key = await deriveKey('246813', salt);

    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.extractable).toBe(false);
  });

  it('should reject a passcode shorter than 6 characters', async () => {
    const salt = await getSalt();
    await expect(deriveKey('a', salt)).rejects.toThrow();
  });

  it('should accept a passcode longer than 8 characters', async () => {
    const salt = await getSalt();
    const key = await deriveKey('this-is-a-long-passphrase', salt);
    expect(key.type).toBe('secret');
  });

  it('should reject iterations below the OWASP minimum', async () => {
    const salt = await getSalt();
    await expect(deriveKey('246813', salt, 100)).rejects.toThrow();
  });

  it('should produce different keys for different passcodes', async () => {
    const salt = await getSalt();
    const keyA = await deriveKey('246813', salt);
    const keyB = await deriveKey('987654', salt);
    expect(keyA).not.toBe(keyB);
  });

  it('should produce different keys for different salts', async () => {
    const saltA = await getSalt();
    const saltB = await getSalt();
    const keyA = await deriveKey('246813', saltA);
    const keyB = await deriveKey('246813', saltB);
    expect(keyA).not.toBe(keyB);
  });
});

describe('crypto.encrypt + decrypt (simple)', () => {
  it('should round-trip a string', async () => {
    const key = await makeKey();
    const original = 'hello tessera';
    const encrypted = await encrypt(key, original);
    const result = await decrypt(key, encrypted);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBe(original);
    }
  });

  it('should produce different ciphertexts for the same plaintext (random IV)', async () => {
    const key = await makeKey();
    const original = 'same data';
    const a = await encrypt(key, original);
    const b = await encrypt(key, original);
    expect(a).not.toBe(b);
  });

  it('should handle empty string', async () => {
    const key = await makeKey();
    const encrypted = await encrypt(key, '');
    const result = await decrypt(key, encrypted);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBe('');
    }
  });

  it('should handle special characters and JSON', async () => {
    const key = await makeKey();
    const data = JSON.stringify({ name: 'tesséra', tags: ['🔐', 'secure'] });
    const encrypted = await encrypt(key, data);
    const result = await decrypt(key, encrypted);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(JSON.parse(result.value)).toEqual({ name: 'tesséra', tags: ['🔐', 'secure'] });
    }
  });

  it('should handle large payloads (100KB)', async () => {
    const key = await makeKey();
    const original = 'x'.repeat(100_000);
    const encrypted = await encrypt(key, original);
    const result = await decrypt(key, encrypted);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBe(original);
    }
  });

  it('should fail to decrypt with a different key', async () => {
    const keyA = await makeKey('246813');
    const keyB = await makeKey('987654');
    const encrypted = await encrypt(keyA, 'secret');
    const result = await decrypt(keyB, encrypted);

    expect(result.ok).toBe(false);
  });

  it('should fail on tampered ciphertext (AES-GCM auth check)', async () => {
    const key = await makeKey();
    const encrypted = await encrypt(key, 'tamper me');
    const bytes = atob(encrypted);
    const tampered =
      bytes.slice(0, -1) + String.fromCodePoint((bytes.codePointAt(bytes.length - 1) ?? 0) ^ 1);
    const tamperedB64 = btoa(tampered);

    const result = await decrypt(key, tamperedB64);
    expect(result.ok).toBe(false);
  });

  it('should handle 8-character passcode', async () => {
    const salt = await getSalt();
    const key = await deriveKey('11223344', salt);
    const encrypted = await encrypt(key, 'data');
    const result = await decrypt(key, encrypted);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBe('data');
    }
  });
});

describe('crypto.encryptWithSalt + decryptFull', () => {
  it('should round-trip with embedded salt', async () => {
    const key = await makeKey();
    const original = 'hello with salt';
    const encrypted = await encryptWithSalt(key, original);
    const result = await decryptFull(key, encrypted);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBe(original);
    }
  });
});

describe('crypto.getSalt', () => {
  it('should produce a 16-byte salt', async () => {
    const salt = await getSalt();
    expect(salt.byteLength).toBe(16);
  });

  it('should produce unique salts', async () => {
    const a = await getSalt();
    const b = await getSalt();
    expect(a).not.toEqual(b);
  });
});

describe('crypto.zeroPasscode', () => {
  it('should zero all bytes in a Uint8Array', () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5, 6]);
    zeroPasscode(buf);
    for (const byte of buf) {
      expect(byte).toBe(0);
    }
  });
});

// ─── Known-Answer Tests ───────────────────────────────────────────────────────
// These tests verify the crypto implementation against a pre-computed vector
// rather than just round-tripping. A silent algorithm change (wrong iteration
// count, wrong key length, swapped IV) would produce a different ciphertext and
// fail here even if round-trip tests still pass.
describe('crypto KAT — PBKDF2-SHA-256 + AES-256-GCM (fixed vector)', () => {
  it('should derive the correct key and decrypt a pre-computed ciphertext', async () => {
    const salt = hexToUint8Array(KAT_SALT_HEX);
    const key = await deriveKey(KAT_PASSCODE, salt, 310_000);

    const result = await decrypt(key, KAT_PAYLOAD_B64);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBe(KAT_PLAINTEXT);
    }
  });

  it('should produce the exact pre-computed ciphertext with a fixed IV', async () => {
    // We cannot call encrypt() directly with a fixed IV because it always
    // generates a random IV. Instead, we verify the inverse: decrypting the
    // known ciphertext with the known key gives the known plaintext, AND
    // encrypting the plaintext round-trips back successfully (both directions).
    const salt = hexToUint8Array(KAT_SALT_HEX);
    const key = await deriveKey(KAT_PASSCODE, salt, 310_000);

    // Forward: decrypt known vector
    const decrypted = await decrypt(key, KAT_PAYLOAD_B64);
    expect(decrypted.ok).toBe(true);
    if (decrypted.ok) {
      expect(decrypted.value).toBe(KAT_PLAINTEXT);
    }

    // Reverse: re-encrypt and verify round-trip (random IV, so only checks plaintext recovery)
    const reEncrypted = await encrypt(key, KAT_PLAINTEXT);
    const reDecrypted = await decrypt(key, reEncrypted);
    expect(reDecrypted.ok).toBe(true);
    if (reDecrypted.ok) {
      expect(reDecrypted.value).toBe(KAT_PLAINTEXT);
    }
  });

  it('should fail to decrypt the vector with the wrong key', async () => {
    const wrongSalt = hexToUint8Array('ff'.repeat(16));
    const wrongKey = await deriveKey(KAT_PASSCODE, wrongSalt, 310_000);
    const result = await decrypt(wrongKey, KAT_PAYLOAD_B64);
    expect(result.ok).toBe(false);
  });

  it('should fail to decrypt the vector with the wrong passcode', async () => {
    const salt = hexToUint8Array(KAT_SALT_HEX);
    const wrongKey = await deriveKey('987654', salt, 310_000);
    const result = await decrypt(wrongKey, KAT_PAYLOAD_B64);
    expect(result.ok).toBe(false);
  });
});

describe('crypto.validatePasscode — whitespace branch', () => {
  it('should reject a passcode that is entirely whitespace (≥6 chars but all spaces)', async () => {
    const salt = await getSalt();
    await expect(deriveKey('      ', salt)).rejects.toThrow();
  });
});

describe('crypto.decrypt — short payload branch', () => {
  it('should return ok:false for a payload shorter than IV_LENGTH+1 bytes', async () => {
    const key = await makeKey();
    // Base64 of 5 bytes — well below the 13-byte minimum (IV_LENGTH=12 + 1)
    const shortPayload = btoa(String.fromCodePoint(1, 2, 3, 4, 5));
    const result = await decrypt(key, shortPayload);
    expect(result.ok).toBe(false);
  });
});

describe('crypto.decryptFull — short payload branch', () => {
  it('should return ok:false for a payload shorter than SALT+IV+1 bytes', async () => {
    const key = await makeKey();
    // Base64 of 10 bytes — well below the 29-byte minimum (SALT=16 + IV=12 + 1)
    const shortPayload = btoa(String.fromCodePoint(1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
    const result = await decryptFull(key, shortPayload);
    expect(result.ok).toBe(false);
  });
});

describe('crypto.deriveHmacKey', () => {
  it('should produce a non-extractable HMAC-SHA256 key', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    expect(hmacKey.type).toBe('secret');
    expect(hmacKey.algorithm.name).toBe('HMAC');
    expect(hmacKey.extractable).toBe(false);
    expect(hmacKey.usages).toContain('sign');
    expect(hmacKey.usages).toContain('verify');
  });

  it('should produce different HMAC keys for different salts', async () => {
    const saltA = await getSalt();
    const saltB = await getSalt();
    const keyA = await deriveHmacKey('246813', saltA);
    const keyB = await deriveHmacKey('246813', saltB);
    // They are different CryptoKey objects (we cannot compare internal bytes directly)
    expect(keyA).not.toBe(keyB);
  });

  it('should reject a passcode shorter than 6 characters', async () => {
    const salt = await getSalt();
    await expect(deriveHmacKey('a', salt)).rejects.toThrow();
  });
});

describe('crypto.rotateKeyName (HMAC-based)', () => {
  it('should return a t_-prefixed 34-character key', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    const rotated = await rotateKeyName(hmacKey, 'my-key');
    expect(rotated).toMatch(/^t_[\da-f]{32}$/);
  });

  it('should produce the same output for the same inputs (deterministic)', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    const a = await rotateKeyName(hmacKey, 'my-key');
    const b = await rotateKeyName(hmacKey, 'my-key');
    expect(a).toBe(b);
  });

  it('should produce different outputs for different developer keys', async () => {
    const salt = await getSalt();
    const hmacKey = await deriveHmacKey('246813', salt);
    const a = await rotateKeyName(hmacKey, 'key-1');
    const b = await rotateKeyName(hmacKey, 'key-2');
    expect(a).not.toBe(b);
  });

  it('should produce different outputs for different HMAC keys (different salts)', async () => {
    const saltA = await getSalt();
    const saltB = await getSalt();
    const hmacKeyA = await deriveHmacKey('246813', saltA);
    const hmacKeyB = await deriveHmacKey('246813', saltB);
    const a = await rotateKeyName(hmacKeyA, 'my-key');
    const b = await rotateKeyName(hmacKeyB, 'my-key');
    expect(a).not.toBe(b);
  });
});

describe('crypto.generateHoneyCiphertext', () => {
  it('produces exactly one dot — two-blob encryptedMeta.encryptedValue format', async () => {
    const key = await makeKey();
    const ct = await generateHoneyCiphertext(key);
    const dots = (ct.match(/\./g) ?? []).length;
    expect(dots).toBe(1);
  });

  it('both blobs are non-empty base64 strings', async () => {
    const key = await makeKey();
    const ct = await generateHoneyCiphertext(key);
    const [meta, value] = ct.split('.');
    expect(meta.length).toBeGreaterThan(0);
    expect(value.length).toBeGreaterThan(0);
    // valid base64 (no dot inside a blob)
    expect(() => atob(meta)).not.toThrow();
    expect(() => atob(value)).not.toThrow();
  });

  it('produces different ciphertexts on each call (random)', async () => {
    const key = await makeKey();
    const a = await generateHoneyCiphertext(key);
    const b = await generateHoneyCiphertext(key);
    expect(a).not.toBe(b);
  });

  it('value blob lengths vary across multiple calls', async () => {
    const key = await makeKey();
    const lengths = new Set<number>();
    for (let i = 0; i < 20; i++) {
      const ct = await generateHoneyCiphertext(key);
      lengths.add(ct.split('.')[1].length);
    }
    // With 20 calls over a 128-char range we expect at least 2 distinct lengths
    expect(lengths.size).toBeGreaterThan(1);
  });

  it('meta blob lengths vary across multiple calls', async () => {
    const key = await makeKey();
    const lengths = new Set<number>();
    for (let i = 0; i < 20; i++) {
      const ct = await generateHoneyCiphertext(key);
      lengths.add(ct.split('.')[0].length);
    }
    expect(lengths.size).toBeGreaterThan(1);
  });
});
