import { TesseraError, TesseraErrorCode, type Result } from '../types';

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const MIN_ITERATIONS = 310_000;
const KEY_LENGTH = 256;

function assertBrowserEnvironment(): void {
  // Check for Web Crypto subtle API directly rather than `window`, so tessera
  // works in Cloudflare Workers, Deno, and Bun where `window` is undefined
  // but `globalThis.crypto.subtle` is available and fully functional.
  if (globalThis.crypto?.subtle === undefined) {
    throw new TesseraError(
      TesseraErrorCode.UNSUPPORTED_ENV,
      'tessera requires an environment with the Web Crypto API (crypto.subtle). ' +
        'In SSR frameworks (Next.js, Nuxt, SvelteKit), use tessera only ' +
        'in client-side code ("use client", .client.ts, onMounted, etc.).',
    );
  }
}

function validatePasscode(passcode: string): void {
  if (passcode.length < 6) {
    throw new TesseraError(
      TesseraErrorCode.INVALID_PASSCODE,
      'Passcode must be at least 6 characters.',
    );
  }
  if (passcode.trim().length === 0) {
    throw new TesseraError(
      TesseraErrorCode.INVALID_PASSCODE,
      'Passcode must not be entirely whitespace.',
    );
  }
}

function concatBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCodePoint(byte);
  }
  return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    // eslint-disable-next-line security/detect-object-injection
    bytes[i] = binary.codePointAt(i)!;
  }
  return bytes;
}

/**
 * Generates a 128-bit cryptographically random salt using `crypto.getRandomValues`.
 *
 * @returns A 16-byte `Uint8Array` unique salt.
 * @throws {TesseraError} `UNSUPPORTED_ENV` if `crypto.subtle` is unavailable.
 *
 * @security Each stored value receives a unique salt, preventing rainbow-table
 *   attacks even when two users share the same passcode (T5).
 */
export async function getSalt(): Promise<Uint8Array> {
  assertBrowserEnvironment();
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

/**
 * Synchronous variant of {@link getSalt} — skips the browser environment check.
 * Intended for use in test helpers and non-`async` setup code only.
 *
 * @returns A 16-byte `Uint8Array` unique salt.
 * @internal
 */
export function unsecuredGetSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

function getIv(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
}

async function importKey(keyBuffer: BufferSource): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', keyBuffer, { name: 'PBKDF2' }, false, ['deriveKey']);
}

async function deriveAesKey(
  passwordKey: CryptoKey,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Derives a non-extractable AES-256-GCM `CryptoKey` from a user passcode
 * using PBKDF2-SHA-256 with a cryptographically random salt.
 *
 * @param passcode   - User-supplied passcode (minimum 6 characters).
 * @param salt       - 128-bit random salt, unique per stored value.
 *   Generate with {@link getSalt}.
 * @param iterations - PBKDF2 iteration count. Must be ≥ 310 000 (OWASP 2024).
 * @returns A non-extractable `CryptoKey` for AES-GCM encryption/decryption.
 * @throws {TesseraError} `UNSUPPORTED_ENV` if `crypto.subtle` is unavailable.
 * @throws {TesseraError} `INVALID_PASSCODE` if passcode is shorter than 6 characters.
 * @throws {TesseraError} `DECRYPT_FAILED` if `iterations` is below the minimum.
 *
 * @security
 *   - `extractable: false` — the raw key bytes can never leave the Web Crypto
 *     engine, preventing serialisation or exfiltration (T7).
 *   - High iteration count slows offline brute-force to ~1 s/attempt (T5).
 *
 * @example
 * ```ts
 * const salt = await getSalt();
 * const key = await deriveKey('246813', salt, 310_000);
 * ```
 */
export async function deriveKey(
  passcode: string,
  salt: Uint8Array,
  iterations: number = MIN_ITERATIONS,
): Promise<CryptoKey> {
  assertBrowserEnvironment();
  validatePasscode(passcode);

  if (iterations < MIN_ITERATIONS) {
    throw new TesseraError(
      TesseraErrorCode.DECRYPT_FAILED,
      `PBKDF2 iterations must be at least ${MIN_ITERATIONS} (OWASP 2024 minimum).`,
    );
  }

  // Pass the Uint8Array directly as BufferSource rather than .buffer to avoid
  // the risk of including padding bytes from an over-allocated ArrayBuffer.
  const encoded = new TextEncoder().encode(passcode);
  const passwordKey = await importKey(encoded);
  return deriveAesKey(passwordKey, salt, iterations);
}

/**
 * Encrypts a plaintext string with AES-256-GCM using a random IV.
 * Produces a base64-encoded payload of the form `iv(12) ‖ ciphertext ‖ tag(16)`.
 *
 * @param key       - A non-extractable AES-GCM `CryptoKey` from {@link deriveKey}.
 * @param plaintext - The string to encrypt.
 * @returns Base64-encoded `iv ‖ ciphertext ‖ auth-tag`.
 * @throws {TesseraError} `UNSUPPORTED_ENV` if `crypto.subtle` is unavailable.
 *
 * @see {@link encryptWithSalt} for the storage-adapter variant that embeds a
 *   per-value salt in the payload.
 */
export async function encrypt(key: CryptoKey, plaintext: string): Promise<string> {
  assertBrowserEnvironment();

  const iv = getIv();
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  const combined = concatBuffers(iv, new Uint8Array(ciphertext));
  return uint8ArrayToBase64(combined);
}

/**
 * Encrypts a plaintext string with AES-256-GCM, embedding a fresh 128-bit
 * salt in the payload for per-value uniqueness.
 *
 * Produces a base64-encoded payload of the form:
 * `salt(16) ‖ iv(12) ‖ ciphertext ‖ tag(16)`.
 *
 * This is the format used by all storage adapters. Use {@link decryptFull}
 * to decrypt payloads produced by this function.
 *
 * @param key       - A non-extractable AES-GCM `CryptoKey`.
 * @param plaintext - The string to encrypt.
 * @returns Base64-encoded `salt ‖ iv ‖ ciphertext ‖ auth-tag`.
 * @throws {TesseraError} `UNSUPPORTED_ENV` if `crypto.subtle` is unavailable.
 *
 * @security Per-value salt prevents rainbow-table attacks even when two
 *   values are encrypted with the same passcode (T5).
 */
export async function encryptWithSalt(key: CryptoKey, plaintext: string): Promise<string> {
  assertBrowserEnvironment();

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  const combined = concatBuffers(salt, concatBuffers(iv, new Uint8Array(ciphertext)));
  return uint8ArrayToBase64(combined);
}

/**
 * Decrypts a base64 payload produced by {@link encrypt} (`iv ‖ ct ‖ tag`).
 * Returns a typed `Result` rather than throwing so callers can handle decrypt
 * failures without a try/catch.
 *
 * @param key     - A non-extractable AES-GCM `CryptoKey`.
 * @param payload - Base64-encoded `iv(12) ‖ ciphertext ‖ tag(16)`.
 * @returns `{ ok: true, value: plaintext }` on success, or
 *   `{ ok: false, error: TesseraError }` on failure.
 *
 * @security AES-GCM authentication tag verification detects any byte-level
 *   tampering before decryption proceeds (T9).
 */
export async function decrypt(key: CryptoKey, payload: string): Promise<Result<string>> {
  assertBrowserEnvironment();

  try {
    const combined = base64ToUint8Array(payload);

    if (combined.length < IV_LENGTH + 1) {
      return {
        ok: false,
        error: new TesseraError(TesseraErrorCode.DECRYPT_FAILED, 'Invalid payload.'),
      };
    }

    const iv = combined.slice(0, IV_LENGTH);
    const ciphertext = combined.slice(IV_LENGTH);

    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);

    const plaintext = new TextDecoder().decode(decrypted);
    return { ok: true, value: plaintext };
  } catch (error) {
    return {
      ok: false,
      error: new TesseraError(TesseraErrorCode.DECRYPT_FAILED, 'Decryption failed.', error),
    };
  }
}

/**
 * Decrypts a base64 payload produced by {@link encryptWithSalt}
 * (`salt ‖ iv ‖ ct ‖ tag`). The embedded salt is discarded after parsing.
 *
 * @param key     - A non-extractable AES-GCM `CryptoKey`.
 * @param payload - Base64-encoded `salt(16) ‖ iv(12) ‖ ciphertext ‖ tag(16)`.
 * @returns `{ ok: true, value: plaintext }` on success, or
 *   `{ ok: false, error: TesseraError }` on failure.
 *
 * @security AES-GCM authentication tag verification detects any byte-level
 *   tampering before decryption proceeds (T9).
 */
export async function decryptFull(key: CryptoKey, payload: string): Promise<Result<string>> {
  assertBrowserEnvironment();

  try {
    const combined = base64ToUint8Array(payload);

    if (combined.length < SALT_LENGTH + IV_LENGTH + 1) {
      return {
        ok: false,
        error: new TesseraError(TesseraErrorCode.DECRYPT_FAILED, 'Invalid payload.'),
      };
    }

    const iv = combined.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const ciphertext = combined.slice(SALT_LENGTH + IV_LENGTH);

    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);

    const plaintext = new TextDecoder().decode(decrypted);
    return { ok: true, value: plaintext };
  } catch (error) {
    return {
      ok: false,
      error: new TesseraError(TesseraErrorCode.DECRYPT_FAILED, 'Decryption failed.', error),
    };
  }
}

/**
 * Overwrites every byte of a `Uint8Array` with zeros.
 * Call this immediately after a passcode buffer is no longer needed to
 * minimise the time that sensitive material lives in memory.
 *
 * @param passcode - The buffer to zero in-place.
 *
 * @security Reduces the window of passcode exposure to memory-reading attacks
 *   on the JS heap (T7).
 */
export function zeroPasscode(passcode: Uint8Array): void {
  for (let i = 0; i < passcode.length; i++) {
    // eslint-disable-next-line security/detect-object-injection
    passcode[i] = 0;
  }
}

function uint8ArrayToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Derives a non-extractable HMAC-SHA256 `CryptoKey` from a user passcode
 * using PBKDF2-SHA-256 with a domain-separated salt. Used for deterministic
 * key-name rotation via HMAC (replaces the unsafe fixed-IV AES-GCM approach).
 *
 * @param passcode   - User-supplied passcode (minimum 6 characters).
 * @param salt       - 128-bit random salt from the vault salt.
 * @param iterations - PBKDF2 iteration count. Must be ≥ 310 000.
 * @returns A non-extractable HMAC-SHA256 `CryptoKey`.
 * @internal Not exported in the public API.
 */
export async function deriveHmacKey(
  passcode: string,
  salt: Uint8Array,
  iterations: number = MIN_ITERATIONS,
): Promise<CryptoKey> {
  assertBrowserEnvironment();
  validatePasscode(passcode);

  // Domain-separate the salt by appending 'keynames' as UTF-8.
  const suffix = new TextEncoder().encode('keynames');
  const domainSalt = concatBuffers(salt, suffix);

  const encoded = new TextEncoder().encode(passcode);
  const passwordKey = await importKey(encoded);

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: domainSalt,
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

/**
 * Produces a deterministic, opaque storage key by HMAC-SHA256-signing
 * `'keyname:' + developerKey` with the provided HMAC key.
 * Takes the first 32 hex chars of the 64-hex HMAC output → `t_<32hex>`.
 *
 * @param hmacKey      - Non-extractable HMAC-SHA256 key from {@link deriveHmacKey}.
 * @param developerKey - The raw developer-facing key name.
 * @returns A `t_`-prefixed 34-character opaque storage key.
 */
export async function rotateKeyName(hmacKey: CryptoKey, developerKey: string): Promise<string> {
  const data = new TextEncoder().encode(`keyname:${developerKey}`);
  const signature = await crypto.subtle.sign('HMAC', hmacKey, data);
  const hex = uint8ArrayToHex(new Uint8Array(signature));
  return `t_${hex.slice(0, 32)}`;
}

export async function generateHoneyCiphertext(key: CryptoKey): Promise<string> {
  const noise = crypto.getRandomValues(new Uint8Array(32));
  const fakePlaintext = uint8ArrayToHex(noise);
  return encryptWithSalt(key, fakePlaintext);
}
