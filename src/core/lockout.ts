import { TesseraError, TesseraErrorCode } from '../types';

const STORAGE_KEY = 'tessera_lockout';
const SIG_STORAGE_KEY = 'tessera_lockout_sig';
const MAX_ATTEMPTS = 5;
const BACKOFF_MULTIPLIER = 2;

interface LockoutRecord {
  attempts: number;
  lockedUntil: number | null;
  backoffMs: number;
}

function readRecord(): LockoutRecord {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === null) {
      return { attempts: 0, lockedUntil: null, backoffMs: 1000 };
    }
    return JSON.parse(stored) as LockoutRecord;
  } catch {
    return { attempts: 0, lockedUntil: null, backoffMs: 1000 };
  }
}

function writeRecord(record: LockoutRecord): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
  } catch {
    // Storage quota may be exceeded; swallow.
  }
}

function uint8ArrayToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Signs the current lockout record with the HMAC key and stores the hex
 * signature as `tessera_lockout_sig`. Called after a successful unlock.
 */
export async function signLockoutRecord(hmacKey: CryptoKey): Promise<void> {
  const record = readRecord();
  const data = new TextEncoder().encode(JSON.stringify(record));
  const signature = await crypto.subtle.sign('HMAC', hmacKey, data);
  const sigHex = uint8ArrayToHex(new Uint8Array(signature));
  try {
    localStorage.setItem(SIG_STORAGE_KEY, sigHex);
  } catch {
    // Best-effort — storage may be unavailable.
  }
}

/**
 * Verifies the HMAC signature of the lockout record.
 * Returns `true` if the record is intact (or no prior signature exists),
 * `false` if the record was tampered.
 */
export async function verifyLockoutRecord(hmacKey: CryptoKey): Promise<boolean> {
  let sigHex: string | null = null;
  try {
    sigHex = localStorage.getItem(SIG_STORAGE_KEY);
  } catch {
    // Storage unavailable — treat as no prior signature.
  }

  // No prior signature means this is the first unlock (or storage was cleared legitimately).
  if (sigHex === null) return true;

  const record = readRecord();
  const data = new TextEncoder().encode(JSON.stringify(record));
  try {
    const sigBytes = hexToBytes(sigHex);
    const valid = await crypto.subtle.verify('HMAC', hmacKey, sigBytes, data);
    return valid;
  } catch {
    // Malformed signature — treat as tampered.
    return false;
  }
}

/**
 * Records a failed `Tessera.unlock()` attempt and, when the threshold is
 * reached, sets a lockout window with exponential backoff.
 *
 * @param maxAttempts - Maximum attempts before lockout fires.
 *
 * @security Mitigates T8 (on-device brute force).
 */
export function recordFailedAttempt(maxAttempts: number = MAX_ATTEMPTS): void {
  const record = readRecord();
  record.attempts += 1;

  if (record.attempts >= maxAttempts) {
    record.lockedUntil = Date.now() + record.backoffMs;
    record.backoffMs *= BACKOFF_MULTIPLIER;
  }

  writeRecord(record);
}

/**
 * Throws `LOCKOUT` if the account is currently within a backoff window.
 * Automatically clears an expired lockout record so the user can retry.
 *
 * @param _maxAttempts - Reserved for future use; currently unused because
 *   the lockout window is determined by `recordFailedAttempt`.
 * @throws {TesseraError} `LOCKOUT` while a backoff window is active.
 */
export function checkLockout(_maxAttempts: number = MAX_ATTEMPTS): void {
  const record = readRecord();

  if (record.lockedUntil !== null && Date.now() < record.lockedUntil) {
    const remaining = record.lockedUntil - Date.now();
    throw new TesseraError(
      TesseraErrorCode.LOCKOUT,
      `Too many failed attempts. Try again in ${Math.ceil(remaining / 1000)} seconds.`,
    );
  }

  if (record.lockedUntil !== null && Date.now() >= record.lockedUntil) {
    writeRecord({ attempts: 0, lockedUntil: null, backoffMs: record.backoffMs });
  }
}

/**
 * Resets the lockout counter and clears any active backoff window.
 * Called by `Tessera.unlock()` after a successful unlock.
 */
export function resetLockout(): void {
  writeRecord({ attempts: 0, lockedUntil: null, backoffMs: 1000 });
}

/**
 * Returns the number of unlock attempts remaining before lockout fires.
 *
 * @param maxAttempts - The configured lockout threshold.
 * @returns A non-negative integer; `0` means the lockout threshold is reached.
 */
export function getRemainingAttempts(maxAttempts: number = MAX_ATTEMPTS): number {
  const record = readRecord();
  return Math.max(0, maxAttempts - record.attempts);
}

/**
 * Best-effort wipe of all browser storage. Called when `lockoutAction: 'wipe'`
 * fires. Preserves the lockout record so subsequent attempts remain blocked.
 *
 * Clears: `localStorage`, `sessionStorage`, all cookies on the current path,
 * and the tessera IndexedDB database.
 *
 * @security Mitigates T8 — removes all encrypted vault data so an attacker
 *   cannot run an offline attack against the stored ciphertext.
 */
export function performWipe(): void {
  // Wipe localStorage and sessionStorage but preserve the lockout record so
  // that repeated attempts after a wipe are still blocked.
  try {
    const lockoutRecord = localStorage.getItem(STORAGE_KEY);
    localStorage.clear();
    sessionStorage.clear();
    if (lockoutRecord !== null) {
      localStorage.setItem(STORAGE_KEY, lockoutRecord);
    }
  } catch {
    // Best-effort — storage may be unavailable.
  }

  // Expire all cookies on the current path.
  try {
    for (const cookie of document.cookie.split('; ')) {
      const name = cookie.split('=')[0];
      if (name) {
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
      }
    }
  } catch {
    // Best-effort — document may be unavailable (e.g. non-browser context).
  }

  // Delete the tessera IndexedDB database.
  try {
    indexedDB.deleteDatabase('tessera_vault');
  } catch {
    // Best-effort — IndexedDB may be unavailable.
  }
}
