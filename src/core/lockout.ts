import { TesseraError, TesseraErrorCode } from '../types';

// Storage keys are computed per vault. 'default' maps to the legacy key
// names so existing apps are unaffected.
function lockoutKey(vaultId = 'default'): string {
  return vaultId === 'default' ? 'tessera_lockout' : `tessera_${vaultId}_lockout`;
}

function lockoutSigKey(vaultId = 'default'): string {
  return vaultId === 'default' ? 'tessera_lockout_sig' : `tessera_${vaultId}_lockout_sig`;
}

const MAX_ATTEMPTS = 5;
const BACKOFF_MULTIPLIER = 2;

interface LockoutRecord {
  attempts: number;
  lockedUntil: number | null;
  backoffMs: number;
}

function readRecord(vaultId = 'default'): LockoutRecord {
  try {
    const stored = localStorage.getItem(lockoutKey(vaultId));
    if (stored === null) {
      return { attempts: 0, lockedUntil: null, backoffMs: 1000 };
    }
    return JSON.parse(stored) as LockoutRecord;
  } catch {
    return { attempts: 0, lockedUntil: null, backoffMs: 1000 };
  }
}

function writeRecord(record: LockoutRecord, vaultId = 'default'): void {
  try {
    localStorage.setItem(lockoutKey(vaultId), JSON.stringify(record));
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
export async function signLockoutRecord(hmacKey: CryptoKey, vaultId = 'default'): Promise<void> {
  const record = readRecord(vaultId);
  const data = new TextEncoder().encode(JSON.stringify(record));
  const signature = await crypto.subtle.sign('HMAC', hmacKey, data);
  const sigHex = uint8ArrayToHex(new Uint8Array(signature));
  try {
    localStorage.setItem(lockoutSigKey(vaultId), sigHex);
  } catch {
    // Best-effort — storage may be unavailable.
  }
}

/**
 * Verifies the HMAC signature of the lockout record.
 * Returns `true` if the record is intact (or no prior signature exists),
 * `false` if the record was tampered.
 */
export async function verifyLockoutRecord(
  hmacKey: CryptoKey,
  vaultId = 'default',
): Promise<boolean> {
  let sigHex: string | null = null;
  try {
    sigHex = localStorage.getItem(lockoutSigKey(vaultId));
  } catch {
    // Storage unavailable — treat as no prior signature.
  }

  if (sigHex === null) return true;

  const record = readRecord(vaultId);
  const data = new TextEncoder().encode(JSON.stringify(record));
  try {
    const sigBytes = hexToBytes(sigHex);
    const valid = await crypto.subtle.verify('HMAC', hmacKey, sigBytes, data);
    return valid;
  } catch {
    return false;
  }
}

/**
 * Records a failed `Tessera.unlock()` attempt and, when the threshold is
 * reached, sets a lockout window with exponential backoff.
 *
 * @param maxAttempts     - Maximum attempts before lockout fires.
 * @param initialBackoffMs - The starting backoff delay in milliseconds for
 *   the first lockout cycle. Defaults to 1 000 ms. Subsequent cycles double
 *   from whatever value was stored in the previous cycle.
 *
 * @security Mitigates T8 (on-device brute force).
 */
export function recordFailedAttempt(
  maxAttempts: number = MAX_ATTEMPTS,
  initialBackoffMs = 1000,
  vaultId = 'default',
): void {
  const record = readRecord(vaultId);

  if (record.attempts === 0 && record.backoffMs === 1000 && initialBackoffMs !== 1000) {
    record.backoffMs = initialBackoffMs;
  }

  record.attempts += 1;

  if (record.attempts >= maxAttempts) {
    record.lockedUntil = Date.now() + record.backoffMs;
    record.backoffMs *= BACKOFF_MULTIPLIER;
  }

  writeRecord(record, vaultId);
}

/**
 * Throws `LOCKOUT` if the account is currently within a backoff window.
 * Automatically clears an expired lockout record so the user can retry.
 *
 * @param _maxAttempts - Reserved for future use; currently unused because
 *   the lockout window is determined by `recordFailedAttempt`.
 * @throws {TesseraError} `LOCKOUT` while a backoff window is active.
 */
export function checkLockout(_maxAttempts: number = MAX_ATTEMPTS, vaultId = 'default'): void {
  const record = readRecord(vaultId);

  if (record.lockedUntil !== null && Date.now() < record.lockedUntil) {
    const remaining = record.lockedUntil - Date.now();
    throw new TesseraError(
      TesseraErrorCode.LOCKOUT,
      `Too many failed attempts. Try again in ${Math.ceil(remaining / 1000)} seconds.`,
    );
  }

  if (record.lockedUntil !== null && Date.now() >= record.lockedUntil) {
    writeRecord({ attempts: 0, lockedUntil: null, backoffMs: record.backoffMs }, vaultId);
  }
}

/**
 * Resets the lockout counter and clears any active backoff window.
 * Called by `Tessera.unlock()` after a successful unlock.
 */
export function resetLockout(vaultId = 'default'): void {
  writeRecord({ attempts: 0, lockedUntil: null, backoffMs: 1000 }, vaultId);
}

/**
 * Returns the number of unlock attempts remaining before lockout fires.
 *
 * @param maxAttempts - The configured lockout threshold.
 * @returns A non-negative integer; `0` means the lockout threshold is reached.
 */
export function getRemainingAttempts(
  maxAttempts: number = MAX_ATTEMPTS,
  vaultId = 'default',
): number {
  const record = readRecord(vaultId);
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
export function performWipe(vaultId = 'default'): void {
  // Wipe localStorage and sessionStorage but preserve the lockout record so
  // that repeated attempts after a wipe are still blocked.
  try {
    const key = lockoutKey(vaultId);
    const sigKey = lockoutSigKey(vaultId);
    const lockoutRecord = localStorage.getItem(key);
    const lockoutSig = localStorage.getItem(sigKey);
    localStorage.clear();
    sessionStorage.clear();
    if (lockoutRecord !== null) {
      localStorage.setItem(key, lockoutRecord);
    }
    if (lockoutSig !== null) {
      localStorage.setItem(sigKey, lockoutSig);
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

  // Delete the vault's IndexedDB database.
  const dbName = vaultId === 'default' ? 'tessera_vault' : `tessera_vault_${vaultId}`;
  try {
    indexedDB.deleteDatabase(dbName);
  } catch {
    // Best-effort — IndexedDB may be unavailable.
  }
}
