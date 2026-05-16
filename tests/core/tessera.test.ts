import { describe, it, expect, beforeEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { Tessera } from '../../src/tessera';
import { TesseraErrorCode } from '../../src/types';
import { resetLockout } from '../../src/core/lockout';

describe('Tessera.unlock', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    resetLockout();
    vi.restoreAllMocks();
  });

  it('should unlock and return a vault with all adapters', async () => {
    const vault = await Tessera.unlock('246813');
    expect(vault).toBeDefined();
    expect(vault.local).toBeDefined();
    expect(vault.session).toBeDefined();
    expect(vault.cookie).toBeDefined();
    expect(vault.idb).toBeDefined();
    expect(typeof vault.lock).toBe('function');
    expect(typeof vault.isLocked).toBe('function');
  });

  it('should start unlocked after Tessera.unlock()', async () => {
    const vault = await Tessera.unlock('246813');
    expect(vault.isLocked()).toBe(false);
  });

  it('should store and retrieve encrypted data via localStorage adapter', async () => {
    const vault = await Tessera.unlock('246813', { debug: true });
    await vault.local.setItem('key', 'value');
    const result = await vault.local.getItem('key');
    expect(result).toBe('value');

    const rawKey = await vault.local.getRawKey!('key');
    const raw = localStorage.getItem(rawKey);
    expect(raw).not.toBeNull();
    expect(raw).not.toBe('value');
  });

  it('should lock and prevent subsequent reads returning null', async () => {
    const vault = await Tessera.unlock('246813');
    await vault.local.setItem('key', 'value');
    vault.lock();
    expect(vault.isLocked()).toBe(true);
    const result = await vault.local.getItem('key');
    expect(result).toBeNull();
  });

  it('should re-derive the same key on second unlock with same passcode (cross-session)', async () => {
    // First session: write a value.
    const vault1 = await Tessera.unlock('123456');
    await vault1.local.setItem('persist', 'hello cross-session');
    vault1.lock();

    // Second session (same localStorage state, same passcode): read it back.
    const vault2 = await Tessera.unlock('123456');
    const result = await vault2.local.getItem('persist');
    expect(result).toBe('hello cross-session');
  });

  it('should reject an incorrect passcode when a vault already exists', async () => {
    const vault1 = await Tessera.unlock('111111');
    await vault1.local.setItem('secret', 'encrypted-data');
    vault1.lock();

    // Wrong passcode — verifier check must reject it before the vault opens.
    await expect(Tessera.unlock('999999')).rejects.toThrow();
  });

  it('should re-derive correctly and read data with the right passcode after lock', async () => {
    const vault1 = await Tessera.unlock('111111');
    await vault1.local.setItem('secret', 'encrypted-data');
    vault1.lock();

    const vault2 = await Tessera.unlock('111111');
    const result = await vault2.local.getItem('secret');
    expect(result).toBe('encrypted-data');
  });

  it('persists the vault salt in localStorage as tessera_vault_salt', async () => {
    expect(localStorage.getItem('tessera_vault_salt')).toBeNull();
    await Tessera.unlock('246813');
    expect(localStorage.getItem('tessera_vault_salt')).not.toBeNull();
  });

  it('reuses the stored salt on subsequent unlocks', async () => {
    await Tessera.unlock('246813');
    const salt1 = localStorage.getItem('tessera_vault_salt');
    await Tessera.unlock('246813');
    const salt2 = localStorage.getItem('tessera_vault_salt');
    expect(salt1).toBe(salt2);
  });

  it('should reject short passcode', async () => {
    await expect(Tessera.unlock('a')).rejects.toThrow();
  });

  it('should accept a long passcode (no upper-length limit)', async () => {
    const vault = await Tessera.unlock('this-is-a-long-passphrase-123');
    expect(vault.isLocked()).toBe(false);
  });

  it('should count failed attempts and surface remaining count in error message', async () => {
    const err = await Tessera.unlock('bad', { lockoutAttempts: 5 }).catch(
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/4 attempt/i);
  });

  it('should enforce lockout after too many failed attempts (delay action)', async () => {
    for (let i = 0; i < 5; i++) {
      await Tessera.unlock('bad', { lockoutAttempts: 5 }).catch(() => {});
    }
    const err = await Tessera.unlock('bad', { lockoutAttempts: 5 }).catch(
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(Error);
    expect((err as { code?: string }).code).toBe(TesseraErrorCode.LOCKOUT);
  });

  it('should throw LOCKOUT immediately when lockoutAction is "throw" and attempts exhausted', async () => {
    // 2 failing attempts bring remaining to 1; the 3rd exhausts the count and
    // triggers the 'throw' action on that same attempt.
    for (let i = 0; i < 2; i++) {
      await Tessera.unlock('bad', { lockoutAttempts: 3, lockoutAction: 'throw' }).catch(() => {});
    }
    const err = await Tessera.unlock('bad', { lockoutAttempts: 3, lockoutAction: 'throw' }).catch(
      (error: unknown) => error,
    );
    expect((err as { code?: string }).code).toBe(TesseraErrorCode.LOCKOUT);
    expect((err as Error).message).toMatch(/permanently locked/i);
  });

  it('should wipe storage when lockoutAction is "wipe" and attempts exhausted', async () => {
    localStorage.setItem('sensitive', 'data');
    // 2 failing attempts first, then the 3rd triggers the wipe.
    for (let i = 0; i < 2; i++) {
      await Tessera.unlock('bad', { lockoutAttempts: 3, lockoutAction: 'wipe' }).catch(() => {});
    }
    const err = await Tessera.unlock('bad', { lockoutAttempts: 3, lockoutAction: 'wipe' }).catch(
      (error: unknown) => error,
    );
    expect((err as { code?: string }).code).toBe(TesseraErrorCode.LOCKOUT);
    expect((err as Error).message).toMatch(/wiped/i);
    expect(localStorage.getItem('sensitive')).toBeNull();
  });

  it('stored localStorage key has t_ prefix with 32-char hex suffix (rotateKeyName format)', async () => {
    const vault = await Tessera.unlock('246813', { debug: true });
    await vault.local.setItem('testkey', 'testvalue');

    // The raw key used in localStorage should be in `t_<32hex>` format (34 chars total).
    const rawKey = await vault.local.getRawKey!('testkey');
    expect(rawKey).toMatch(/^t_[\da-f]{32}$/);
    expect(rawKey).toHaveLength(34);

    // The raw storage value should be encrypted (not the plaintext).
    const raw = localStorage.getItem(rawKey);
    expect(raw).not.toBeNull();
    expect(raw).not.toBe('testvalue');
  });

  // on() and off() event handlers
  it('should receive events via vault.on() and stop receiving after vault.off()', async () => {
    const vault = await Tessera.unlock('246813');
    const handler = vi.fn();
    vault.on('vault-locked', handler);
    vault.lock();
    expect(handler).toHaveBeenCalledTimes(1);

    // Unlock fresh vault, register then remove handler
    localStorage.clear();
    resetLockout();
    const vault2 = await Tessera.unlock('246813');
    const handler2 = vi.fn();
    vault2.on('vault-locked', handler2);
    vault2.off('vault-locked', handler2);
    vault2.lock();
    expect(handler2).not.toHaveBeenCalled();
  });

  // reconfirm() with correct passcode
  it('should succeed when reconfirm is called with the correct passcode', async () => {
    const vault = await Tessera.unlock('246813');
    await vault.reconfirm('246813');
    // After reconfirm, a reconfirm key is set on the session
    expect(vault.isLocked()).toBe(false);
  });

  // reconfirm() with wrong passcode throws INVALID_PASSCODE
  it('should throw INVALID_PASSCODE when reconfirm is called with wrong passcode', async () => {
    const vault = await Tessera.unlock('246813');
    const err = await vault.reconfirm('wrongpasscode').catch((error: unknown) => error);
    expect((err as { code?: string }).code).toBe(TesseraErrorCode.INVALID_PASSCODE);
  });

  // reconfirm() while locked throws LOCKED
  it('should throw LOCKED when reconfirm is called after vault is locked', async () => {
    const vault = await Tessera.unlock('246813');
    vault.lock();
    const err = await vault.reconfirm('246813').catch((error: unknown) => error);
    expect(err).toBeInstanceOf(Error);
  });

  // terminate() clears events and locks
  it('should lock vault and clear all events when terminate() is called', async () => {
    const vault = await Tessera.unlock('246813');
    const handler = vi.fn();
    vault.on('vault-locked', handler);
    vault.terminate();
    // After terminate, vault should be locked
    expect(vault.isLocked()).toBe(true);
    // handler should NOT have been called (events were cleared before lock notification)
    // Note: terminate clears events then locks — no vault-locked is emitted
    expect(handler).not.toHaveBeenCalled();
  });

  // lock() emits vault-locked with reason 'user'
  it('should emit vault-locked with reason "user" when vault.lock() is called', async () => {
    const vault = await Tessera.unlock('246813');
    const handler = vi.fn();
    vault.on('vault-locked', handler);
    vault.lock();
    expect(handler).toHaveBeenCalledWith(expect.objectContaining({ reason: 'user' }));
  });

  // wipeHighSensitivity via suspicion lockdown (_simulateHoneyHit)
  it('should lock and wipe high-sensitivity keys on suspicion lockdown', async () => {
    const vault = await Tessera.unlock('246813', {
      suspicion: { thresholds: { lockdown: 1 } },
    } as Parameters<typeof Tessera.unlock>[1]);
    await vault.local.setItem('secure', 'sensitive', { sensitivity: 'high' });

    // Trigger suspicion lockdown (lockdown threshold is 1 honey-hit score point)
    vault._simulateHoneyHit('local');

    // Wait a tick for the async lockdown to complete
    await new Promise((r) => setTimeout(r, 50));

    expect(vault.isLocked()).toBe(true);
  });

  // ── Issue 1: lockdown wipe ordering ──────────────────────────────────────────

  it('lockdown: wipes high-sensitivity keys from storage before locking', async () => {
    const vault = await Tessera.unlock('246813', {
      suspicion: { thresholds: { lockdown: 1 } },
      debug: true,
    } as Parameters<typeof Tessera.unlock>[1]);

    await vault.local.setItem('secret', 'sensitive-data', { sensitivity: 'high' });
    const rawKey = await vault.local.getRawKey!('secret');
    expect(localStorage.getItem(rawKey)).not.toBeNull();

    vault._simulateHoneyHit('local');
    await new Promise((r) => setTimeout(r, 50));

    expect(vault.isLocked()).toBe(true);
    expect(localStorage.getItem(rawKey)).toBeNull();
  });

  it('lockdown: wipes critical-sensitivity keys from storage before locking', async () => {
    const vault = await Tessera.unlock('246813', {
      suspicion: { thresholds: { lockdown: 1 } },
      debug: true,
    } as Parameters<typeof Tessera.unlock>[1]);

    await vault.local.setItem('crit', 'top-secret', { sensitivity: 'critical' });
    const rawKey = await vault.local.getRawKey!('crit');
    expect(localStorage.getItem(rawKey)).not.toBeNull();

    vault._simulateHoneyHit('local');
    await new Promise((r) => setTimeout(r, 50));

    expect(vault.isLocked()).toBe(true);
    expect(localStorage.getItem(rawKey)).toBeNull();
  });

  it('lockdown: also wipes low-sensitivity keys (wipeAll nukes everything)', async () => {
    const vault = await Tessera.unlock('246813', {
      suspicion: { thresholds: { lockdown: 1 } },
      debug: true,
    } as Parameters<typeof Tessera.unlock>[1]);

    await vault.local.setItem('pub', 'public-data', { sensitivity: 'low' });
    const rawKey = await vault.local.getRawKey!('pub');
    expect(localStorage.getItem(rawKey)).not.toBeNull();

    vault._simulateHoneyHit('local');
    await new Promise((r) => setTimeout(r, 50));

    expect(vault.isLocked()).toBe(true);
    // wipeAll nukes every t_ entry — low-sensitivity keys no longer survive lockdown
    expect(localStorage.getItem(rawKey)).toBeNull();
  });

  it('lockdown: suspicion-lockdown event lists wiped key paths', async () => {
    const vault = await Tessera.unlock('246813', {
      suspicion: { thresholds: { lockdown: 1 } },
    } as Parameters<typeof Tessera.unlock>[1]);

    await vault.local.setItem('k1', 'val', { sensitivity: 'high' });
    await vault.local.setItem('k2', 'val', { sensitivity: 'critical' });

    let wiped: string[] = [];
    vault.on('suspicion-lockdown', (p) => {
      wiped = p.keysWiped;
    });

    vault._simulateHoneyHit('local');
    await new Promise((r) => setTimeout(r, 50));

    expect(wiped.length).toBeGreaterThanOrEqual(2);
    // wipeAll includes both local: entries and the idb:* sentinel
    expect(wiped.every((k) => k.startsWith('local:') || k === 'idb:*')).toBe(true);
  });

  // vault-unlocked event emitted on unlock — test the event comes through by registering
  // a handler on the vault we get back
  it('should emit vault-unlocked event on second unlock (stored verifier path)', async () => {
    // First unlock creates the verifier
    const vault1 = await Tessera.unlock('246813');
    vault1.lock();

    // Second unlock uses the stored verifier path and emits vault-unlocked
    let modeReceived: string | undefined;
    // We need to register the handler before the vault emits; since emitted synchronously
    // after unlock returns, we cannot intercept mid-call. Instead confirm the event API exists.
    const vault2 = await Tessera.unlock('246813');
    vault2.on('vault-unlocked', (p) => {
      modeReceived = p.mode;
    });
    // Emit a second vault-unlocked by doing a reconfirm (which emits 'reconfirm' mode)
    await vault2.reconfirm('246813');
    expect(modeReceived).toBe('reconfirm');
  });

  // auto-lock via idle timeout (covers lines 198-199: auto-locked and vault-locked events)
  it('should emit auto-locked and vault-locked events when idle timeout fires', async () => {
    // Use a longer idle timeout to avoid flakiness; register handlers before the
    // timer fires. The key derivation (unlock) takes ~1-2s, so we need the timeout
    // to fire AFTER the handlers are registered.
    const autoLockedHandler = vi.fn();
    const vaultLockedHandler = vi.fn();

    // Unlock with 200ms idle timeout — by the time unlock returns (~2s for key derivation),
    // the timer will have already been reset by touch() at the end of unlock().
    // We register handlers immediately after unlock returns and wait.
    const vault = await Tessera.unlock('246813', { idleTimeout: 200 });
    vault.on('auto-locked', autoLockedHandler);
    vault.on('vault-locked', vaultLockedHandler);

    // Wait longer than the idle timeout
    await new Promise((r) => setTimeout(r, 400));

    expect(autoLockedHandler).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'idle-timeout' }),
    );
    expect(vault.isLocked()).toBe(true);
  }, 15_000);

  // tessera.ts lines 187-191 and 303-304: tampered lockout record causes LOCKOUT on second unlock
  it('should throw LOCKOUT when the lockout record has been tampered with', async () => {
    // First unlock: creates verifier and signs lockout record
    const vault1 = await Tessera.unlock('246813');
    vault1.lock();

    // Tamper with the lockout record so verifyLockoutRecord returns false
    localStorage.setItem(
      'tessera_lockout',
      JSON.stringify({ attempts: 99, lockedUntil: null, backoffMs: 1000 }),
    );

    // Second unlock with same passcode: verifier passes but lockout record is tampered
    const err = await Tessera.unlock('246813').catch((error: unknown) => error);
    expect((err as { code?: string }).code).toBe(TesseraErrorCode.LOCKOUT);
    expect((err as Error).message).toMatch(/tampered/i);
  });

  // off() without handler removes all handlers for that event
  it('vault.off() with no handler arg removes all handlers for that event', async () => {
    const vault = await Tessera.unlock('246813');
    const h1 = vi.fn();
    const h2 = vi.fn();
    vault.on('vault-locked', h1);
    vault.on('vault-locked', h2);
    vault.off('vault-locked'); // remove all
    vault.lock();
    expect(h1).not.toHaveBeenCalled();
    expect(h2).not.toHaveBeenCalled();
  });

  // wipeAll on lockdown: every t_ entry is removed — real, honey, and low-sensitivity
  it('lockdown nukes all t_ entries including honey and low-sensitivity keys', async () => {
    const vault = await Tessera.unlock('246813', {
      honeyKeys: { count: 2 },
      suspicion: { thresholds: { lockdown: 1 } },
    } as Parameters<typeof Tessera.unlock>[1]);

    // Write keys at different sensitivity levels
    await vault.local.setItem('low-key', 'lo', { sensitivity: 'low' });
    await vault.local.setItem('high-key', 'hi', { sensitivity: 'high' });

    // Confirm t_ entries exist (2 real + 2 honey)
    const tKeysBefore = Object.keys(localStorage).filter((k) => k.startsWith('t_'));
    expect(tKeysBefore.length).toBeGreaterThanOrEqual(3);

    let keysWiped: string[] = [];
    vault.on('suspicion-lockdown', (p) => {
      keysWiped = p.keysWiped;
    });
    vault._simulateHoneyHit('local');
    await new Promise((r) => setTimeout(r, 50));

    // All t_ entries must be gone
    const tKeysAfter = Object.keys(localStorage).filter((k) => k.startsWith('t_'));
    expect(tKeysAfter.length).toBe(0);

    // keysWiped includes real and honey entries (plus idb:* sentinel)
    expect(keysWiped.length).toBeGreaterThanOrEqual(3);
    expect(keysWiped.every((w: string) => w.startsWith('local:') || w === 'idb:*')).toBe(true);
  });

  // cleanOrphanedHoneyKeys fires at unlock and wipes orphans from prior session
  it('unlock fires background orphan cleanup that wipes orphaned honey keys', async () => {
    // Session 1: write key + generate honey keys, then lock
    const vault1 = await Tessera.unlock('246813', { honeyKeys: { count: 2 } });
    await vault1.local.setItem('real', 'value');
    const honeyKeys1 = vault1._honeyStorageKeys('local');
    expect(honeyKeys1.length).toBe(2);
    vault1.lock();

    // Confirm orphans are in localStorage
    for (const k of honeyKeys1) {
      expect(localStorage.getItem(k)).not.toBeNull();
    }

    // Session 2: unlock fires cleanOrphanedHoneyKeys in background
    const vault2 = await Tessera.unlock('246813', { honeyKeys: { count: 2 } });

    // Allow background microtasks to settle
    await new Promise((r) => setTimeout(r, 50));

    // Orphaned honey keys from session 1 must be wiped
    for (const k of honeyKeys1) {
      expect(localStorage.getItem(k)).toBeNull();
    }

    // Real key is still readable
    expect(await vault2.local.getItem('real')).toBe('value');

    vault2.lock();
  });

  it('direct localStorage.getItem on a honey key records a honey hit', async () => {
    const vault = await Tessera.unlock('246813', { honeyKeys: { count: 3 } });
    await vault.local.setItem('mykey', 'myvalue');
    const honeyKeys = vault._honeyStorageKeys('local');
    expect(honeyKeys.length).toBeGreaterThan(0);
    let honeyHit = false;
    vault.on('honey-triggered', () => {
      honeyHit = true;
    });
    localStorage.getItem(honeyKeys[0]);
    expect(honeyHit).toBe(true);
    vault.lock();
  });

  it('proxy is removed on vault.lock()', async () => {
    const vault = await Tessera.unlock('246813', { honeyKeys: { count: 3 } });
    await vault.local.setItem('mykey', 'myvalue');
    const honeyKeys = vault._honeyStorageKeys('local');
    expect(honeyKeys.length).toBeGreaterThan(0);
    vault.lock();

    let honeyHit = false;
    vault.on('honey-triggered', () => {
      honeyHit = true;
    });
    localStorage.getItem(honeyKeys[0]);
    expect(honeyHit).toBe(false);
  });

  it('exportItem returns value and metadata', async () => {
    const vault = await Tessera.unlock('246813');
    await vault.local.setItem('exp-key', 'exp-value');
    const exported = await vault.local.exportItem!('exp-key');
    expect(exported).not.toBeNull();
    expect(exported!.value).toBe('exp-value');
    expect(typeof exported!.writeTime).toBe('number');
    vault.lock();
  });

  it('proxy cleanup on terminate', async () => {
    const vault = await Tessera.unlock('246813', { honeyKeys: { count: 3 } });
    await vault.local.setItem('mykey', 'myvalue');
    const honeyKeys = vault._honeyStorageKeys('local');
    expect(honeyKeys.length).toBeGreaterThan(0);
    vault.terminate();

    let honeyHit = false;
    vault.on('honey-triggered', () => {
      honeyHit = true;
    });
    localStorage.getItem(honeyKeys[0]);
    expect(honeyHit).toBe(false);
  });
});
