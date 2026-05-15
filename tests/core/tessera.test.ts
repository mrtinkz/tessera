import { describe, it, expect, beforeEach } from 'vitest';
import { Tessera } from '../../src/tessera';
import { TesseraErrorCode } from '../../src/types';
import { resetLockout } from '../../src/core/lockout';

describe('Tessera.unlock', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    resetLockout();
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
    const vault = await Tessera.unlock('246813');
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
    const vault = await Tessera.unlock('246813');
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
});
