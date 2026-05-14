import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { LocalStorageAdapter } from '../../src/adapters/local-storage';
import { KeySession } from '../../src/core/session';
import { deriveKey, getSalt } from '../../src/core/crypto';

let session: KeySession;

async function setupSession(): Promise<void> {
  session = new KeySession();
  const salt = await getSalt();
  const key = await deriveKey('abc123', salt);
  session.setKey(key, 900_000);
}

describe('LocalStorageAdapter', () => {
  beforeEach(async () => {
    localStorage.clear();
    await setupSession();
  });

  afterEach(() => {
    session.reset();
  });

  it('should encrypt and decrypt values', async () => {
    const adapter = new LocalStorageAdapter({}, session);
    await adapter.setItem('hello', 'world');
    const value = await adapter.getItem('hello');
    expect(value).toBe('world');
    // Raw value must be ciphertext, not plaintext
    expect(localStorage.getItem('hello')).not.toBe('world');
  });

  it('should return null for missing keys', async () => {
    const adapter = new LocalStorageAdapter({}, session);
    const value = await adapter.getItem('nonexistent');
    expect(value).toBeNull();
  });

  it('should remove items', async () => {
    const adapter = new LocalStorageAdapter({}, session);
    await adapter.setItem('temp', 'data');
    await adapter.removeItem('temp');
    expect(await adapter.getItem('temp')).toBeNull();
  });

  it('should skip encryption for unlisted keys in selective mode', async () => {
    const adapter = new LocalStorageAdapter({ selectiveKeys: ['secure'] }, session);
    await adapter.setItem('plain', 'visible');
    await adapter.setItem('secure', 'hidden');

    expect(localStorage.getItem('plain')).toBe('visible');
    expect(localStorage.getItem('secure')).not.toBe('hidden');
    expect(await adapter.getItem('plain')).toBe('visible');
    expect(await adapter.getItem('secure')).toBe('hidden');
  });

  it('should clear all items', async () => {
    const adapter = new LocalStorageAdapter({}, session);
    await adapter.setItem('a', '1');
    await adapter.setItem('b', '2');
    await adapter.clear();
    expect(await adapter.getItem('a')).toBeNull();
    expect(await adapter.getItem('b')).toBeNull();
  });

  it('should list stored keys', async () => {
    const adapter = new LocalStorageAdapter({}, session);
    await adapter.setItem('x', '1');
    await adapter.setItem('y', '2');
    const keys = await adapter.keys();
    expect(keys).toContain('x');
    expect(keys).toContain('y');
  });

  it('should return null when vault is locked', async () => {
    const adapter = new LocalStorageAdapter({}, session);
    await adapter.setItem('key', 'value');
    session.lock();
    const result = await adapter.getItem('key');
    expect(result).toBeNull();
  });

  it('should handle special characters and unicode values', async () => {
    const adapter = new LocalStorageAdapter({}, session);
    const data = '{"emoji":"🔐","accents":"café"}';
    await adapter.setItem('data', data);
    expect(await adapter.getItem('data')).toBe(data);
  });
});

