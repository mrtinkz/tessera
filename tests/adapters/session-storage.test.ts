import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SessionStorageAdapter } from '../../src/adapters/session-storage';
import { KeySession } from '../../src/core/session';
import { deriveKey, getSalt } from '../../src/core/crypto';

let session: KeySession;

async function setupSession(): Promise<void> {
  session = new KeySession();
  const salt = await getSalt();
  const key = await deriveKey('abc123', salt);
  session.setKey(key, 900_000);
}

describe('SessionStorageAdapter', () => {
  beforeEach(async () => {
    sessionStorage.clear();
    await setupSession();
  });

  afterEach(() => {
    session.reset();
  });

  it('should encrypt and decrypt values', async () => {
    const adapter = new SessionStorageAdapter({}, session);
    await adapter.setItem('hello', 'world');
    const value = await adapter.getItem('hello');
    expect(value).toBe('world');
    expect(sessionStorage.getItem('hello')).not.toBe('world');
  });

  it('should return null for missing keys', async () => {
    const adapter = new SessionStorageAdapter({}, session);
    expect(await adapter.getItem('missing')).toBeNull();
  });

  it('should remove items', async () => {
    const adapter = new SessionStorageAdapter({}, session);
    await adapter.setItem('temp', 'val');
    await adapter.removeItem('temp');
    expect(await adapter.getItem('temp')).toBeNull();
  });

  it('should skip encryption for unlisted keys in selective mode', async () => {
    const adapter = new SessionStorageAdapter({ selectiveKeys: ['enc'] }, session);
    await adapter.setItem('plain', 'open');
    await adapter.setItem('enc', 'secret');
    expect(sessionStorage.getItem('plain')).toBe('open');
    expect(sessionStorage.getItem('enc')).not.toBe('secret');
    expect(await adapter.getItem('enc')).toBe('secret');
  });

  it('should clear all items', async () => {
    const adapter = new SessionStorageAdapter({}, session);
    await adapter.setItem('a', '1');
    await adapter.setItem('b', '2');
    await adapter.clear();
    expect(await adapter.getItem('a')).toBeNull();
  });

  it('should list stored keys', async () => {
    const adapter = new SessionStorageAdapter({}, session);
    await adapter.setItem('k1', 'v1');
    const keys = await adapter.keys();
    expect(keys).toContain('k1');
  });

  it('should return null when vault is locked', async () => {
    const adapter = new SessionStorageAdapter({}, session);
    await adapter.setItem('key', 'value');
    session.lock();
    expect(await adapter.getItem('key')).toBeNull();
  });
});



