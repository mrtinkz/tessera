import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { LocalStorageAdapter } from '../../src/adapters/local-storage';
import { KeySession } from '../../src/core/session';
import { deriveKey, deriveHmacKey, getSalt } from '../../src/core/crypto';
import { resolveConfig } from '../../src/core/config';
import { TesseraEmitter } from '../../src/core/events';

let session: KeySession;

async function setupSession(): Promise<void> {
  session = new KeySession();
  const salt = await getSalt();
  const key = await deriveKey('246813', salt);
  const hmacKey = await deriveHmacKey('246813', salt);
  session.setKey(key, 900_000);
  session.setHmacKey(hmacKey);
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
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('hello', 'world');
    const value = await adapter.getItem('hello');
    expect(value).toBe('world');
    // Raw value must be ciphertext, not plaintext
    expect(localStorage.getItem('hello')).not.toBe('world');
  });

  it('should return null for missing keys', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const value = await adapter.getItem('nonexistent');
    expect(value).toBeNull();
  });

  it('should remove items', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('temp', 'data');
    await adapter.removeItem('temp');
    expect(await adapter.getItem('temp')).toBeNull();
  });

  it('should encrypt all keys with name rotation', async () => {
    const config = resolveConfig();
    const events = new TesseraEmitter();
    const adapter = new LocalStorageAdapter(config, session, events);
    await adapter.setItem('plain', 'visible');
    await adapter.setItem('secure', 'hidden');

    const rawKeyPlain = await adapter.getRawKey!('plain');
    const rawKeySecure = await adapter.getRawKey!('secure');
    expect(localStorage.getItem(rawKeyPlain)).not.toBeNull();
    expect(localStorage.getItem(rawKeySecure)).not.toBeNull();
    expect(await adapter.getItem('plain')).toBe('visible');
    expect(await adapter.getItem('secure')).toBe('hidden');
  });

  it('should clear all items', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('a', '1');
    await adapter.setItem('b', '2');
    await adapter.clear();
    expect(await adapter.getItem('a')).toBeNull();
    expect(await adapter.getItem('b')).toBeNull();
  });

  it('should list stored keys', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('x', '1');
    await adapter.setItem('y', '2');
    const keys = await adapter.keys();
    expect(keys).toContain('x');
    expect(keys).toContain('y');
  });

  it('should return null when vault is locked', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    await adapter.setItem('key', 'value');
    session.lock();
    const result = await adapter.getItem('key');
    expect(result).toBeNull();
  });

  it('should handle special characters and unicode values', async () => {
    const adapter = new LocalStorageAdapter(resolveConfig(), session, new TesseraEmitter());
    const data = '{"emoji":"🔐","accents":"café"}';
    await adapter.setItem('data', data);
    expect(await adapter.getItem('data')).toBe(data);
  });
});
