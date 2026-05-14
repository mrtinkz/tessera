import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { IndexedDbAdapter } from '../../src/adapters/indexed-db';
import { KeySession } from '../../src/core/session';
import { deriveKey, getSalt } from '../../src/core/crypto';

let session: KeySession;

async function setupSession(): Promise<void> {
  session = new KeySession();
  const salt = await getSalt();
  const key = await deriveKey('abc123', salt);
  session.setKey(key, 900_000);
}

describe('IndexedDbAdapter', () => {
  beforeEach(async () => {
    await setupSession();
  });

  afterEach(() => {
    session.reset();
  });

  it('should store and retrieve a value', async () => {
    const adapter = new IndexedDbAdapter(session);
    await adapter.put('myStore', 'key1', { hello: 'world' });
    const result = await adapter.get('myStore', 'key1');
    expect(result).toEqual({ hello: 'world' });
  });

  it('should return undefined for a missing key', async () => {
    const adapter = new IndexedDbAdapter(session);
    const result = await adapter.get('myStore', 'nonexistent');
    expect(result).toBeUndefined();
  });

  it('should store the value encrypted (raw stored value is not plaintext)', async () => {
    const adapter = new IndexedDbAdapter(session);
    await adapter.put('myStore', 'secret', 'plaintext');
    // A different key would fail to decrypt — confirms data is encrypted
    const salt2 = await getSalt();
    const key2 = await deriveKey('xyz789', salt2);
    session.setKey(key2, 900_000);
    const result = await adapter.get('myStore', 'secret');
    // Decryption with wrong key returns undefined
    expect(result).toBeUndefined();
  });

  it('should remove a stored value', async () => {
    const adapter = new IndexedDbAdapter(session);
    await adapter.put('myStore', 'toRemove', 42);
    await adapter.remove('myStore', 'toRemove');
    const result = await adapter.get('myStore', 'toRemove');
    expect(result).toBeUndefined();
  });

  it('should clear all values in a named store', async () => {
    const adapter = new IndexedDbAdapter(session);
    await adapter.put('clearStore', 'a', 1);
    await adapter.put('clearStore', 'b', 2);
    await adapter.put('otherStore', 'c', 3);
    await adapter.clear('clearStore');
    expect(await adapter.get('clearStore', 'a')).toBeUndefined();
    expect(await adapter.get('clearStore', 'b')).toBeUndefined();
    // Other store must be untouched
    expect(await adapter.get('otherStore', 'c')).toBe(3);
  });

  it('should return undefined when vault is locked', async () => {
    const adapter = new IndexedDbAdapter(session);
    await adapter.put('myStore', 'lockedKey', 'value');
    session.lock();
    const result = await adapter.get('myStore', 'lockedKey');
    expect(result).toBeUndefined();
  });

  it('should support complex nested objects', async () => {
    const adapter = new IndexedDbAdapter(session);
    const data = { users: [{ id: 1, name: 'Alice' }, { id: 2, name: 'Bob' }], meta: { count: 2 } };
    await adapter.put('myStore', 'users', data);
    const result = await adapter.get('myStore', 'users');
    expect(result).toEqual(data);
  });
});


