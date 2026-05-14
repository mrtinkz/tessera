import { type IIDBAdapter, TesseraError, TesseraErrorCode } from '../types';
import { type KeySession } from '../core/session';
import { encryptWithSalt, decryptFull } from '../core/crypto';

const DB_NAME = 'tessera_vault';
const DB_VERSION = 1;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('tessera_data')) {
        db.createObjectStore('tessera_data', { keyPath: ['store', 'key'] });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.addEventListener('error', () => reject(new TesseraError(TesseraErrorCode.STORAGE_QUOTA, 'Failed to open IndexedDB.')));
  });
}

export class IndexedDbAdapter implements IIDBAdapter {
  private readonly session: KeySession;

  constructor(session: KeySession) {
    this.session = session;
  }

  async put(storeName: string, key: string, value: unknown): Promise<void> {
    const cryptoKey = this.session.getKey();
    const encrypted = await encryptWithSalt(cryptoKey, JSON.stringify(value));

    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      store.put({ store: storeName, key, value: encrypted, updatedAt: Date.now() });
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.addEventListener('error', () => { db.close(); reject(new TesseraError(TesseraErrorCode.STORAGE_QUOTA, 'IndexedDB write failed.')); });
    });
  }

  async get(storeName: string, key: string): Promise<unknown> {
    const cryptoKey = this.session.getKeySafe();
    if (cryptoKey === null) return undefined;

    const db = await openDb();
    const record = await new Promise<{ value: string } | undefined>((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readonly');
      const store = tx.objectStore('tessera_data');
      const request = store.get([storeName, key]);
      request.onsuccess = () => { resolve(request.result); };
      request.addEventListener('error', () => { reject(new TesseraError(TesseraErrorCode.STORAGE_QUOTA, 'IndexedDB read failed.')); });
      tx.oncomplete = () => { db.close(); };
    });

    if (record === undefined) return undefined;

    const result = await decryptFull(cryptoKey, record.value);
    if (!result.ok) return undefined;

    return JSON.parse(result.value) as unknown;
  }

  async remove(storeName: string, key: string): Promise<void> {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      store.delete([storeName, key]);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.addEventListener('error', () => { db.close(); reject(); });
    });
  }

  async clear(storeName: string): Promise<void> {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('tessera_data', 'readwrite');
      const store = tx.objectStore('tessera_data');
      const request = store.openCursor();
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor) {
          const data = cursor.value as { store: string };
          if (data.store === storeName) {
            cursor.delete();
          }
          cursor.continue();
        }
      };
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.addEventListener('error', () => { db.close(); reject(); });
    });
  }
}
