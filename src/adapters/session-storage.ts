import { type IStorageAdapter, type TesseraConfig } from '../types';
import { type KeySession } from '../core/session';
import { encryptWithSalt, decryptFull } from '../core/crypto';

export class SessionStorageAdapter implements IStorageAdapter {
  private readonly selectiveKeys: Set<string>;
  private readonly encryptAll: boolean;
  private readonly session: KeySession;

  constructor(config: TesseraConfig, session: KeySession) {
    this.selectiveKeys = new Set(config.selectiveKeys ?? []);
    this.encryptAll = this.selectiveKeys.size === 0;
    this.session = session;
  }

  private shouldEncrypt(key: string): boolean {
    return this.encryptAll || this.selectiveKeys.has(key);
  }

  async getItem(key: string): Promise<string | null> {
    const raw = sessionStorage.getItem(key);
    if (raw === null) return null;

    if (!this.shouldEncrypt(key)) return raw;

    const cryptoKey = this.session.getKeySafe();
    if (cryptoKey === null) return null;
    const result = await decryptFull(cryptoKey, raw);
    if (result.ok) return result.value;
    return null;
  }

  async setItem(key: string, value: string): Promise<void> {
    if (!this.shouldEncrypt(key)) {
      sessionStorage.setItem(key, value);
      return;
    }

    const cryptoKey = this.session.getKey();
    const encrypted = await encryptWithSalt(cryptoKey, value);
    sessionStorage.setItem(key, encrypted);
  }

  async removeItem(key: string): Promise<void> {
    sessionStorage.removeItem(key);
  }

  async clear(): Promise<void> {
    sessionStorage.clear();
  }

  async keys(): Promise<string[]> {
    return Object.keys(sessionStorage);
  }
}
