import { type ICookieAdapter, type CookieOptions, type TesseraConfig } from '../types';
import { type KeySession } from '../core/session';
import { encryptWithSalt, decryptFull } from '../core/crypto';

export class CookieAdapter implements ICookieAdapter {
  private readonly selectiveKeys: Set<string>;
  private readonly encryptAll: boolean;
  private readonly session: KeySession;

  constructor(config: TesseraConfig, session: KeySession) {
    this.selectiveKeys = new Set(config.selectiveKeys ?? []);
    this.encryptAll = this.selectiveKeys.size === 0;
    this.session = session;
  }

  private shouldEncrypt(name: string): boolean {
    return this.encryptAll || this.selectiveKeys.has(name);
  }

  async get(name: string): Promise<string | null> {
    const value = this.readRaw(name);
    if (value === null) return null;

    if (this.shouldEncrypt(name)) {
      const cryptoKey = this.session.getKeySafe();
      if (cryptoKey === null) return null;
      const result = await decryptFull(cryptoKey, decodeURIComponent(value));
      if (result.ok) return result.value;
      return null;
    }

    return value;
  }

  async set(name: string, value: string, options?: CookieOptions): Promise<void> {
    const parts: string[] = [];

    if (this.shouldEncrypt(name)) {
      const cryptoKey = this.session.getKey();
      const encrypted = await encryptWithSalt(cryptoKey, value);
      parts.push(`${encodeURIComponent(name)}=${encodeURIComponent(encrypted)}`);
    } else {
      parts.push(`${encodeURIComponent(name)}=${encodeURIComponent(value)}`);
    }

    if (options?.expires !== undefined) {
      const date = new Date();
      date.setDate(date.getDate() + options.expires);
      parts.push(`expires=${date.toUTCString()}`);
    }

    if (options?.path !== undefined) {
      parts.push(`path=${options.path}`);
    }

    if (options?.domain !== undefined) {
      parts.push(`domain=${options.domain}`);
    }

    if (options?.sameSite !== undefined) {
      parts.push(`SameSite=${options.sameSite}`);
    }

    if (options?.secure === true) {
      parts.push('Secure');
    }

    document.cookie = parts.join('; ');
  }

  async remove(name: string): Promise<void> {
    document.cookie = `${encodeURIComponent(name)}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  }

  private readRaw(name: string): string | null {
    const encodedName = encodeURIComponent(name);
    const cookies = document.cookie.split('; ');
    for (const cookie of cookies) {
      const eqIdx = cookie.indexOf('=');
      if (eqIdx === -1) continue;
      const cookieName = cookie.slice(0, eqIdx);
      if (cookieName === encodedName) {
        return cookie.slice(eqIdx + 1);
      }
    }
    return null;
  }
}
