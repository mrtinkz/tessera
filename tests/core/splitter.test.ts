import { describe, it, expect } from 'vitest';
import {
  splitValue,
  reconstructValue,
  shareToBase64,
  base64ToShare,
} from '../../src/core/splitter';

describe('splitter.splitValue + reconstructValue', () => {
  it('round-trips a simple string', () => {
    const { shareA, shareB } = splitValue('hello tessera');
    expect(reconstructValue(shareA, shareB)).toBe('hello tessera');
  });

  it('round-trips an empty string', () => {
    const { shareA, shareB } = splitValue('');
    expect(reconstructValue(shareA, shareB)).toBe('');
  });

  it('round-trips a unicode string', () => {
    const { shareA, shareB } = splitValue('tesséra 🔐');
    expect(reconstructValue(shareA, shareB)).toBe('tesséra 🔐');
  });

  it('produces shares the same byte length as the encoded input', () => {
    const value = 'abc';
    const { shareA, shareB } = splitValue(value);
    const encoded = new TextEncoder().encode(value);
    expect(shareA.length).toBe(encoded.length);
    expect(shareB.length).toBe(encoded.length);
  });

  it('shareA alone does not equal the plaintext', () => {
    const { shareA } = splitValue('secret');
    const decoded = new TextDecoder().decode(shareA);
    expect(decoded).not.toBe('secret');
  });

  it('shareB alone does not equal the plaintext', () => {
    const { shareB } = splitValue('secret');
    const decoded = new TextDecoder().decode(shareB);
    expect(decoded).not.toBe('secret');
  });

  it('different calls produce different shareA (random pad)', () => {
    const { shareA: a1 } = splitValue('same');
    const { shareA: a2 } = splitValue('same');
    expect(a1).not.toEqual(a2);
  });

  it('reconstructValue uses minimum length when shares differ in length', () => {
    const { shareA, shareB } = splitValue('hi');
    const longA = new Uint8Array([...shareA, 99]);
    expect(reconstructValue(longA, shareB)).toBe('hi');
  });
});

describe('splitter.shareToBase64 + base64ToShare', () => {
  it('round-trips a Uint8Array through base64', () => {
    const bytes = new Uint8Array([1, 2, 3, 255, 0, 128]);
    const b64 = shareToBase64(bytes);
    const result = base64ToShare(b64);
    expect(result).toEqual(bytes);
  });

  it('produces a valid base64 string', () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]);
    const b64 = shareToBase64(bytes);
    expect(() => atob(b64)).not.toThrow();
  });

  it('handles empty array', () => {
    const b64 = shareToBase64(new Uint8Array(0));
    const result = base64ToShare(b64);
    expect(result.length).toBe(0);
  });
});
