import { describe, it, expect } from 'vitest';
import { generateClaimToken, isClaimToken, extractTokenId } from '../../src/storage/claim';

describe('claim.generateClaimToken', () => {
  it('returns a string starting with t_', () => {
    expect(generateClaimToken()).toMatch(/^t_/);
  });

  it('returns a 34-character token (t_ + 32 hex chars)', () => {
    expect(generateClaimToken()).toHaveLength(34);
  });

  it('token body is lowercase hex', () => {
    const token = generateClaimToken();
    expect(token.slice(2)).toMatch(/^[\da-f]{32}$/);
  });

  it('generates unique tokens', () => {
    const a = generateClaimToken();
    const b = generateClaimToken();
    expect(a).not.toBe(b);
  });
});

describe('claim.isClaimToken', () => {
  it('returns true for a ref: prefixed string', () => {
    expect(isClaimToken('ref:t_abc123')).toBe(true);
  });

  it('returns false for a non-ref string', () => {
    expect(isClaimToken('t_abc123')).toBe(false);
  });

  it('returns false for an empty string', () => {
    expect(isClaimToken('')).toBe(false);
  });
});

describe('claim.extractTokenId', () => {
  it('strips the ref: prefix', () => {
    expect(extractTokenId('ref:t_abc123')).toBe('t_abc123');
  });

  it('returns the value unchanged when no prefix', () => {
    expect(extractTokenId('t_abc123')).toBe('t_abc123');
  });

  it('handles empty string', () => {
    expect(extractTokenId('')).toBe('');
  });
});
