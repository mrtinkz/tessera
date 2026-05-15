import { CLAIM_TOKEN_PREFIX } from '../types';

export function generateClaimToken(): string {
  const random = crypto.getRandomValues(new Uint8Array(16));
  let hex = '';
  for (const b of random) {
    hex += b.toString(16).padStart(2, '0');
  }
  return `t_${hex}`;
}

export function isClaimToken(value: string): boolean {
  return value.startsWith(CLAIM_TOKEN_PREFIX);
}

export function extractTokenId(value: string): string {
  if (value.startsWith(CLAIM_TOKEN_PREFIX)) {
    return value.slice(CLAIM_TOKEN_PREFIX.length);
  }
  return value;
}
