export function splitValue(value: string): { shareA: Uint8Array; shareB: Uint8Array } {
  const encoded = new TextEncoder().encode(value);
  const shareA = crypto.getRandomValues(new Uint8Array(encoded.length));
  const shareB = new Uint8Array(encoded.length);
  for (const [i, element] of encoded.entries()) {
    shareB[i] = element! ^ shareA[i]!;
  }
  return { shareA, shareB };
}

export function reconstructValue(shareA: Uint8Array, shareB: Uint8Array): string {
  const length = Math.min(shareA.length, shareB.length);
  const decoded = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    decoded[i] = shareA[i]! ^ shareB[i]!;
  }
  return new TextDecoder().decode(decoded);
}

export function shareToBase64(share: Uint8Array): string {
  let binary = '';
  for (const b of share) {
    binary += String.fromCodePoint(b);
  }
  return btoa(binary);
}

export function base64ToShare(encoded: string): Uint8Array {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.codePointAt(i)!;
  }
  return bytes;
}
