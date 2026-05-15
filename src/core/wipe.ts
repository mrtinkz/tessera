function generateNoise(length: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCodePoint(b);
  }
  return btoa(binary);
}

export async function hardWipe(
  rawBackend: {
    removeItem(key: string): void | Promise<void>;
    setItem(key: string, value: string): void | Promise<void>;
  },
  key: string,
): Promise<void> {
  const noise = generateNoise(256);
  await rawBackend.setItem(key, noise);
  await rawBackend.removeItem(key);
}

export function generateNoiseBlock(length?: number): string {
  return generateNoise(length ?? 256);
}
