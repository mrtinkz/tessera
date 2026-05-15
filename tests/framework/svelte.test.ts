import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('svelte/store', () => ({
  writable: (init: unknown) => {
    let val = init;
    const subscribers: Array<(v: unknown) => void> = [];
    return {
      subscribe: (fn: (v: unknown) => void) => {
        subscribers.push(fn);
        fn(val);
        return () => {};
      },
      set: (v: unknown) => {
        val = v;
        for (const fn of subscribers) fn(val);
      },
      update: (fn: (v: unknown) => unknown) => {
        val = fn(val);
        for (const sub of subscribers) sub(val);
      },
    };
  },
  derived: (_store: unknown, fn: (v: unknown) => unknown) => ({
    subscribe: (cb: (v: unknown) => void) => {
      cb(fn(false));
      return () => {};
    },
  }),
}));

describe('Svelte framework adapter — tesseraStore', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it('exports tesseraStore function', async () => {
    const { tesseraStore } = await import('../../src/framework/svelte/index');
    expect(typeof tesseraStore).toBe('function');
  });

  it('returns vault, isLocked, unlock, and lock', async () => {
    const { tesseraStore } = await import('../../src/framework/svelte/index');
    const store = tesseraStore();
    expect(store).toHaveProperty('vault');
    expect(store).toHaveProperty('isLocked');
    expect(typeof store.unlock).toBe('function');
    expect(typeof store.lock).toBe('function');
  });

  it('vault store starts with null value', async () => {
    const { tesseraStore } = await import('../../src/framework/svelte/index');
    const store = tesseraStore();
    let vaultValue: unknown = 'unset';
    store.vault.subscribe((v: unknown) => {
      vaultValue = v;
    });
    expect(vaultValue).toBeNull();
  });

  // Exercise the unlock() body — calls Tessera.unlock and updates the store
  it('unlock() calls Tessera.unlock and resolves', async () => {
    const { tesseraStore } = await import('../../src/framework/svelte/index');
    const store = tesseraStore();
    await expect(store.unlock('246813')).resolves.not.toThrow();
  });

  // Exercise the lock() body — no-op when currentVault is null
  it('lock() runs without error when no vault is set', async () => {
    const { tesseraStore } = await import('../../src/framework/svelte/index');
    const store = tesseraStore();
    expect(() => store.lock()).not.toThrow();
  });

  // Exercise lock() body with an existing vault
  it('lock() calls vault.lock() and resets vault store to null', async () => {
    const { tesseraStore } = await import('../../src/framework/svelte/index');
    const store = tesseraStore();

    // Unlock first so currentVault is set
    await store.unlock('246813');

    // Now lock — should call vault.lock() internally
    let currentVault: unknown = 'unset';
    store.vault.subscribe((v: unknown) => {
      currentVault = v;
    });

    expect(() => store.lock()).not.toThrow();
    expect(currentVault).toBeNull();
  });
});
