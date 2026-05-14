import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('Svelte framework adapter — tesseraStore', () => {
  beforeEach(() => {
    vi.mock('svelte/store', () => ({
      writable: (init: unknown) => {
        let val = init;
        return {
          subscribe: (fn: (v: unknown) => void) => { fn(val); return () => {}; },
          set: (v: unknown) => { val = v; },
          update: (fn: (v: unknown) => unknown) => { val = fn(val); },
        };
      },
      derived: (_store: unknown, fn: (v: unknown) => unknown) => {
        return {
          subscribe: (cb: (v: unknown) => void) => { cb(fn(false)); return () => {}; },
        };
      },
    }));
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
    store.vault.subscribe((v: unknown) => { vaultValue = v; });
    expect(vaultValue).toBeNull();
  });
});
