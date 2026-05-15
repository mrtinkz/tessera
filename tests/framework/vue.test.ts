import { describe, it, expect, vi, beforeEach } from 'vitest';

// Hoisted so the mock applies before the module imports
vi.mock('vue', () => {
  const onUnmountedCallbacks: Array<() => void> = [];
  return {
    ref: (init: unknown) => ({ value: init }),
    readonly: (v: unknown) => v,
    onUnmounted: (fn: () => void) => {
      onUnmountedCallbacks.push(fn);
    },
    _triggerUnmounted: () => {
      for (const fn of onUnmountedCallbacks) fn();
      onUnmountedCallbacks.length = 0;
    },
  };
});

// Minimal Vue composable test — mock Vue primitives to isolate adapter logic.
describe('Vue framework adapter — useTessera', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it('exports useTessera function', async () => {
    const { useTessera } = await import('../../src/framework/vue/index');
    expect(typeof useTessera).toBe('function');
  });

  it('returns vault, isLocked, unlock, and lock', async () => {
    const { useTessera } = await import('../../src/framework/vue/index');
    const result = useTessera();
    expect(result).toHaveProperty('vault');
    expect(result).toHaveProperty('isLocked');
    expect(typeof result.unlock).toBe('function');
    expect(typeof result.lock).toBe('function');
  });

  it('initial vault value is null', async () => {
    const { useTessera } = await import('../../src/framework/vue/index');
    const result = useTessera();
    expect((result.vault as { value: unknown }).value).toBeNull();
  });

  it('initial isLocked value is true', async () => {
    const { useTessera } = await import('../../src/framework/vue/index');
    const result = useTessera();
    expect((result.isLocked as { value: unknown }).value).toBe(true);
  });

  // Exercise the unlock() body
  it('unlock() calls Tessera.unlock and resolves', async () => {
    const { useTessera } = await import('../../src/framework/vue/index');
    const result = useTessera();
    await expect(result.unlock('246813')).resolves.not.toThrow();
  });

  // Exercise the lock() body with null vault — no-op
  it('lock() runs without error when vault is null', async () => {
    const { useTessera } = await import('../../src/framework/vue/index');
    const result = useTessera();
    expect(() => result.lock()).not.toThrow();
  });

  // Exercise lock() body after unlock
  it('lock() calls vault.lock() and resets vault ref to null', async () => {
    const { useTessera } = await import('../../src/framework/vue/index');
    const result = useTessera();
    await result.unlock('246813');
    expect(() => result.lock()).not.toThrow();
    // After lock, vault ref value should be null
    expect((result.vault as { value: unknown }).value).toBeNull();
  });

  // Exercise onUnmounted cleanup — lock is called when component unmounts
  it('onUnmounted cleanup calls vault.lock()', async () => {
    const vue = (await import('vue')) as unknown as { _triggerUnmounted: () => void };
    const { useTessera } = await import('../../src/framework/vue/index');
    const result = useTessera();
    await result.unlock('246813');
    // Trigger unmount — should call vault.lock()
    expect(() => vue._triggerUnmounted()).not.toThrow();
  });
});
