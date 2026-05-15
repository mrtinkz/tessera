import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useTessera } from '../../src/framework/vue/index';

// Minimal Vue composable test — mock Vue primitives to isolate adapter logic.
describe('Vue framework adapter — useTessera', () => {
  beforeEach(() => {
    vi.mock('vue', () => ({
      ref: (init: unknown) => ({ value: init }),
      readonly: (v: unknown) => v,
      onUnmounted: vi.fn(),
    }));
  });

  it('exports useTessera function', () => {
    expect(typeof useTessera).toBe('function');
  });

  it('returns vault, isLocked, unlock, and lock', () => {
    const result = useTessera();
    expect(result).toHaveProperty('vault');
    expect(result).toHaveProperty('isLocked');
    expect(typeof result.unlock).toBe('function');
    expect(typeof result.lock).toBe('function');
  });

  it('initial vault value is null', () => {
    const result = useTessera();
    expect((result.vault as { value: unknown }).value).toBeNull();
  });

  it('initial isLocked value is true', () => {
    const result = useTessera();
    expect((result.isLocked as { value: unknown }).value).toBe(true);
  });
});
