import { describe, it, expect, vi } from 'vitest';
import { useTessera } from '../../src/framework/react/index';

describe('React framework adapter — useTessera', () => {
  it('exports useTessera function', () => {
    expect(typeof useTessera).toBe('function');
  });

  it('returns an object with vault, isLocked, unlock and lock keys', () => {
    vi.mock('react', () => ({
      useState: (init: unknown) => [init, vi.fn()],
      useCallback: (fn: unknown) => fn,
      useRef: (v: unknown) => ({ current: v }),
      useEffect: vi.fn(),
    }));

    const result = useTessera();
    expect(result).toHaveProperty('vault');
    expect(result).toHaveProperty('isLocked');
    expect(typeof result.unlock).toBe('function');
    expect(typeof result.lock).toBe('function');
  });

  it('initial isLocked state is true', () => {
    vi.mock('react', () => ({
      useState: (init: unknown) => [init, vi.fn()],
      useCallback: (fn: unknown) => fn,
      useRef: (v: unknown) => ({ current: v }),
      useEffect: vi.fn(),
    }));

    const { isLocked } = useTessera();
    expect(isLocked).toBe(true);
  });

  it('initial vault state is null', () => {
    vi.mock('react', () => ({
      useState: (init: unknown) => [init, vi.fn()],
      useCallback: (fn: unknown) => fn,
      useRef: (v: unknown) => ({ current: v }),
      useEffect: vi.fn(),
    }));

    const { vault } = useTessera();
    expect(vault).toBeNull();
  });
});
