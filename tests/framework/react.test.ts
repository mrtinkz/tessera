import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useTessera } from '../../src/framework/react/index';
import type { IVault } from '../../src/types';

// Minimal React hook runner — invoke the hook as a plain function with mocked
// React primitives. This avoids a full React renderer dependency.
type SetState<T> = (value: T) => void;

function runHook(config?: Parameters<typeof useTessera>[0]) {
  // Capture state setters and simulate basic useState / useCallback / useRef / useEffect
  const state: Record<string, unknown> = { vault: null, isLocked: true };
  const calls: Array<() => void> = [];

  vi.mock('react', () => ({
    useState: (init: unknown) => {
      const key = init === null ? 'vault' : 'isLocked';
      const setter: SetState<unknown> = (v: unknown) => { state[key] = v; };
      return [state[key], setter];
    },
    useCallback: (fn: () => unknown) => fn,
    useRef: (v: unknown) => ({ current: v }),
    useEffect: (fn: () => void) => { calls.push(fn); },
  }));

  return { state, calls };
}

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
