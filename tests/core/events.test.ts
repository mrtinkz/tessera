import { describe, it, expect, vi } from 'vitest';
import { TesseraEmitter } from '../../src/core/events';

describe('TesseraEmitter', () => {
  it('calls registered handler when event is emitted', () => {
    const emitter = new TesseraEmitter();
    const handler = vi.fn();
    emitter.on('vault-locked', handler);
    emitter.emit('vault-locked', { reason: 'test' });
    expect(handler).toHaveBeenCalledOnce();
    expect(handler).toHaveBeenCalledWith({ reason: 'test' });
  });

  it('calls multiple handlers for the same event', () => {
    const emitter = new TesseraEmitter();
    const h1 = vi.fn();
    const h2 = vi.fn();
    emitter.on('vault-locked', h1);
    emitter.on('vault-locked', h2);
    emitter.emit('vault-locked', { reason: 'test' });
    expect(h1).toHaveBeenCalledOnce();
    expect(h2).toHaveBeenCalledOnce();
  });

  it('does not call handler after off(handler)', () => {
    const emitter = new TesseraEmitter();
    const handler = vi.fn();
    emitter.on('vault-locked', handler);
    emitter.off('vault-locked', handler);
    emitter.emit('vault-locked', { reason: 'test' });
    expect(handler).not.toHaveBeenCalled();
  });

  it('removes all handlers for an event when off() called without handler', () => {
    const emitter = new TesseraEmitter();
    const h1 = vi.fn();
    const h2 = vi.fn();
    emitter.on('vault-locked', h1);
    emitter.on('vault-locked', h2);
    emitter.off('vault-locked');
    emitter.emit('vault-locked', { reason: 'test' });
    expect(h1).not.toHaveBeenCalled();
    expect(h2).not.toHaveBeenCalled();
  });

  it('emits nothing when no handlers are registered', () => {
    const emitter = new TesseraEmitter();
    expect(() => emitter.emit('vault-locked', { reason: 'x' })).not.toThrow();
  });

  it('clears all handlers via clear()', () => {
    const emitter = new TesseraEmitter();
    const handler = vi.fn();
    emitter.on('vault-locked', handler);
    emitter.on('auto-locked', handler);
    emitter.clear();
    emitter.emit('vault-locked', { reason: 'x' });
    emitter.emit('auto-locked', { reason: 'idle-timeout' });
    expect(handler).not.toHaveBeenCalled();
  });

  it('emits handler-error when a handler throws', () => {
    const emitter = new TesseraEmitter();
    const errorHandler = vi.fn();
    emitter.on('vault-locked', () => {
      throw new Error('boom');
    });
    emitter.on('handler-error', errorHandler);
    emitter.emit('vault-locked', { reason: 'x' });
    expect(errorHandler).toHaveBeenCalledOnce();
    const payload = errorHandler.mock.calls[0]?.[0] as { sourceEvent: string; error: unknown };
    expect(payload.sourceEvent).toBe('vault-locked');
  });

  it('does not recurse when handler-error handler itself throws', () => {
    const emitter = new TesseraEmitter();
    emitter.on('vault-locked', () => {
      throw new Error('original');
    });
    emitter.on('handler-error', () => {
      throw new Error('error-handler-throws');
    });
    expect(() => emitter.emit('vault-locked', { reason: 'x' })).not.toThrow();
  });

  it('off() on unknown event does nothing', () => {
    const emitter = new TesseraEmitter();
    expect(() => emitter.off('vault-locked')).not.toThrow();
  });

  it('off(handler) on event with no remaining handlers removes the set', () => {
    const emitter = new TesseraEmitter();
    const handler = vi.fn();
    emitter.on('vault-locked', handler);
    emitter.off('vault-locked', handler);
    // Second off should be a no-op
    expect(() => emitter.off('vault-locked', handler)).not.toThrow();
  });

  it('off(handler) leaves the set intact when other handlers remain (set.size > 0 branch)', () => {
    const emitter = new TesseraEmitter();
    const h1 = vi.fn();
    const h2 = vi.fn();
    emitter.on('vault-locked', h1);
    emitter.on('vault-locked', h2);
    // Remove h1 — h2 is still registered; set must NOT be deleted.
    emitter.off('vault-locked', h1);
    emitter.emit('vault-locked', { reason: 'x' });
    expect(h1).not.toHaveBeenCalled();
    expect(h2).toHaveBeenCalledOnce();
  });

  it('silently drops registrations beyond MAX_HANDLERS_PER_EVENT (32)', () => {
    const emitter = new TesseraEmitter();
    const handlers = Array.from({ length: 34 }, () => vi.fn());
    for (const h of handlers) {
      emitter.on('vault-locked', h);
    }
    emitter.emit('vault-locked', { reason: 'x' });
    // First 32 are called; the remaining 2 were silently dropped.
    const calledCount = handlers.filter((h) => h.mock.calls.length > 0).length;
    expect(calledCount).toBe(32);
  });
});
