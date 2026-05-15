import {
  type TesseraEventName,
  type TesseraEventPayloads,
  type TesseraEventHandler,
} from '../types';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type HandlerSet = Map<TesseraEventName, Set<TesseraEventHandler<any>>>;

export class TesseraEmitter {
  private handlers: HandlerSet = new Map();

  on<E extends TesseraEventName>(event: E, handler: TesseraEventHandler<E>): void {
    let set = this.handlers.get(event);
    if (!set) {
      set = new Set();
      this.handlers.set(event, set);
    }
    set.add(handler);
  }

  off<E extends TesseraEventName>(event: E, handler?: TesseraEventHandler<E>): void {
    if (handler === undefined) {
      this.handlers.delete(event);
      return;
    }
    const set = this.handlers.get(event);
    if (set) {
      set.delete(handler);
      if (set.size === 0) this.handlers.delete(event);
    }
  }

  emit<E extends TesseraEventName>(event: E, payload: TesseraEventPayloads[E]): void {
    const set = this.handlers.get(event);
    if (!set) return;
    for (const handler of set) {
      try {
        handler(payload);
      } catch (error) {
        if (event !== 'handler-error') {
          this.emit('handler-error', { sourceEvent: event, error });
        }
      }
    }
  }

  clear(): void {
    this.handlers.clear();
  }
}
