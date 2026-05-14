/**
 * In-memory key session manager.
 *
 * Each `Tessera.unlock()` call creates an isolated `KeySession` instance.
 * The derived `CryptoKey` lives only inside this object's private state —
 * it is never written to any persistent storage or module-level variable.
 *
 * @security PLAN §5: "Never store the derived key in a module-level variable."
 */
import { TesseraError, TesseraErrorCode } from '../types';

const BROADCAST_CHANNEL = 'tessera_lock';

interface SessionState {
  key: CryptoKey;
  locked: boolean;
  lastActivity: number;
  idleTimeout: number;
  timerId?: ReturnType<typeof setTimeout>;
}

interface LockMessage {
  type: 'lock';
}

/**
 * Manages a single in-memory AES-GCM `CryptoKey` with idle-timeout auto-lock
 * and cross-tab synchronisation via `BroadcastChannel`.
 *
 * One `KeySession` is created per `Tessera.unlock()` call and closed over by
 * the returned `IVault`. The key never leaves this object.
 */
export class KeySession {
  private state: SessionState | null = null;
  private channel: BroadcastChannel | null = null;

  /**
   * Stores the derived key and starts the idle-timeout timer.
   * Any previously held key is discarded and its timer cancelled.
   *
   * @param key         - Non-extractable AES-GCM `CryptoKey`.
   * @param idleTimeout - Milliseconds of inactivity before auto-lock.
   */
  setKey(key: CryptoKey, idleTimeout: number): void {
    this.clearTimer();
    this.closeChannel();

    this.state = {
      key,
      locked: false,
      lastActivity: Date.now(),
      idleTimeout,
    };

    this.startTimer();
    this.openChannel();
  }

  /**
   * Returns the current `CryptoKey` and resets the idle timer.
   *
   * @returns The non-extractable AES-GCM key.
   * @throws {TesseraError} `LOCKED` if the vault is locked or no key is set.
   */
  getKey(): CryptoKey {
    if (this.state === null || this.state.locked) {
      throw new TesseraError(
        TesseraErrorCode.LOCKED,
        'Vault is locked. Call Tessera.unlock() first.',
      );
    }

    this.state.lastActivity = Date.now();
    return this.state.key;
  }

  /**
   * Returns the current `CryptoKey`, or `null` if the vault is locked.
   * Prefer this over {@link getKey} in adapter *read* paths to return `null`
   * gracefully instead of throwing.
   */
  getKeySafe(): CryptoKey | null {
    if (this.state === null || this.state.locked) return null;
    this.state.lastActivity = Date.now();
    return this.state.key;
  }

  /**
   * Marks the session as locked and broadcasts a lock event to all sibling tabs.
   * Subsequent calls to {@link getKey} will throw `LOCKED`.
   *
   * @security Call this when the user explicitly logs out or when sensitive
   *   work is complete to minimise the in-memory key exposure window (T7).
   */
  lock(): void {
    if (this.state !== null) {
      this.state.locked = true;
    }
    this.clearTimer();
    // Broadcast lock event to sibling tabs so they lock immediately.
    try {
      this.channel?.postMessage({ type: 'lock' } satisfies LockMessage);
    } catch {
      // Best-effort — channel may already be closed.
    }
    this.closeChannel();
  }

  /** Returns `true` if the session has no key or the key is locked. */
  isLocked(): boolean {
    return this.state === null || this.state.locked;
  }

  /**
   * Fully resets the session: clears the key, cancels the idle timer, and
   * closes the BroadcastChannel. Used in error paths and test teardown.
   */
  reset(): void {
    this.clearTimer();
    this.closeChannel();
    this.state = null;
  }

  private startTimer(): void {
    if (this.state === null) return;

    this.clearTimer();

    this.state.timerId = setTimeout(() => {
      this.lock();
    }, this.state.idleTimeout);
  }

  private clearTimer(): void {
    if (this.state?.timerId !== undefined) {
      clearTimeout(this.state.timerId);
      // Cast through unknown to satisfy exactOptionalPropertyTypes — the
      // optional field must hold Timeout | undefined but we can only delete it.
      delete (this.state as { timerId?: ReturnType<typeof setTimeout> }).timerId;
    }
  }

  private openChannel(): void {
    if (typeof BroadcastChannel === 'undefined') return;
    try {
      this.channel = new BroadcastChannel(BROADCAST_CHANNEL);
      this.channel.addEventListener('message', (event: MessageEvent<LockMessage>) => {
        if (event.data?.type === 'lock') {
          this.lock();
        }
      });
    } catch {
      // BroadcastChannel unavailable in this environment — skip.
    }
  }

  private closeChannel(): void {
    try {
      this.channel?.close();
    } catch {
      // Ignore.
    }
    this.channel = null;
  }

  /**
   * Records user activity and resets the idle-timeout timer.
   * Called internally by `Tessera.unlock()` after a successful key derivation.
   */
  touch(): void {
    if (this.state !== null) {
      this.state.lastActivity = Date.now();
      this.startTimer();
    }
  }
}

export const keySession = new KeySession();
