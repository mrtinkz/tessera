import { type ResolvedConfig } from '../types';
import { TesseraEmitter } from './events';

const RATE_WINDOW_MS = 1000;

export class SuspicionEngine {
  private score = 0;
  private callTimestamps: number[] = [];
  private hiddenAt = 0;
  private isMobile = false;
  private platformThreshold = 500;
  private locked = false;
  private config: ResolvedConfig;
  private events: TesseraEmitter;
  private visibilityListener: (() => void) | null = null;
  private onLockdownCallback: (() => Promise<string[]>) | null = null;

  constructor(config: ResolvedConfig, events: TesseraEmitter) {
    this.config = config;
    this.events = events;
    this.detectPlatform();
    this.setupVisibilityChange();
  }

  get currentScore(): number {
    return this.score;
  }

  get isLockedDown(): boolean {
    return this.locked;
  }

  private detectPlatform(): void {
    if (this.config.suspicion.platform === 'desktop') {
      this.isMobile = false;
    } else if (this.config.suspicion.platform === 'mobile') {
      this.isMobile = true;
    } else {
      this.isMobile = this.detectMobile();
    }
    this.platformThreshold = this.isMobile
      ? this.config.suspicion.visibilityChange.duration.mobile
      : this.config.suspicion.visibilityChange.duration.desktop;
    if (this.platformThreshold < this.config.suspicion.visibilityChange.duration.floor) {
      this.platformThreshold = this.config.suspicion.visibilityChange.duration.floor;
    }
  }

  private detectMobile(): boolean {
    try {
      const nav = navigator as Navigator & { userAgentData?: { mobile?: boolean } };
      if (nav.userAgentData?.mobile === true) return true;
    } catch {
      /* ignore */
    }
    const ua = navigator.userAgent;
    return /android|iphone|ipad|ipod|blackberry|opera mini|iemobile|mobile/i.test(ua);
  }

  private setupVisibilityChange(): void {
    if (typeof document === 'undefined') return;
    this.visibilityListener = () => {
      if (document.hidden) {
        this.hiddenAt = Date.now();
      } else if (this.hiddenAt > 0) {
        const hiddenDuration = Date.now() - this.hiddenAt;
        this.hiddenAt = 0;
        if (hiddenDuration >= this.platformThreshold) {
          this.increment(this.config.suspicion.visibilityChange.score, 'visibility-change');
        }
      }
    };
    document.addEventListener('visibilitychange', this.visibilityListener);
  }

  increment(points: number, reason?: string): void {
    if (this.locked) return;
    this.score += points;
    if (this.score >= this.config.suspicion.thresholds.lockdown) {
      void this.lockdown(reason ?? 'suspicion-threshold');
    }
  }

  checkRateLimit(): { ok: boolean; callsPerSecond: number } {
    const now = Date.now();
    this.callTimestamps = this.callTimestamps.filter((t) => now - t < RATE_WINDOW_MS);
    this.callTimestamps.push(now);
    const callsPerSecond = this.callTimestamps.length;

    if (callsPerSecond > this.config.suspicion.rateLimit.callsPerSecond) {
      const excess = callsPerSecond - this.config.suspicion.rateLimit.callsPerSecond;
      const scoreIncrement = excess * this.config.suspicion.rateLimit.scorePerExcess;

      if (callsPerSecond >= this.config.suspicion.rateLimit.callsPerSecond * 1.5) {
        this.increment(scoreIncrement, 'rate-limit');
      }

      if (
        callsPerSecond > this.config.suspicion.rateLimit.callsPerSecond &&
        callsPerSecond < this.config.suspicion.rateLimit.callsPerSecond * 1.5
      ) {
        this.events.emit('rate-limit-warning', {
          callsPerSecond,
          threshold: this.config.suspicion.rateLimit.callsPerSecond,
        });
      }

      return { ok: false, callsPerSecond };
    }

    return { ok: true, callsPerSecond };
  }

  recordPasscodeFailure(): void {
    this.increment(this.config.suspicion.passcodeFailure.scorePerAttempt, 'passcode-failure');
  }

  recordHoneyHit(backend: string): void {
    this.increment(50, 'honey-key');
    this.events.emit('honey-triggered', { backend, score: this.score });
  }

  recordHmacFailure(): void {
    this.increment(100, 'hmac-failure');
  }

  setOnLockdown(fn: () => Promise<string[]>): void {
    this.onLockdownCallback = fn;
  }

  private async lockdown(reason: string): Promise<void> {
    this.locked = true;
    const keysWiped = await (this.onLockdownCallback?.() ?? Promise.resolve([]));
    this.events.emit('suspicion-lockdown', {
      reason,
      score: this.score,
      keysWiped,
    });
  }

  reset(): void {
    this.score = 0;
    this.callTimestamps = [];
    this.locked = false;
    this.hiddenAt = 0;
  }

  destroy(): void {
    if (this.visibilityListener && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this.visibilityListener);
      this.visibilityListener = null;
    }
    this.reset();
  }
}
