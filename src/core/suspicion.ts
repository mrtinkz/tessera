import { type ResolvedConfig } from '../types';
import { TesseraEmitter } from './events';

const RATE_WINDOW_MS = 1000;
// Fixed-capacity circular buffer replaces the grow-on-every-call number[].
// 200 slots covers any realistic rate-limit scenario with zero GC pressure.
const RATE_BUFFER_SIZE = 200;

export class SuspicionEngine {
  private score = 0;
  // Track time of last increment for score decay.
  private lastIncrementAt = 0;
  // Track which graduated thresholds have already fired to avoid duplicates.
  private readonly firedThresholds = new Set<string>();
  // Circular buffer of timestamps (Float64Array avoids Int32 epoch overflow).
  private readonly tsBuf = new Float64Array(RATE_BUFFER_SIZE);
  private tsHead = 0;
  private hiddenAt = 0;
  private isMobile = false;
  private platformThreshold = 500;
  private locked = false;
  private config: ResolvedConfig;
  private events: TesseraEmitter;
  private visibilityListener: (() => void) | null = null;
  private onLockdownCallback: (() => Promise<string[]>) | null = null;
  /** Fired after every score increment when persistScore is enabled. */
  private onScoreUpdate: ((score: number, timestamp: number) => void) | null = null;

  constructor(config: ResolvedConfig, events: TesseraEmitter, initialScore = 0) {
    this.config = config;
    this.events = events;
    if (initialScore > 0) {
      this.score = initialScore;
      this.lastIncrementAt = Date.now();
    }
    this.detectPlatform();
    this.setupVisibilityChange();
  }

  /**
   * Register a callback that is invoked after each score increment.
   * Use this to persist the score snapshot (e.g. HMAC-sign to localStorage).
   */
  setScoreUpdateCallback(cb: (score: number, timestamp: number) => void): void {
    this.onScoreUpdate = cb;
  }

  /**
   * Seed the engine with a pre-computed decayed score loaded from a persisted
   * snapshot. Only takes effect if the engine has not yet been incremented
   * (i.e. `lastIncrementAt === 0`). Call immediately after construction.
   */
  seedInitialScore(score: number): void {
    if (score > 0 && this.lastIncrementAt === 0) {
      this.score = score;
      this.lastIncrementAt = Date.now();
    }
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
    this.visibilityListener = (): void => {
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

    // Apply continuous exponential score decay before adding new points.
    const now = Date.now();
    const halfLife = this.config.suspicion.scoreDecayHalfLifeMs;
    if (halfLife > 0 && this.lastIncrementAt > 0 && this.score > 0) {
      const elapsed = now - this.lastIncrementAt;
      this.score = this.score * Math.exp((-Math.LN2 * elapsed) / halfLife);
    }
    this.lastIncrementAt = now;

    // Reduce impact when there is genuine user activation (user is at keyboard).
    const nav = globalThis.navigator as Navigator & { userActivation?: { isActive?: boolean } };
    const userIsActive = nav.userActivation?.isActive === true;
    const effectivePoints = userIsActive ? points * 0.5 : points;
    this.score += effectivePoints;

    // Emit graduated threshold events (fire once per threshold crossing).
    const th = this.config.suspicion.thresholds;
    if (!this.firedThresholds.has('cautious') && this.score >= th.cautious) {
      this.firedThresholds.add('cautious');
      this.events.emit('suspicion-cautious', { score: this.score });
    }
    if (!this.firedThresholds.has('guarded') && this.score >= th.guarded) {
      this.firedThresholds.add('guarded');
      this.events.emit('suspicion-guarded', { score: this.score });
    }
    if (!this.firedThresholds.has('critical') && this.score >= th.critical) {
      this.firedThresholds.add('critical');
      this.events.emit('suspicion-critical', { score: this.score });
    }

    if (this.score >= th.lockdown) {
      void this.lockdown(reason ?? 'suspicion-threshold');
    }

    this.onScoreUpdate?.(this.score, Date.now());
  }

  checkRateLimit(): { ok: boolean; callsPerSecond: number } {
    const now = Date.now();

    // O(1) write into circular buffer, O(RATE_BUFFER_SIZE) scan — no allocation.
    this.tsBuf[this.tsHead] = now;
    this.tsHead = (this.tsHead + 1) % RATE_BUFFER_SIZE;

    // Count entries within the 1-second window.
    let callsPerSecond = 0;
    for (let i = 0; i < RATE_BUFFER_SIZE; i++) {
      // eslint-disable-next-line security/detect-object-injection
      const ts = this.tsBuf[i] ?? 0;
      if (ts > 0 && now - ts < RATE_WINDOW_MS) {
        callsPerSecond++;
      }
    }

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
    this.tsBuf.fill(0);
    this.tsHead = 0;
    this.locked = false;
    this.hiddenAt = 0;
    this.lastIncrementAt = 0;
    this.firedThresholds.clear();
  }

  destroy(): void {
    if (this.visibilityListener && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this.visibilityListener);
      this.visibilityListener = null;
    }
    this.reset();
  }
}
