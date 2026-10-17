import type { Clock } from './types.js';

/**
 * In-memory sliding-window counter (S1.4). Keys are opaque strings
 * ("ip:203.0.113.0", "login:sara"); each key keeps the times of its hits
 * inside the window. The clock is injected so tests can move time. Memory
 * is bounded: at most maxKeys keys, the stalest evicted first.
 */
export class SlidingWindow {
  readonly limit: number;
  readonly windowMs: number;
  private readonly maxKeys: number;
  private readonly clock: Clock;
  private readonly hits = new Map<string, number[]>();

  constructor(options: { limit: number; windowMs: number; maxKeys?: number }, clock: Clock) {
    this.limit = options.limit;
    this.windowMs = options.windowMs;
    this.maxKeys = options.maxKeys ?? 50_000;
    this.clock = clock;
  }

  private live(key: string, now: number): number[] {
    const list = this.hits.get(key);
    if (!list) return [];
    const from = now - this.windowMs;
    let i = 0;
    while (i < list.length && (list[i] as number) <= from) i += 1;
    if (i > 0) list.splice(0, i);
    if (list.length === 0) this.hits.delete(key);
    return list;
  }

  /** Hits currently counted for the key. */
  count(key: string): number {
    return this.live(key, this.clock.now().getTime()).length;
  }

  /** True when the key has reached the limit. */
  blocked(key: string): boolean {
    return this.count(key) >= this.limit;
  }

  /** Milliseconds until the key drops below the limit (0 when not blocked). */
  retryAfterMs(key: string): number {
    const now = this.clock.now().getTime();
    const list = this.live(key, now);
    if (list.length < this.limit) return 0;
    const unblockAt = (list[list.length - this.limit] as number) + this.windowMs;
    return Math.max(0, unblockAt - now);
  }

  /** Records a hit; returns the count including it. */
  hit(key: string): number {
    const now = this.clock.now().getTime();
    const list = this.live(key, now);
    if (list.length === 0) {
      if (this.hits.size >= this.maxKeys) this.evict(now);
      this.hits.set(key, list);
    }
    list.push(now);
    // Never keep more than the window needs to decide.
    if (list.length > this.limit * 2) list.splice(0, list.length - this.limit * 2);
    return list.length;
  }

  reset(key: string): void {
    this.hits.delete(key);
  }

  private evict(now: number): void {
    for (const key of [...this.hits.keys()]) this.live(key, now);
    while (this.hits.size >= this.maxKeys) {
      const oldest = this.hits.keys().next().value;
      if (oldest === undefined) break;
      this.hits.delete(oldest);
    }
  }
}

export const FIFTEEN_MINUTES = 15 * 60 * 1000;

export interface Limits {
  /** S1.4: 30 POST /api/auth/* per IP per 15 min. */
  authIp: SlidingWindow;
  /** S1.4: 10 failed sign-ins per login per 15 min, then 423. */
  loginFailures: SlidingWindow;
  /** Failed recovery-code attempts per login per 15 min. */
  recoveryFailures: SlidingWindow;
  /** Invite creation and acceptance per IP per 15 min (ADR §6). */
  inviteIp: SlidingWindow;
  /** Invite creation and acceptance per account per 15 min (ADR §6). */
  inviteAccount: SlidingWindow;
}

export function createLimits(clock: Clock): Limits {
  return {
    authIp: new SlidingWindow({ limit: 30, windowMs: FIFTEEN_MINUTES }, clock),
    loginFailures: new SlidingWindow({ limit: 10, windowMs: FIFTEEN_MINUTES }, clock),
    recoveryFailures: new SlidingWindow({ limit: 10, windowMs: FIFTEEN_MINUTES }, clock),
    inviteIp: new SlidingWindow({ limit: 120, windowMs: FIFTEEN_MINUTES }, clock),
    inviteAccount: new SlidingWindow({ limit: 100, windowMs: FIFTEEN_MINUTES }, clock),
  };
}
