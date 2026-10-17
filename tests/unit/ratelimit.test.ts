import { describe, expect, it } from 'vitest';
import { FIFTEEN_MINUTES, SlidingWindow, createLimits } from '../../server/ratelimit.js';
import { TestClock } from '../api/helpers.js';

describe('S1.4 rate-limit store (in memory, test clock)', () => {
  it('counts hits inside a sliding window', () => {
    const clock = new TestClock();
    const w = new SlidingWindow({ limit: 3, windowMs: 1000 }, clock);
    expect(w.hit('k')).toBe(1);
    clock.advance(400);
    expect(w.hit('k')).toBe(2);
    expect(w.blocked('k')).toBe(false);
    expect(w.hit('k')).toBe(3);
    expect(w.blocked('k')).toBe(true);
    expect(w.retryAfterMs('k')).toBe(600);
    clock.advance(601);
    expect(w.blocked('k')).toBe(false);
    expect(w.count('k')).toBe(2);
    expect(w.count('other')).toBe(0);
    w.reset('k');
    expect(w.count('k')).toBe(0);
  });

  it('bounds memory by evicting the stalest keys', () => {
    const clock = new TestClock();
    const w = new SlidingWindow({ limit: 2, windowMs: 1000, maxKeys: 10 }, clock);
    for (let i = 0; i < 100; i += 1) w.hit(`k${i}`);
    expect(w.count('k99')).toBe(1);
    expect(w.count('k0')).toBe(0);
  });

  it('ships the limits of S1.4', () => {
    const l = createLimits(new TestClock());
    expect(l.authIp).toMatchObject({ limit: 30, windowMs: FIFTEEN_MINUTES });
    expect(l.loginFailures).toMatchObject({ limit: 10, windowMs: FIFTEEN_MINUTES });
  });
});
