import { describe, expect, it } from 'vitest';
import {
  CIRCLE_STATUSES,
  allRoundsClosed,
  checkCircle,
  checkCloseRound,
  checkDraw,
  checkOpenRound,
  checkStart,
  contributionStatus,
  nextCircleStatus,
  reportableAmount,
  type CircleAction,
  type CircleStatus,
  type RoundRef,
} from '../../shared/state.js';

describe('state: circle machine', () => {
  const allowed: Record<CircleAction, CircleStatus[]> = {
    edit: ['draft'],
    invite: ['draft'],
    join: ['draft'],
    leave: ['draft'],
    set_order: ['draft'],
    open_draw: ['draft'],
    draw: ['drawing'],
    start: ['draft', 'drawing'],
    cancel: ['draft', 'drawing'],
    run_rounds: ['active'],
    complete: ['active'],
  };

  it('allows exactly the listed transitions and explains every refusal', () => {
    for (const [action, from] of Object.entries(allowed) as [CircleAction, CircleStatus[]][]) {
      for (const status of CIRCLE_STATUSES) {
        const c = checkCircle(status, action);
        expect(c.ok, `${action} from ${status}`).toBe(from.includes(status));
        if (!c.ok) {
          expect(c.code).toMatch(/^[a-z_]+$/);
          expect(c.reason.length).toBeGreaterThan(10);
        }
      }
    }
  });

  it('moves draft -> drawing -> active -> completed and draft/drawing -> cancelled', () => {
    expect(nextCircleStatus('draft', 'open_draw')).toBe('drawing');
    expect(nextCircleStatus('drawing', 'start')).toBe('active');
    expect(nextCircleStatus('draft', 'start')).toBe('active');
    expect(nextCircleStatus('active', 'complete')).toBe('completed');
    expect(nextCircleStatus('drawing', 'cancel')).toBe('cancelled');
    expect(nextCircleStatus('draft', 'edit')).toBe('draft');
    expect(() => nextCircleStatus('active', 'cancel')).toThrow(/before it starts/);
    expect(() => nextCircleStatus('completed', 'open_draw')).toThrow(RangeError);
    expect(() => nextCircleStatus('cancelled', 'start')).toThrow(RangeError);
  });

  it('checkStart lists each missing precondition', () => {
    const base = {
      status: 'draft' as CircleStatus,
      memberCount: 3,
      memberIds: ['a', 'b', 'c'],
      order: ['b', 'c', 'a'],
      startDate: '2026-11-01',
      drawFinalized: false,
    };
    expect(checkStart(base)).toEqual({ ok: true });
    expect(checkStart({ ...base, memberCount: 1, memberIds: ['a'], order: ['a'] })).toMatchObject({ code: 'too_few_members' });
    expect(checkStart({ ...base, order: null })).toMatchObject({ code: 'no_order' });
    expect(checkStart({ ...base, order: ['a', 'b'] })).toMatchObject({ code: 'no_order' });
    expect(checkStart({ ...base, order: ['a', 'a', 'b'] })).toMatchObject({ code: 'no_order' });
    expect(checkStart({ ...base, order: ['a', 'b', 'x'] })).toMatchObject({ code: 'no_order' });
    expect(checkStart({ ...base, startDate: null })).toMatchObject({ code: 'no_start_date' });
    expect(checkStart({ ...base, status: 'drawing' })).toMatchObject({ code: 'draw_not_finalized' });
    expect(checkStart({ ...base, status: 'drawing', drawFinalized: true })).toEqual({ ok: true });
    expect(checkStart({ ...base, status: 'active' })).toMatchObject({ code: 'circle_not_startable' });
  });
});

describe('state: draw machine', () => {
  it('commit and close while committing; reveal and finalize while revealing', () => {
    expect(checkDraw('committing', 'commit').ok).toBe(true);
    expect(checkDraw('committing', 'close_commits').ok).toBe(true);
    expect(checkDraw('committing', 'reveal')).toMatchObject({ code: 'commits_open' });
    expect(checkDraw('committing', 'finalize')).toMatchObject({ code: 'commits_open' });
    expect(checkDraw('revealing', 'commit')).toMatchObject({ code: 'commits_closed' });
    expect(checkDraw('revealing', 'reveal').ok).toBe(true);
    expect(checkDraw('revealing', 'finalize').ok).toBe(true);
    expect(checkDraw('finalized', 'reveal')).toMatchObject({ code: 'draw_finalized' });
    expect(checkDraw('finalized', 'commit')).toMatchObject({ code: 'commits_closed' });
    expect(checkDraw(null, 'commit')).toMatchObject({ code: 'no_draw' });
  });
});

describe('state: round machine', () => {
  const rounds = (...s: RoundRef['status'][]): RoundRef[] => s.map((status, i) => ({ n: i + 1, status }));

  it('opens rounds strictly in order, one at a time', () => {
    expect(checkOpenRound(rounds('upcoming', 'upcoming'), 1).ok).toBe(true);
    expect(checkOpenRound(rounds('upcoming', 'upcoming'), 2)).toMatchObject({ code: 'previous_round_not_closed' });
    expect(checkOpenRound(rounds('open', 'upcoming'), 2)).toMatchObject({ code: 'another_round_open' });
    expect(checkOpenRound(rounds('closed', 'upcoming'), 2).ok).toBe(true);
    expect(checkOpenRound(rounds('closed', 'open'), 2)).toMatchObject({ code: 'round_already_open' });
    expect(checkOpenRound(rounds('closed', 'closed'), 2)).toMatchObject({ code: 'round_closed' });
    expect(checkOpenRound(rounds('closed'), 3)).toMatchObject({ code: 'no_such_round' });
  });

  it('closes only an open round', () => {
    expect(checkCloseRound(rounds('open'), 1).ok).toBe(true);
    expect(checkCloseRound(rounds('upcoming'), 1)).toMatchObject({ code: 'round_not_open' });
    expect(checkCloseRound(rounds('closed'), 1)).toMatchObject({ code: 'round_not_open' });
    expect(allRoundsClosed(rounds('closed', 'closed'))).toBe(true);
    expect(allRoundsClosed(rounds('closed', 'open'))).toBe(false);
    expect(allRoundsClosed([])).toBe(false);
  });
});

describe('state: contribution derivation', () => {
  it('derives outstanding, reported, confirmed and waived; nothing is assumed paid', () => {
    expect(contributionStatus(1000, [], false)).toEqual({ state: 'outstanding', expected: 1000, reported: 0, confirmed: 0, outstanding: 1000 });
    expect(contributionStatus(1000, [{ amount: 400, confirmed: false }], false)).toMatchObject({ state: 'outstanding', reported: 400, outstanding: 1000 });
    expect(contributionStatus(1000, [{ amount: 400, confirmed: true }], false)).toMatchObject({ state: 'outstanding', confirmed: 400, outstanding: 600 });
    expect(
      contributionStatus(1000, [{ amount: 400, confirmed: true }, { amount: 600, confirmed: false }], false),
    ).toMatchObject({ state: 'reported', outstanding: 600 });
    expect(
      contributionStatus(1000, [{ amount: 400, confirmed: true }, { amount: 600, confirmed: true }], false),
    ).toMatchObject({ state: 'confirmed', outstanding: 0 });
    expect(contributionStatus(1000, [{ amount: 100, confirmed: true }], true)).toMatchObject({ state: 'waived', outstanding: 0 });
  });

  it('reportableAmount refuses over-payment', () => {
    expect(reportableAmount(1000, [])).toBe(1000);
    expect(reportableAmount(1000, [{ amount: 700, confirmed: false }])).toBe(300);
    expect(reportableAmount(1000, [{ amount: 1000, confirmed: true }])).toBe(0);
  });
});
