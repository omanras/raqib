import { describe, expect, it } from 'vitest';
import { addDays, isoDateOf } from '../../shared/schedule.js';
import { listLedger } from '../../server/db/ledger.js';
import { fixtureUser, testApp, type Agent, type TestApp } from './helpers.js';
import { createCircle, invite, join } from './world.js';

const DAY = 24 * 3600 * 1000;
type ErrorBody = { error: { code: string; message: string; details?: Record<string, unknown> } };
const err = (res: { json(): unknown }) => (res.json() as ErrorBody).error;

interface Line {
  memberId: string;
  contributionId: string;
  state: string;
  expected: number;
  reported: number;
  confirmed: number;
  outstanding: number;
  ageDays: number | null;
  seqs: number[];
  reports: { reportId: string; amount: number; confirmedSeq: number | null }[];
}
interface RoundView {
  round: { n: number; status: string; expected: number; confirmed: number; outstanding: number; payout: null | { amount: number; acknowledgedSeq: number | null } };
  lines: Line[];
}

interface Running {
  t: TestApp;
  id: string;
  org: Agent;
  members: Agent[];
  /** member ids by position: [0] is the recipient of round 1 */
  order: string[];
  agentOf: Map<string, Agent>;
}

/** A started circle of `n` members (organizer included), contribution 10.000 OMR, ordered as joined. */
async function running(n: number, options: { startInDays?: number; recipientPays?: boolean } = {}): Promise<Running> {
  const t = testApp();
  const o = await fixtureUser(t, 'organizer', 'Organizer');
  const startDate = addDays(isoDateOf(t.clock.now()), options.startInDays ?? 0);
  const id = await createCircle(o.agent, 'Running circle', { contribution: 10_000, startDate, recipientPays: options.recipientPays ?? true });
  const members: Agent[] = [];
  for (let i = 1; i < n; i += 1) {
    const u = await fixtureUser(t, `m${i}`, `Member ${i}`, `198.51.100.${20 + i}`);
    await join(u.agent, (await invite(o.agent, id)).token);
    members.push(u.agent);
  }
  const agents = [o.agent, ...members];
  const ids: string[] = [];
  for (const a of agents) ids.push(((await a.get(`/api/circles/${id}`)).json() as { me: { memberId: string } }).me.memberId);
  await o.agent.post(`/api/circles/${id}/order`, { order: ids });
  const started = await o.agent.post(`/api/circles/${id}/start`);
  expect(started.statusCode, started.body).toBe(200);
  return { t, id, org: o.agent, members, order: ids, agentOf: new Map(ids.map((m, i) => [m, agents[i] as Agent])) };
}

const types = (t: TestApp, id: string) => listLedger(t.db, id).map((e) => e.type);
const lineOf = (v: RoundView, memberId: string) => v.lines.find((l) => l.memberId === memberId) as Line;

describe('S3.3 state.rounds: open and close', () => {
  it('round 1 opens at start when the start date has come; otherwise it waits', async () => {
    const now = await running(2);
    expect(types(now.t, now.id).slice(-2)).toEqual(['circle.started', 'round.opened']);
    const later = await running(2, { startInDays: 5 });
    expect(types(later.t, later.id).at(-1)).toBe('circle.started');
    const v = (await later.org.get(`/api/circles/${later.id}`)).json() as { rounds: { status: string }[] };
    expect(v.rounds.map((r) => r.status)).toEqual(['upcoming', 'upcoming']);
  });

  it('opens strictly in order, one at a time, for the organizer only, with reasons', async () => {
    const r = await running(3, { startInDays: 2 });
    const open = (n: number, a: Agent = r.org) => a.post(`/api/circles/${r.id}/rounds/${n}/open`);
    expect(err(await open(2))).toMatchObject({ code: 'previous_round_not_closed', message: expect.stringContaining('Round 1') });
    expect((await open(1, r.members[0])).statusCode).toBe(403);
    expect((await open(1)).statusCode).toBe(200);
    expect(err(await open(1)).code).toBe('round_already_open');
    expect(err(await open(2)).code).toBe('another_round_open');
    expect(err(await open(9)).code).toBe('no_such_round');
    expect(err(await r.org.post(`/api/circles/${r.id}/rounds/2/close`)).code).toBe('round_not_open');
    expect(err(await r.org.post(`/api/circles/${r.id}/rounds/0/open`)).code).toBe('invalid_input');
    const entry = listLedger(r.t.db, r.id).at(-1);
    expect(entry).toMatchObject({ type: 'round.opened', payload: { n: 1, expected: 30_000, payers: 3, recipientMemberId: r.order[0] } });
  });

  it('closes with outstanding contributions listed in the entry; the last close completes the circle', async () => {
    const r = await running(2);
    const [first, second] = r.order as [string, string];
    await r.agentOf.get(first)?.post(`/api/circles/${r.id}/rounds/1/contributions`, { amount: 10_000 });
    const close1 = await r.org.post(`/api/circles/${r.id}/rounds/1/close`);
    expect(close1.statusCode).toBe(200);
    const entry = listLedger(r.t.db, r.id).at(-1);
    expect(entry?.type).toBe('round.closed');
    expect(entry?.payload).toMatchObject({ n: 1, expected: 20_000, confirmed: 0 });
    expect((entry?.payload.outstanding as { memberId: string }[]).map((o) => o.memberId).sort()).toEqual([first, second].sort());
    await r.org.post(`/api/circles/${r.id}/rounds/2/open`);
    await r.org.post(`/api/circles/${r.id}/rounds/2/close`);
    expect(types(r.t, r.id).slice(-2)).toEqual(['round.closed', 'circle.completed']);
    const v = (await r.org.get(`/api/circles/${r.id}`)).json() as { circle: { status: string } };
    expect(v.circle.status).toBe('completed');
    expect(err(await r.org.post(`/api/circles/${r.id}/rounds/2/open`)).code).toBe('circle_not_active');
    // Arrears can still be recorded after completion.
    expect((await r.agentOf.get(second)?.post(`/api/circles/${r.id}/rounds/1/contributions`, { amount: 10_000 }))?.statusCode).toBe(201);
  });
});

describe('contributions: report, confirm, waive', () => {
  it('a member reports for self (partial allowed); over-payment and reports for others are refused', async () => {
    const r = await running(3);
    const [, mid, last] = r.order as [string, string, string];
    const a = r.agentOf.get(mid) as Agent;
    const url = `/api/circles/${r.id}/rounds/1/contributions`;
    const part = await a.post(url, { amount: 4_000, method: 'cash', reference: 'envelope' });
    expect(part.statusCode).toBe(201);
    expect(lineOf(part.json() as RoundView, mid)).toMatchObject({ state: 'outstanding', reported: 4_000, confirmed: 0, outstanding: 10_000 });
    const over = await a.post(url, { amount: 6_001 });
    expect(over.statusCode).toBe(409);
    expect(err(over)).toMatchObject({ code: 'overpayment', details: { reportable: 6_000 } });
    const rest = await a.post(url, { amount: 6_000 });
    expect(lineOf(rest.json() as RoundView, mid)).toMatchObject({ state: 'reported', reported: 10_000, outstanding: 10_000 });
    expect(err(await a.post(url, { amount: 1 })).code).toBe('overpayment');
    expect((await a.post(url, { memberId: last, amount: 1_000 })).statusCode).toBe(403);
    expect(err(await a.post(url, { amount: 10.5 })).code).toBe('invalid_input');
    expect(err(await a.post(url, { amount: '100' })).code).toBe('invalid_input');
    expect(err(await a.post(`/api/circles/${r.id}/rounds/2/contributions`, { amount: 1_000 })).code).toBe('round_not_due');
    const entry = listLedger(r.t.db, r.id).filter((e) => e.type === 'contribution.reported').at(0);
    expect(entry?.payload).toMatchObject({ roundN: 1, memberId: mid, amount: 4_000, method: 'cash', reference: 'envelope' });
  });

  it('the organizer records a payment for any member and confirms it; a partial confirmation leaves the rest outstanding', async () => {
    const r = await running(3);
    const [, mid] = r.order as [string, string];
    const url = `/api/circles/${r.id}/rounds/1/contributions`;
    const first = (await r.org.post(url, { memberId: mid, amount: 3_000, method: 'cash' })).json() as RoundView & { reportId: string };
    const second = (await r.org.post(url, { memberId: mid, amount: 7_000 })).json() as RoundView & { reportId: string };
    const cid = lineOf(second, mid).contributionId;
    const confirmOne = await r.org.post(`${url}/${cid}/confirm`, { reportIds: [first.reportId] });
    expect(lineOf(confirmOne.json() as RoundView, mid)).toMatchObject({ state: 'reported', confirmed: 3_000, outstanding: 7_000 });
    expect(err(await r.org.post(`${url}/${cid}/confirm`, { reportIds: [first.reportId] })).code).toBe('unknown_report');
    const rest = await r.org.post(`${url}/${cid}/confirm`, {});
    const line = lineOf(rest.json() as RoundView, mid);
    expect(line).toMatchObject({ state: 'confirmed', confirmed: 10_000, outstanding: 0 });
    expect(line.seqs.length).toBe(4);
    expect(err(await r.org.post(`${url}/${cid}/confirm`, {})).code).toBe('nothing_to_confirm');
    expect((await (r.agentOf.get(mid) as Agent).post(`${url}/${cid}/confirm`, {})).statusCode).toBe(403);
    const confirmed = listLedger(r.t.db, r.id).filter((e) => e.type === 'contribution.confirmed');
    expect(confirmed.map((e) => e.payload.amount)).toEqual([3_000, 7_000]);
    const wrongRound = await r.org.post(`/api/circles/${r.id}/rounds/2/contributions/${cid}/confirm`, {});
    expect(wrongRound.statusCode).toBe(409);
  });

  it('waives with a reason; a waived contribution takes no reports; a confirmed one cannot be waived', async () => {
    const r = await running(3);
    const [, mid, last] = r.order as [string, string, string];
    const view = (await r.org.get(`/api/circles/${r.id}/overview`)).json() as { round: { members: Line[] } };
    const cid = view.round.members.find((m) => m.memberId === mid)?.contributionId as string;
    const url = `/api/circles/${r.id}/rounds/1/contributions/${cid}/waive`;
    expect(err(await r.org.post(url, {})).code).toBe('invalid_input');
    expect(err(await r.org.post(url, { reason: '   ' })).code).toBe('invalid_input');
    const w = await r.org.post(url, { reason: 'Hospital this month' });
    expect(lineOf(w.json() as RoundView, mid)).toMatchObject({ state: 'waived', outstanding: 0 });
    expect(err(await r.org.post(url, { reason: 'again' })).code).toBe('already_waived');
    expect(err(await (r.agentOf.get(mid) as Agent).post(`/api/circles/${r.id}/rounds/1/contributions`, { amount: 100 })).code).toBe('waived');
    expect(listLedger(r.t.db, r.id).at(-1)).toMatchObject({ type: 'contribution.waived', payload: { reason: 'Hospital this month', waived: 10_000 } });
    const row = r.t.db.prepare('SELECT waive_reason FROM contributions WHERE id = ?').get(cid) as { waive_reason: string };
    expect(row.waive_reason).toBe('Hospital this month');

    const lastAgent = r.agentOf.get(last) as Agent;
    const paid = (await lastAgent.post(`/api/circles/${r.id}/rounds/1/contributions`, { amount: 10_000 })).json() as RoundView;
    const lastCid = lineOf(paid, last).contributionId;
    await r.org.post(`/api/circles/${r.id}/rounds/1/contributions/${lastCid}/confirm`, {});
    expect(err(await r.org.post(`/api/circles/${r.id}/rounds/1/contributions/${lastCid}/waive`, { reason: 'x' })).code).toBe('already_confirmed');
  });

  it('with recipient_pays off the recipient owes nothing in their own round', async () => {
    const r = await running(3, { recipientPays: false });
    const recipient = r.order[0] as string;
    const res = await (r.agentOf.get(recipient) as Agent).post(`/api/circles/${r.id}/rounds/1/contributions`, { amount: 100 });
    expect(err(res).code).toBe('no_obligation');
    const view = (await r.org.get(`/api/circles/${r.id}/overview`)).json() as { round: { expected: number; members: Line[] } };
    expect(view.round.expected).toBe(20_000);
    expect(view.round.members.map((m) => m.memberId).sort()).toEqual([r.order[1], r.order[2]].sort());
  });
});

describe('payouts', () => {
  it('the organizer records one payout per round; only the recipient acknowledges it, once', async () => {
    const r = await running(2);
    const [recipient, other] = r.order as [string, string];
    const url = `/api/circles/${r.id}/rounds/1/payout`;
    expect(err(await r.org.post(`${url}/ack`)).code).toBe('no_payout');
    expect((await (r.agentOf.get(other) as Agent).post(url, { amount: 20_000 })).statusCode).toBe(403);
    expect(err(await r.org.post(url, { amount: 20_000, paidOn: addDays(isoDateOf(r.t.clock.now()), 3) })).code).toBe('paid_on_future');
    const rec = await r.org.post(url, { amount: 19_500, method: 'bank transfer', reference: 'TRX 77' });
    expect(rec.statusCode).toBe(201);
    expect((rec.json() as RoundView).round.payout).toMatchObject({ amount: 19_500, acknowledgedSeq: null });
    expect(err(await r.org.post(url, { amount: 1 })).code).toBe('payout_exists');
    expect(listLedger(r.t.db, r.id).at(-1)).toMatchObject({
      type: 'payout.recorded',
      payload: { roundN: 1, recipientMemberId: recipient, amount: 19_500, confirmedPot: 0, method: 'bank transfer' },
    });
    expect(err(await (r.agentOf.get(other) as Agent).post(`${url}/ack`)).code).toBe('not_recipient');
    const ack = await (r.agentOf.get(recipient) as Agent).post(`${url}/ack`);
    expect((ack.json() as RoundView).round.payout?.acknowledgedSeq).toBeGreaterThan(0);
    expect(err(await (r.agentOf.get(recipient) as Agent).post(`${url}/ack`)).code).toBe('already_acknowledged');
    expect(err(await r.org.post(`/api/circles/${r.id}/rounds/2/payout`, { amount: 1 })).code).toBe('round_not_due');
  });
});

describe('reads: ledger, statement, audit, overview', () => {
  it('GET ledger returns the entries from a seq and the verification; a tampered row is found (S6.3 ledger.tamper)', async () => {
    const r = await running(2);
    const all = (await r.org.get(`/api/circles/${r.id}/ledger?verify=1`)).json() as {
      entries: { seq: number }[];
      verification: { ok: boolean; lastSeq: number };
      head: { seq: number };
    };
    expect(all.verification).toMatchObject({ ok: true, lastSeq: all.head.seq });
    const from = (await r.org.get(`/api/circles/${r.id}/ledger?from=3`)).json() as { entries: { seq: number }[]; verification: null };
    expect(from.entries[0]?.seq).toBe(3);
    expect(from.verification).toBeNull();
    expect(err(await r.org.get(`/api/circles/${r.id}/ledger?from=0`)).code).toBe('invalid_input');
    expect(err(await r.org.get(`/api/circles/${r.id}/ledger?evil=1`)).code).toBe('invalid_input');

    // Tamper with one row underneath the application (the trigger forbids UPDATE, so drop it as an attacker would).
    r.t.db.exec('DROP TRIGGER ledger_no_update');
    r.t.db.prepare("UPDATE ledger SET payload = replace(payload, '10000', '1000') WHERE circle_id = ? AND seq = 1").run(r.id);
    const broken = (await r.org.get(`/api/circles/${r.id}/ledger?verify=1`)).json() as { verification: { ok: boolean; brokenSeq: number; reason: string } };
    expect(broken.verification).toMatchObject({ ok: false, brokenSeq: 1, reason: 'hash' });
  });

  it('the statement lists every round and member with seqs and totals; a member sees only their own', async () => {
    const r = await running(3);
    const [first, mid, last] = r.order as [string, string, string];
    const url = `/api/circles/${r.id}/rounds/1/contributions`;
    const v = (await (r.agentOf.get(mid) as Agent).post(url, { amount: 10_000, method: '=HYPERLINK("http://x")', reference: '+1' })).json() as RoundView;
    await r.org.post(`${url}/${lineOf(v, mid).contributionId}/confirm`, {});
    await (r.agentOf.get(last) as Agent).post(url, { amount: 2_000 });
    const s = (await r.org.get(`/api/circles/${r.id}/statement`)).json() as {
      members: Record<string, string>;
      statement: { rounds: { n: number; lines: (Line & { contributionId: string })[]; seqs: number[] }[]; totals: Record<string, number> };
    };
    expect(s.statement.rounds).toHaveLength(3);
    expect(s.statement.totals).toMatchObject({ expected: 90_000, expectedDue: 30_000, reported: 12_000, confirmed: 10_000, outstanding: 20_000 });
    const r1 = s.statement.rounds[0];
    expect(r1?.lines).toHaveLength(3);
    expect(r1?.lines.find((l) => l.memberId === mid)).toMatchObject({ state: 'confirmed', seqs: [expect.any(Number), expect.any(Number)] });
    expect(r1?.lines.find((l) => l.memberId === first)).toMatchObject({ state: 'outstanding', seqs: [] });
    expect(s.statement.rounds[1]?.lines.every((l) => l.state === 'not_due')).toBe(true);
    for (const line of r1?.lines ?? []) {
      for (const seq of line.seqs) expect(listLedger(r.t.db, r.id).some((e) => e.seq === seq)).toBe(true);
    }
    expect(s.members[mid]).toBe('Member 1');

    const midAgent = r.agentOf.get(mid) as Agent;
    const mine = (await midAgent.get(`/api/circles/${r.id}/statement?member=${mid}`)).json() as { statement: { rounds: { lines: Line[] }[]; totals: { confirmed: number } } };
    expect(mine.statement.rounds.every((x) => x.lines.every((l) => l.memberId === mid))).toBe(true);
    expect(mine.statement.totals.confirmed).toBe(10_000);
    expect((await midAgent.get(`/api/circles/${r.id}/statement?member=${last}`)).statusCode).toBe(403);
    expect((await r.org.get(`/api/circles/${r.id}/statement?member=${last}`)).statusCode).toBe(200);
    expect((await r.org.get(`/api/circles/${r.id}/statement?member=AAAAAAAAAAAAAAAAAAAAAA`)).statusCode).toBe(404);
  });

  it('S4.4 export.csv-injection: the CSV escapes formula-leading cells and quotes properly', async () => {
    const r = await running(2);
    const [, mid] = r.order as [string, string];
    await (r.agentOf.get(mid) as Agent).post(`/api/circles/${r.id}/rounds/1/contributions`, { amount: 5_000 });
    const cid = (((await r.org.get(`/api/circles/${r.id}/overview`)).json() as { round: { members: Line[] } }).round.members.find((m) => m.memberId === mid) as Line).contributionId;
    await r.org.post(`/api/circles/${r.id}/rounds/1/contributions/${cid}/waive`, { reason: '=1+2, "quoted"\nnext line' });
    const res = await r.org.get(`/api/circles/${r.id}/statement.csv`);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.headers['content-disposition']).toContain(`dawr-statement-${r.id}.csv`);
    expect(res.body.charCodeAt(0)).toBe(0xfeff);
    const text = res.body.slice(1);
    expect(text.split('\r\n')[0]).toBe('round,due_date,round_status,member,member_id,currency,expected,reported,confirmed,outstanding,state,days_overdue,waive_reason,ledger_seqs');
    expect(text).toContain(`"'=1+2, ""quoted""\nnext line"`);
    expect(text).not.toMatch(/(^|,)=1\+2/m);
    expect(text).toContain(',OMR,10.000,5.000,0.000,0.000,waived,');
  });

  it('GET audit is for the organizer, newest first and paged', async () => {
    const r = await running(2);
    const page1 = (await r.org.get(`/api/circles/${r.id}/audit?limit=2`)).json() as {
      entries: { id: number; action: string; actorName: string | null; requestId: string; ipPrefix: string }[];
      nextBefore: number | null;
    };
    expect(page1.entries).toHaveLength(2);
    expect(page1.entries[0]?.action).toBe('round.opened');
    expect(page1.entries[0]?.actorName).toBe('Organizer');
    expect(page1.entries[0]?.ipPrefix).toMatch(/\/24$/);
    expect(page1.nextBefore).toBe(page1.entries[1]?.id);
    const page2 = (await r.org.get(`/api/circles/${r.id}/audit?limit=50&before=${page1.nextBefore}`)).json() as { entries: { id: number }[]; nextBefore: null };
    expect(page2.entries.every((e) => e.id < (page1.nextBefore as number))).toBe(true);
    expect(page2.nextBefore).toBeNull();
    expect((await (r.members[0] as Agent).get(`/api/circles/${r.id}/audit`)).statusCode).toBe(403);
    expect(err(await r.org.get(`/api/circles/${r.id}/audit?limit=500`)).code).toBe('invalid_input');
  });

  it('GET overview: this round, recipient, due date, every member state, pot confirmed vs expected, outstanding with age', async () => {
    const r = await running(3);
    const [first, mid] = r.order as [string, string];
    const midAgent = r.agentOf.get(mid) as Agent;
    const before = (await midAgent.get(`/api/circles/${r.id}/overview`)).json() as {
      round: { n: number; of: number; status: string; dueDate: string; daysUntilDue: number; expected: number; confirmed: number; recipient: { memberId: string; displayName: string }; members: Line[] };
      me: { canReport: boolean; isRecipient: boolean };
      arrears: unknown[];
    };
    expect(before.round).toMatchObject({ n: 1, of: 3, status: 'open', expected: 30_000, confirmed: 0, recipient: { memberId: first, displayName: 'Organizer' } });
    expect(before.round.daysUntilDue).toBeGreaterThanOrEqual(0);
    expect(before.me).toEqual({ ...before.me, canReport: true, isRecipient: false });
    expect(before.round.members.every((m) => m.state === 'outstanding' && m.ageDays === null)).toBe(true);

    r.t.clock.advance(25 * DAY);
    const late = (await midAgent.get(`/api/circles/${r.id}/overview`)).json() as typeof before;
    const age = late.round.members[0]?.ageDays as number;
    expect(age).toBeGreaterThan(0);
    expect(late.round.daysUntilDue).toBe(-age);
    await midAgent.post(`/api/circles/${r.id}/rounds/1/contributions`, { amount: 10_000 });
    const after = (await midAgent.get(`/api/circles/${r.id}/overview`)).json() as typeof before;
    expect(after.me.canReport).toBe(false);
    await r.org.post(`/api/circles/${r.id}/rounds/1/close`);
    await r.org.post(`/api/circles/${r.id}/rounds/2/open`);
    const nextRes = await midAgent.get(`/api/circles/${r.id}/overview`);
    expect(nextRes.statusCode, nextRes.body).toBe(200);
    const next = nextRes.json() as Omit<typeof before, 'arrears'> & { arrears: Line[] };
    expect(next.round.n).toBe(2);
    expect(next.round.recipient.memberId).toBe(mid);
    expect(next.me.isRecipient).toBe(true);
    // A reported but unconfirmed payment is still outstanding (A5: nothing is assumed paid).
    expect(next.arrears.map((a) => a.memberId).sort()).toEqual([...r.order].sort());
    expect(next.arrears.find((a) => a.memberId === mid)).toMatchObject({ state: 'reported', reported: 10_000, confirmed: 0 });
    expect(next.arrears.every((a) => (a.ageDays ?? 0) > 0)).toBe(true);
  });

  it('the indexes agree with the books recomputed from the ledger', async () => {
    const r = await running(3);
    const [first, mid] = r.order as [string, string];
    await (r.agentOf.get(mid) as Agent).post(`/api/circles/${r.id}/rounds/1/contributions`, { amount: 10_000 });
    await r.org.post(`/api/circles/${r.id}/rounds/1/payout`, { amount: 10_000 });
    await (r.agentOf.get(first) as Agent).post(`/api/circles/${r.id}/rounds/1/payout/ack`);
    await r.org.post(`/api/circles/${r.id}/rounds/1/close`);
    const rows = r.t.db.prepare('SELECT n, status FROM rounds WHERE circle_id = ? ORDER BY n').all(r.id) as { n: number; status: string }[];
    const s = (await r.org.get(`/api/circles/${r.id}/statement`)).json() as { statement: { rounds: { n: number; status: string; payout: { amount: number } | null }[] } };
    expect(s.statement.rounds.map((x) => ({ n: x.n, status: x.status }))).toEqual(rows);
    const payout = r.t.db.prepare('SELECT amount, acknowledged_at FROM payouts WHERE circle_id = ?').get(r.id) as { amount: number; acknowledged_at: string };
    expect(s.statement.rounds[0]?.payout?.amount).toBe(payout.amount);
    expect(payout.acknowledged_at).toBeTruthy();
    const mine = (await r.org.get(`/api/circles/${r.id}`)).json() as { summary: { outstandingCount: number; outstandingAmount: number } };
    expect(mine.summary).toMatchObject({ outstandingCount: 3, outstandingAmount: 30_000 });
    const list = (await (r.agentOf.get(first) as Agent).get('/api/circles')).json() as { circles: { myOutstandingCount: number }[] };
    expect(list.circles[0]?.myOutstandingCount).toBe(1);
  });
});
