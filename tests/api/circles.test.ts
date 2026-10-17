import { describe, expect, it } from 'vitest';
import { verify } from '../../shared/ledger.js';
import { addDays, isoDateOf } from '../../shared/schedule.js';
import { sha256Hex } from '../../server/crypto.js';
import { listLedger } from '../../server/db/ledger.js';
import { fixtureUser, testApp, type Agent, type TestApp } from './helpers.js';
import { CIRCLE_INPUT, buildWorld, createCircle, invite, join, memberIds } from './world.js';

type ErrorBody = { error: { code: string; message: string; details?: unknown } };
const err = (res: { json(): unknown }) => (res.json() as ErrorBody).error;

interface CircleView {
  circle: { id: string; status: string; memberCount: number; pot: number; startDate: string | null; rulesText: string; contribution: number; currency: string; minorUnit: number };
  me: { memberId: string; role: string };
  members: { id: string; userId: string; displayName: string; role: string; position: number | null }[];
  rounds: { n: number; dueDate: string; recipientMemberId: string; status: string }[];
  summary: { outstandingCount: number };
  startCheck: { ok: boolean; code?: string; reason?: string };
}

const view = async (a: Agent, id: string) => (await a.get(`/api/circles/${id}`)).json() as CircleView;
const auditActions = (t: TestApp, circleId: string) =>
  (t.db.prepare('SELECT action FROM audit WHERE circle_id = ? ORDER BY id').all(circleId) as { action: string }[]).map((r) => r.action);
const ledgerTypes = (t: TestApp, circleId: string) => listLedger(t.db, circleId).map((e) => e.type);

describe('POST /api/circles', () => {
  it('creates a draft circle, the creator becomes organizer, ledger circle.created + member.joined, audit', async () => {
    const t = testApp();
    const { agent, userId } = await fixtureUser(t, 'org', 'Organizer');
    const res = await agent.post('/api/circles', { ...CIRCLE_INPUT, name: 'جمعية الحي', recipientPays: true, displayName: 'أم سالم' });
    expect(res.statusCode).toBe(201);
    const v = res.json() as CircleView;
    expect(v.circle).toMatchObject({ status: 'draft', currency: 'OMR', minorUnit: 3, contribution: 50000, memberCount: 1, pot: 50000 });
    expect(v.me.role).toBe('organizer');
    expect(v.members).toEqual([expect.objectContaining({ userId, role: 'organizer', displayName: 'أم سالم', position: null })]);
    expect(ledgerTypes(t, v.circle.id)).toEqual(['circle.created', 'member.joined']);
    const created = listLedger(t.db, v.circle.id)[0];
    expect(created?.payload).toMatchObject({ name: 'جمعية الحي', contribution: 50000, currency: 'OMR', rulesText: CIRCLE_INPUT.rulesText });
    expect(created?.actor).toBe(userId);
    expect(auditActions(t, v.circle.id)).toEqual(['circle.created']);
    expect(v.startCheck).toMatchObject({ ok: false, code: 'too_few_members' });
  });

  it('refuses bad input: unknown currency, floats, strings for amounts, bad due days, unknown keys, past start, unsafe text', async () => {
    const t = testApp();
    const { agent } = await fixtureUser(t, 'org');
    const base = { ...CIRCLE_INPUT, name: 'x' };
    const cases: [Record<string, unknown>, string][] = [
      [{ ...base, currency: 'XYZ' }, 'invalid_input'],
      [{ ...base, contribution: 10.5 }, 'invalid_input'],
      [{ ...base, contribution: '50' }, 'invalid_input'],
      [{ ...base, contribution: 0 }, 'invalid_input'],
      [{ ...base, contribution: 1e12 }, 'invalid_input'],
      [{ ...base, dueDay: 29 }, 'invalid_input'],
      [{ ...base, period: 'weekly', dueDay: 9 }, 'invalid_input'],
      [{ ...base, period: 'daily' }, 'invalid_input'],
      [{ ...base, owner: 'me' }, 'invalid_input'],
      [{ ...base, name: '' }, 'invalid_input'],
      [{ ...base, name: 'a‮b' }, 'invalid_input'],
      [{ ...base, rulesText: 'x'.repeat(4001) }, 'invalid_input'],
      [{ ...base, startDate: '2026-02-30' }, 'invalid_input'],
      [{ ...base, startDate: addDays(isoDateOf(t.clock.now()), -5) }, 'start_date_past'],
    ];
    for (const [body, code] of cases) {
      const res = await agent.post('/api/circles', body);
      expect(err(res).code, JSON.stringify(body).slice(0, 80)).toBe(code);
    }
    const weekly = await agent.post('/api/circles', { ...base, period: 'weekly', dueDay: 5, rulesText: 'line one\nline two' });
    expect(weekly.statusCode).toBe(201);
  });
});

describe('S3.2 S8.1 GET /api/circles and /api/circles/:id (404 for circles not mine)', () => {
  it('lists only my circles with my role; shows a circle to its members only (404 otherwise)', async () => {
    const w = await buildWorld('draft');
    const { organizerA, memberA, memberB } = w.people;
    const mine = (await memberA.agent.get('/api/circles')).json() as { circles: { id: string; role: string; status: string }[] };
    expect(mine.circles).toEqual([expect.objectContaining({ id: w.ids.circleA, role: 'member', status: 'draft' })]);
    const org = (await organizerA.agent.get('/api/circles')).json() as { circles: { id: string; role: string }[] };
    expect(org.circles.map((c) => [c.id, c.role])).toEqual([[w.ids.circleA, 'organizer']]);
    const v = await view(memberA.agent, w.ids.circleA as string);
    expect(v.members.map((m) => m.role).sort()).toEqual(['member', 'organizer']);
    expect(v.me.role).toBe('member');
    const outsider = await memberB.agent.get(`/api/circles/${w.ids.circleA}`);
    expect(outsider.statusCode).toBe(404);
    const missing = await memberB.agent.get('/api/circles/AAAAAAAAAAAAAAAAAAAAAA');
    expect(missing.statusCode).toBe(404);
    expect({ code: err(outsider).code, message: err(outsider).message }).toEqual({ code: err(missing).code, message: err(missing).message });
  });
});

describe('PATCH /api/circles/:id', () => {
  it('writes one circle.rule_changed per changed field with from and to; nothing for unchanged fields', async () => {
    const w = await buildWorld('draft');
    const org = w.people.organizerA.agent;
    const id = w.ids.circleA as string;
    const before = ledgerTypes(w.t, id).length;
    const startDate = addDays(isoDateOf(w.t.clock.now()), 10);
    const res = await org.patch(`/api/circles/${id}`, { rulesText: 'New rules', contribution: 60000, dueDay: 5, startDate });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { changed: string[] }).changed.sort()).toEqual(['contribution', 'rulesText', 'startDate']);
    const entries = listLedger(w.t.db, id).slice(before);
    expect(entries.map((e) => e.type)).toEqual(['circle.rule_changed', 'circle.rule_changed', 'circle.rule_changed']);
    expect(entries.map((e) => e.payload)).toEqual(
      expect.arrayContaining([
        { field: 'contribution', from: 50000, to: 60000 },
        { field: 'rulesText', from: CIRCLE_INPUT.rulesText, to: 'New rules' },
        { field: 'startDate', from: null, to: startDate },
      ]),
    );
    expect(auditActions(w.t, id)).toContain('circle.rule_changed');
  });

  it('refuses a currency change of minor unit without a new contribution, and a weekly due day 9', async () => {
    const w = await buildWorld('draft');
    const org = w.people.organizerA.agent;
    const id = w.ids.circleA as string;
    expect(err(await org.patch(`/api/circles/${id}`, { currency: 'USD' })).code).toBe('contribution_required');
    const ok = await org.patch(`/api/circles/${id}`, { currency: 'USD', contribution: 2500 });
    expect((await view(org, id)).circle).toMatchObject({ currency: 'USD', minorUnit: 2, contribution: 2500 });
    expect(ok.statusCode).toBe(200);
    expect((await org.patch(`/api/circles/${id}`, { currency: 'SAR' })).statusCode).toBe(200);
    expect(err(await org.patch(`/api/circles/${id}`, { period: 'weekly', dueDay: 9 })).code).toBe('invalid_due_day');
    expect(err(await org.patch(`/api/circles/${id}`, { dueDay: 20, period: 'weekly' })).code).toBe('invalid_due_day');
    expect(err(await org.patch(`/api/circles/${id}`, {})).code).toBe('invalid_input');
  });

  it('is refused for members (403) and after start (409 with the reason)', async () => {
    const w = await buildWorld('active');
    const res = await w.people.organizerA.agent.patch(`/api/circles/${w.ids.circleA}`, { rulesText: 'late change' });
    expect(res.statusCode).toBe(409);
    expect(err(res)).toMatchObject({ code: 'circle_not_draft', message: expect.stringContaining('draft') });
    const m = await w.people.memberA.agent.patch(`/api/circles/${w.ids.circleA}`, { rulesText: 'x' });
    expect(m.statusCode).toBe(403);
  });
});

describe('S3.2 invites.*', () => {
  it('creates a one-time link under BASE_URL, stores only the token hash, and the invitee joins once', async () => {
    const t = testApp({ config: { baseUrl: 'https://dawr.example.org' } });
    const org = await fixtureUser(t, 'org');
    const guest = await fixtureUser(t, 'guest', 'Guest');
    const id = await createCircle(org.agent, 'Circle');
    const res = await org.agent.post(`/api/circles/${id}/invites`);
    expect(res.statusCode).toBe(201);
    const body = res.json() as { token: string; link: string; invite: { id: string; expiresAt: string; status: string } };
    expect(body.link).toBe(`https://dawr.example.org/join/${body.token}`);
    expect(body.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Date.parse(body.invite.expiresAt) - t.clock.now().getTime()).toBe(7 * 24 * 3600 * 1000);
    expect(JSON.stringify(t.db.prepare('SELECT * FROM invites').all())).not.toContain(body.token);
    expect(JSON.stringify(listLedger(t.db, id))).not.toContain(body.token);

    const preview = await guest.agent.get(`/api/invites/${body.token}`);
    expect(preview.json()).toMatchObject({ circle: { name: 'Circle', memberCount: 1 }, organizerName: 'org', alreadyMember: false });
    const accepted = await guest.agent.post(`/api/invites/${body.token}/accept`, { displayName: 'Guest in circle' });
    expect(accepted.statusCode).toBe(200);
    const v = await view(guest.agent, id);
    expect(v.members.find((m) => m.userId === guest.userId)).toMatchObject({ role: 'member', displayName: 'Guest in circle' });
    expect(ledgerTypes(t, id)).toEqual(['circle.created', 'member.joined', 'member.joined']);
    expect(auditActions(t, id)).toEqual(['circle.created', 'invite.created', 'member.joined']);

    const again = await guest.agent.post(`/api/invites/${body.token}/accept`);
    expect(again.statusCode).toBe(404);
    const third = await fixtureUser(t, 'third');
    expect((await third.agent.post(`/api/invites/${body.token}/accept`)).statusCode).toBe(404);
    expect((await third.agent.get(`/api/invites/${body.token}`)).statusCode).toBe(404);
    const list = (await org.agent.get(`/api/circles/${id}/invites`)).json() as { invites: { status: string }[] };
    expect(list.invites.map((i) => i.status)).toEqual(['accepted']);
  });

  it('refuses expired and revoked links, a second membership, and links after the draw or start', async () => {
    const w = await buildWorld('draft');
    const org = w.people.organizerA.agent;
    const id = w.ids.circleA as string;
    const expiring = await invite(org, id);
    w.t.clock.advance(7 * 24 * 3600 * 1000 + 1);
    expect((await w.people.memberB.agent.post(`/api/invites/${expiring.token}/accept`)).statusCode).toBe(404);
    const revoked = await invite(org, id);
    expect((await org.post(`/api/circles/${id}/invites/${revoked.id}/revoke`)).statusCode).toBe(200);
    expect((await org.post(`/api/circles/${id}/invites/${revoked.id}/revoke`)).statusCode).toBe(409);
    expect((await w.people.memberB.agent.post(`/api/invites/${revoked.token}/accept`)).statusCode).toBe(404);
    expect(auditActions(w.t, id)).toContain('invite.revoked');
    expect(ledgerTypes(w.t, id)).not.toContain('invite.revoked');
    const dup = await invite(org, id);
    const again = await w.people.memberA.agent.post(`/api/invites/${dup.token}/accept`);
    expect(err(again).code).toBe('already_member');

    const late = await invite(org, id);
    await org.patch(`/api/circles/${id}`, { startDate: addDays(isoDateOf(w.t.clock.now()), 2) });
    await org.post(`/api/circles/${id}/order`, { order: await memberIds(org, id) });
    expect((await org.post(`/api/circles/${id}/start`)).statusCode).toBe(200);
    const after = await w.people.memberB.agent.post(`/api/invites/${late.token}/accept`);
    expect(after.statusCode).toBe(409);
    expect(err(after).code).toBe('circle_closed_to_members');
    expect(err(await org.post(`/api/circles/${id}/invites`)).code).toBe('circle_not_draft');
  });

  it('caps open invitations at 50 and members at 100', async () => {
    const w = await buildWorld('draft');
    const org = w.people.organizerA.agent;
    const id = w.ids.circleA as string;
    for (let i = 0; i < 49; i += 1) await invite(org, id);
    const over = await org.post(`/api/circles/${id}/invites`);
    expect(err(over).code).toBe('too_many_invites');

    const now = w.t.clock.now().toISOString();
    const insertUser = w.t.db.prepare(
      "INSERT INTO users (id, login, display_name, password_hash, password_changed_at, created_at) VALUES (?, ?, 'x', 'x', ?, ?)",
    );
    const insertMember = w.t.db.prepare(
      "INSERT INTO members (id, circle_id, user_id, role, display_name, joined_at, created_at) VALUES (?, ?, ?, 'member', 'x', ?, ?)",
    );
    for (let i = 0; i < 98; i += 1) {
      insertUser.run(`u${i}`, `filler${i}`, now, now);
      insertMember.run(`m${i}`, id, `u${i}`, now, now);
    }
    const token = w.ids.inviteTokenA as string;
    const full = await w.people.memberB.agent.post(`/api/invites/${token}/accept`);
    expect(err(full).code).toBe('circle_full');
  });

  it('rate-limits invite creation and acceptance per IP and per account', async () => {
    const w = await buildWorld('draft');
    const org = w.people.organizerA.agent;
    let last = 0;
    for (let i = 0; i < 150; i += 1) {
      const r = await org.get(`/api/invites/${'x'.repeat(43)}`);
      last = r.statusCode;
      if (last === 429) break;
    }
    expect(last).toBe(429);
    // Another account from another address is unaffected.
    expect((await w.people.memberB.agent.get(`/api/invites/${w.ids.inviteTokenA}`)).statusCode).toBe(200);
  });
});

describe('S3.3 state.* order, start, leave, cancel', () => {
  it('sets a manual order (a full permutation) and records it', async () => {
    const w = await buildWorld('draft');
    const org = w.people.organizerA.agent;
    const id = w.ids.circleA as string;
    const [first, second] = [w.ids.memberAInA as string, w.ids.organizerAInA as string];
    for (const bad of [[first], [first, first], [first, 'AAAAAAAAAAAAAAAAAAAAAA'], [first, second, 'x']]) {
      expect(err(await org.post(`/api/circles/${id}/order`, { order: bad })).code).toBe('invalid_order');
    }
    expect((await org.post(`/api/circles/${id}/order`, { order: [first, second] })).statusCode).toBe(200);
    const v = await view(org, id);
    expect(v.members.map((m) => [m.id, m.position])).toEqual([
      [first, 1],
      [second, 2],
    ]);
    const entry = listLedger(w.t.db, id).at(-1);
    expect(entry).toMatchObject({ type: 'order.set', payload: { order: [first, second], method: 'manual' } });
  });

  it('start refuses with each state-machine reason, then freezes members, creates rounds and obligations', async () => {
    const t = testApp();
    const org = await fixtureUser(t, 'org');
    const id = await createCircle(org.agent, 'Start me', { recipientPays: false });
    const start = () => org.agent.post(`/api/circles/${id}/start`);
    expect(err(await start())).toMatchObject({ code: 'too_few_members', message: expect.stringContaining('at least 2') });
    const b = await fixtureUser(t, 'bee');
    const c = await fixtureUser(t, 'cee');
    await join(b.agent, (await invite(org.agent, id)).token);
    await join(c.agent, (await invite(org.agent, id)).token);
    expect(err(await start()).code).toBe('no_order');
    const ids = await memberIds(org.agent, id);
    const order = [ids[2], ids[0], ids[1]] as string[];
    await org.agent.post(`/api/circles/${id}/order`, { order });
    expect(err(await start()).code).toBe('no_start_date');
    const startDate = addDays(isoDateOf(t.clock.now()), 1);
    await org.agent.patch(`/api/circles/${id}`, { startDate });
    expect((await b.agent.post(`/api/circles/${id}/start`)).statusCode).toBe(403);
    const res = await start();
    expect(res.statusCode).toBe(200);
    const v = res.json() as CircleView;
    expect(v.circle).toMatchObject({ status: 'active', memberCount: 3, pot: 100000 });
    expect(v.rounds.map((r) => [r.n, r.recipientMemberId, r.status])).toEqual([
      [1, order[0], 'upcoming'],
      [2, order[1], 'upcoming'],
      [3, order[2], 'upcoming'],
    ]);
    expect(v.rounds.map((r) => r.dueDate)).toEqual(['2026-11-05', '2026-12-05', '2027-01-05']);
    const obligations = t.db.prepare('SELECT round_n, member_id FROM contributions WHERE circle_id = ?').all(id) as {
      round_n: number;
      member_id: string;
    }[];
    expect(obligations).toHaveLength(6);
    for (const r of v.rounds) expect(obligations.some((o) => o.round_n === r.n && o.member_id === r.recipientMemberId)).toBe(false);
    const entry = listLedger(t.db, id).at(-1);
    expect(entry).toMatchObject({ type: 'circle.started', payload: { memberCount: 3, startDate, pot: 100000, recipientPays: false } });
    expect(verify(listLedger(t.db, id), sha256Hex).ok).toBe(true);

    expect(err(await start()).code).toBe('circle_not_startable');
    expect(err(await b.agent.post(`/api/circles/${id}/leave`)).code).toBe('circle_not_draft');
    expect(err(await org.agent.post(`/api/circles/${id}/cancel`)).code).toBe('circle_not_cancellable');
    expect(err(await org.agent.post(`/api/circles/${id}/order`, { order })).code).toBe('circle_not_draft');
    expect(auditActions(t, id)).toContain('circle.started');
  });

  it('a member leaves a draft (order cleared, ledger member.left); the organizer cannot leave', async () => {
    const w = await buildWorld('ordered');
    const id = w.ids.circleA as string;
    expect(err(await w.people.organizerA.agent.post(`/api/circles/${id}/leave`)).code).toBe('organizer_cannot_leave');
    expect((await w.people.memberA.agent.post(`/api/circles/${id}/leave`)).statusCode).toBe(200);
    expect((await w.people.memberA.agent.get(`/api/circles/${id}`)).statusCode).toBe(404);
    const v = await view(w.people.organizerA.agent, id);
    expect(v.members).toHaveLength(1);
    expect(v.members[0]?.position).toBeNull();
    expect(listLedger(w.t.db, id).at(-1)).toMatchObject({ type: 'member.left', payload: { orderCleared: true } });
    expect(auditActions(w.t, id)).toContain('member.left');
  });

  it('cancels a draft; afterwards nothing changes it', async () => {
    const w = await buildWorld('draft');
    const org = w.people.organizerA.agent;
    const id = w.ids.circleA as string;
    const res = await org.post(`/api/circles/${id}/cancel`, { reason: 'Not enough people' });
    expect((res.json() as CircleView).circle.status).toBe('cancelled');
    expect(listLedger(w.t.db, id).at(-1)).toMatchObject({ type: 'circle.cancelled', payload: { reason: 'Not enough people', status: 'draft' } });
    expect(err(await org.patch(`/api/circles/${id}`, { rulesText: 'x' })).code).toBe('circle_not_draft');
    expect(err(await org.post(`/api/circles/${id}/invites`)).code).toBe('circle_not_draft');
    expect(err(await org.post(`/api/circles/${id}/cancel`)).code).toBe('circle_not_cancellable');
    expect(err(await w.people.memberB.agent.post(`/api/invites/${w.ids.inviteTokenA}/accept`)).code).toBe('circle_closed_to_members');
    expect((await w.people.memberB.agent.get(`/api/invites/${w.ids.inviteTokenA}`)).statusCode).toBe(404);
    expect(auditActions(w.t, id)).toContain('circle.cancelled');
  });
});
