import { describe, expect, it } from 'vitest';
import { webSha256Hex } from '../../shared/hash.js';
import { verify } from '../../shared/ledger.js';
import { commit, finalizeAsync } from '../../shared/lottery.js';
import { addDays, isoDateOf } from '../../shared/schedule.js';
import { sha256Hex } from '../../server/crypto.js';
import { migrate, openDb } from '../../server/db/db.js';
import { listLedger } from '../../server/db/ledger.js';
import { computeResult, loadDraw } from '../../server/draw.js';
import { fixtureUser, testApp, type Agent, type TestApp } from './helpers.js';
import { createCircle, drawDeadlines, invite, join, newSecret } from './world.js';

const HOUR = 3600 * 1000;
type ErrorBody = { error: { code: string; message: string } };
const err = (res: { json(): unknown }) => (res.json() as ErrorBody).error;

interface DrawView {
  draw: {
    phase: string;
    committedCount: number;
    revealedCount: number;
    mine: { committed: boolean; revealed: boolean };
    result: null | { seed: string; order: string[]; silent: string[]; notCommitted: string[]; members: string[]; reveals: { memberId: string; secret: string }[] };
  } | null;
}

interface Party {
  t: TestApp;
  circleId: string;
  agents: Agent[];
  memberIds: string[];
  org: Agent;
}

async function party(n: number): Promise<Party> {
  const t = testApp();
  const org = await fixtureUser(t, 'organizer', 'Organizer');
  const circleId = await createCircle(org.agent, 'Draw circle', { startDate: addDays(isoDateOf(t.clock.now()), 3) });
  const agents = [org.agent];
  for (let i = 1; i < n; i += 1) {
    const u = await fixtureUser(t, `member${i}`, `Member ${i}`, `198.51.100.${10 + i}`);
    await join(u.agent, (await invite(org.agent, circleId)).token);
    agents.push(u.agent);
  }
  const memberIds: string[] = [];
  for (const a of agents) memberIds.push(((await a.get(`/api/circles/${circleId}`)).json() as { me: { memberId: string } }).me.memberId);
  return { t, circleId, agents, memberIds, org: org.agent };
}

const draw = async (a: Agent, id: string) => (await a.get(`/api/circles/${id}/draw`)).json() as DrawView;
const types = (t: TestApp, id: string) => listLedger(t.db, id).map((e) => e.type);
const actions = (t: TestApp, id: string) =>
  (t.db.prepare('SELECT action FROM audit WHERE circle_id = ? ORDER BY id').all(id) as { action: string }[]).map((r) => r.action);

describe('draw: open', () => {
  it('needs the organizer, a draft, two members and deadlines at least an hour apart', async () => {
    const t = testApp();
    const org = await fixtureUser(t, 'org');
    const id = await createCircle(org.agent, 'Solo', { startDate: addDays(isoDateOf(t.clock.now()), 3) });
    const now = t.clock.now().getTime();
    expect(err(await org.agent.post(`/api/circles/${id}/draw/open`, drawDeadlines(t.clock.now()))).code).toBe('too_few_members');
    const p = await party(3);
    const at = (ms: number) => new Date(p.t.clock.now().getTime() + ms).toISOString();
    const open = (body: unknown) => p.org.post(`/api/circles/${p.circleId}/draw/open`, body);
    expect(err(await open({ commitDeadline: at(30 * 60 * 1000), revealDeadline: at(3 * HOUR) })).code).toBe('deadline_too_soon');
    expect(err(await open({ commitDeadline: at(2 * HOUR), revealDeadline: at(2.5 * HOUR) })).code).toBe('deadline_too_soon');
    expect(err(await open({ commitDeadline: at(2 * HOUR), revealDeadline: at(31 * 24 * HOUR) })).code).toBe('deadline_too_far');
    expect(err(await open({ commitDeadline: 'tomorrow', revealDeadline: at(5 * HOUR) })).code).toBe('invalid_input');
    expect(err(await open({ commitDeadline: '2026-10-17T12:00:00', revealDeadline: at(5 * HOUR) })).code).toBe('invalid_input');
    expect((await p.agents[1]?.post(`/api/circles/${p.circleId}/draw/open`, drawDeadlines(p.t.clock.now())))?.statusCode).toBe(403);
    // A manual order set before is cleared by the draw.
    await p.org.post(`/api/circles/${p.circleId}/order`, { order: p.memberIds });
    const ok = await open(drawDeadlines(p.t.clock.now()));
    expect(ok.statusCode).toBe(200);
    const entry = listLedger(p.t.db, p.circleId).at(-1);
    expect(entry).toMatchObject({ type: 'draw.opened', payload: { members: [...p.memberIds].sort(), orderCleared: true } });
    const v = (await p.org.get(`/api/circles/${p.circleId}`)).json() as { circle: { status: string }; members: { position: number | null }[] };
    expect(v.circle.status).toBe('drawing');
    expect(v.members.every((m) => m.position === null)).toBe(true);
    expect(err(await open(drawDeadlines(p.t.clock.now()))).code).toBe('circle_not_draft');
    expect(now).toBeGreaterThan(0);
  });

  it('freezes the member set: join, leave and manual order are refused while drawing; cancel is allowed', async () => {
    const p = await party(2);
    const late = await invite(p.org, p.circleId);
    await p.org.post(`/api/circles/${p.circleId}/draw/open`, drawDeadlines(p.t.clock.now()));
    const outsider = await fixtureUser(p.t, 'late.comer');
    expect(err(await outsider.agent.post(`/api/invites/${late.token}/accept`)).code).toBe('circle_closed_to_members');
    expect(err(await (p.agents[1] as Agent).post(`/api/circles/${p.circleId}/leave`)).code).toBe('circle_not_draft');
    expect(err(await p.org.post(`/api/circles/${p.circleId}/order`, { order: p.memberIds })).code).toBe('circle_not_draft');
    expect(err(await p.org.post(`/api/circles/${p.circleId}/invites`)).code).toBe('circle_not_draft');
    expect((await p.org.post(`/api/circles/${p.circleId}/cancel`, { reason: 'changed our minds' })).statusCode).toBe(200);
    expect(err(await (p.agents[1] as Agent).post(`/api/circles/${p.circleId}/draw/commit`, { commitment: 'a'.repeat(64) })).code).toBe(
      'circle_not_drawing',
    );
  });
});

describe('draw: commit, close, reveal, finalize', () => {
  it('runs a full draw; only hashes enter the ledger until reveals; the order is set and start uses it', async () => {
    const p = await party(3);
    const { t, circleId, agents, memberIds } = p;
    await p.org.post(`/api/circles/${circleId}/draw/open`, drawDeadlines(t.clock.now()));
    const secrets = memberIds.map(() => newSecret());

    expect(err(await p.org.post(`/api/circles/${circleId}/draw/reveal`, { secret: secrets[0] })).code).toBe('commits_open');
    for (let i = 0; i < 3; i += 1) {
      const res = await (agents[i] as Agent).post(`/api/circles/${circleId}/draw/commit`, {
        commitment: commit(secrets[i] as string, memberIds[i] as string, sha256Hex),
      });
      expect(res.statusCode).toBe(200);
      if (i === 0) {
        expect(err(await p.org.post(`/api/circles/${circleId}/draw/close-commits`)).code).toBe('commits_pending');
      }
    }
    expect(err(await (agents[1] as Agent).post(`/api/circles/${circleId}/draw/commit`, { commitment: 'b'.repeat(64) })).code).toBe(
      'already_committed',
    );
    expect(err(await (agents[1] as Agent).post(`/api/circles/${circleId}/draw/commit`, { commitment: 'XYZ' })).code).toBe('invalid_input');
    const ledgerText = JSON.stringify(listLedger(t.db, circleId));
    for (const s of secrets) expect(ledgerText).not.toContain(s);

    const before = await draw(agents[2] as Agent, circleId);
    expect(before.draw).toMatchObject({ phase: 'committing', committedCount: 3, revealedCount: 0, result: null, mine: { committed: true } });
    expect((await (agents[1] as Agent).post(`/api/circles/${circleId}/draw/close-commits`)).statusCode).toBe(403);
    expect((await p.org.post(`/api/circles/${circleId}/draw/close-commits`)).statusCode).toBe(200);
    expect(err(await (agents[1] as Agent).post(`/api/circles/${circleId}/draw/commit`, { commitment: 'c'.repeat(64) })).code).toBe(
      'commits_closed',
    );

    const wrong = await (agents[1] as Agent).post(`/api/circles/${circleId}/draw/reveal`, { secret: secrets[2] });
    expect(wrong.statusCode).toBe(400);
    expect(err(wrong).code).toBe('wrong_secret');
    expect(actions(t, circleId)).toContain('draw.reveal_refused');
    for (let i = 0; i < 3; i += 1) {
      expect((await (agents[i] as Agent).post(`/api/circles/${circleId}/draw/reveal`, { secret: secrets[i] })).statusCode).toBe(200);
    }
    expect(err(await (agents[0] as Agent).post(`/api/circles/${circleId}/draw/reveal`, { secret: secrets[0] })).code).toBe('already_revealed');

    const fin = await p.org.post(`/api/circles/${circleId}/draw/finalize`);
    expect(fin.statusCode).toBe(200);
    const result = (fin.json() as DrawView).draw?.result;
    expect(result?.silent).toEqual([]);
    expect([...(result?.order ?? [])].sort()).toEqual([...memberIds].sort());
    expect(result?.reveals).toHaveLength(3);
    const entry = listLedger(t.db, circleId).at(-1);
    expect(entry).toMatchObject({ type: 'draw.finalized', payload: { seed: result?.seed, order: result?.order, silent: [] } });
    expect(err(await p.org.post(`/api/circles/${circleId}/draw/finalize`)).code).toBe('draw_finalized');

    const v = (await p.org.get(`/api/circles/${circleId}`)).json() as {
      circle: { status: string };
      members: { id: string; position: number }[];
      startCheck: { ok: boolean; code?: string };
    };
    expect(v.circle.status).toBe('drawing');
    for (const [i, m] of (result?.order ?? []).entries()) expect(v.members.find((x) => x.id === m)?.position).toBe(i + 1);
    expect(v.startCheck).toEqual({ ok: true });
    expect(err(await p.org.patch(`/api/circles/${circleId}`, { rulesText: 'x' })).code).toBe('circle_not_draft');
    const started = await p.org.post(`/api/circles/${circleId}/start`);
    expect(started.statusCode, started.body).toBe(200);
    const rounds = (started.json() as { rounds: { recipientMemberId: string }[] }).rounds;
    expect(rounds.map((r) => r.recipientMemberId)).toEqual(result?.order);
    expect(types(t, circleId)).toEqual([
      'circle.created',
      'member.joined',
      'member.joined',
      'member.joined',
      'draw.opened',
      'draw.committed',
      'draw.committed',
      'draw.committed',
      'draw.commits_closed',
      'draw.revealed',
      'draw.revealed',
      'draw.revealed',
      'draw.finalized',
      'circle.started',
    ]);
    expect(verify(listLedger(t.db, circleId), sha256Hex).ok).toBe(true);
  });

  it('the draw needs a start date on or after the reveal deadline; while drawing only the start date may move', async () => {
    const t = testApp();
    const org = await fixtureUser(t, 'org2');
    const b = await fixtureUser(t, 'bee2');
    const id = await createCircle(org.agent, 'No date');
    await join(b.agent, (await invite(org.agent, id)).token);
    const open = () => org.agent.post(`/api/circles/${id}/draw/open`, drawDeadlines(t.clock.now()));
    expect(err(await open()).code).toBe('no_start_date');
    await org.agent.patch(`/api/circles/${id}`, { startDate: isoDateOf(new Date(t.clock.now().getTime() - 0)) });
    const late = { commitDeadline: new Date(t.clock.now().getTime() + 30 * HOUR).toISOString(), revealDeadline: new Date(t.clock.now().getTime() + 60 * HOUR).toISOString() };
    expect(err(await org.agent.post(`/api/circles/${id}/draw/open`, late)).code).toBe('start_before_draw_ends');
    await org.agent.patch(`/api/circles/${id}`, { startDate: addDays(isoDateOf(t.clock.now()), 4) });
    expect((await org.agent.post(`/api/circles/${id}/draw/open`, late)).statusCode).toBe(200);
    expect(err(await org.agent.patch(`/api/circles/${id}`, { contribution: 1 })).code).toBe('circle_not_draft');
    expect(err(await org.agent.patch(`/api/circles/${id}`, { startDate: addDays(isoDateOf(t.clock.now()), 6), rulesText: 'x' })).code).toBe('circle_not_draft');
    expect(err(await org.agent.patch(`/api/circles/${id}`, { startDate: null })).code).toBe('start_date_required');
    const moved = await org.agent.patch(`/api/circles/${id}`, { startDate: addDays(isoDateOf(t.clock.now()), 6) });
    expect(moved.statusCode).toBe(200);
    expect(listLedger(t.db, id).at(-1)).toMatchObject({ type: 'circle.rule_changed', payload: { field: 'startDate' } });
    expect(err(await b.agent.patch(`/api/circles/${id}`, { startDate: addDays(isoDateOf(t.clock.now()), 7) })).code).toBe('forbidden');
  });
});

describe('draw: silence is visible (A5)', () => {
  it('commitments close by themselves at the deadline; a non-committer cannot reveal; a silent revealer is placed last', async () => {
    const p = await party(4);
    const { t, circleId, agents, memberIds } = p;
    await p.org.post(`/api/circles/${circleId}/draw/open`, drawDeadlines(t.clock.now()));
    const secrets = memberIds.map(() => newSecret());
    // Members 0, 1, 2 commit; member 3 never does.
    for (let i = 0; i < 3; i += 1) {
      await (agents[i] as Agent).post(`/api/circles/${circleId}/draw/commit`, {
        commitment: commit(secrets[i] as string, memberIds[i] as string, sha256Hex),
      });
    }
    t.clock.advance(2 * HOUR + 1000);
    const lengthBefore = listLedger(t.db, circleId).length;
    const seen = await draw(agents[3] as Agent, circleId);
    expect(seen.draw?.phase).toBe('revealing');
    expect(listLedger(t.db, circleId)).toHaveLength(lengthBefore); // GET wrote nothing

    const late = await (agents[3] as Agent).post(`/api/circles/${circleId}/draw/commit`, {
      commitment: commit(secrets[3] as string, memberIds[3] as string, sha256Hex),
    });
    expect(err(late).code).toBe('commits_closed');
    const closed = listLedger(t.db, circleId).at(-1);
    expect(closed).toMatchObject({ type: 'draw.commits_closed', actor: 'system', payload: { automatic: true, notCommitted: [memberIds[3]] } });

    expect(err(await (agents[3] as Agent).post(`/api/circles/${circleId}/draw/reveal`, { secret: secrets[3] })).code).toBe('not_committed');
    // Members 0 and 2 reveal; member 1 stays silent.
    await (agents[0] as Agent).post(`/api/circles/${circleId}/draw/reveal`, { secret: secrets[0] });
    await (agents[2] as Agent).post(`/api/circles/${circleId}/draw/reveal`, { secret: secrets[2] });
    expect(err(await p.org.post(`/api/circles/${circleId}/draw/finalize`)).code).toBe('reveals_pending');
    t.clock.advance(2 * HOUR);
    expect(err(await (agents[1] as Agent).post(`/api/circles/${circleId}/draw/reveal`, { secret: secrets[1] })).code).toBe('reveals_closed');
    const fin = await p.org.post(`/api/circles/${circleId}/draw/finalize`);
    expect(fin.statusCode).toBe(200);
    const result = (fin.json() as DrawView).draw?.result;
    const silent = [memberIds[1], memberIds[3]].sort() as string[];
    expect(result?.silent).toEqual(silent);
    expect(result?.notCommitted).toEqual([memberIds[3]]);
    expect(result?.order.slice(2)).toEqual(silent);
    expect(listLedger(t.db, circleId).at(-1)?.payload).toMatchObject({ silent, notCommitted: [memberIds[3]], rule: expect.stringContaining('last') });
  });
});

describe('draw: determinism', () => {
  it('two servers given the same ledger compute the same order, and so does the browser code', async () => {
    const p = await party(5);
    const { t, circleId, agents, memberIds } = p;
    await p.org.post(`/api/circles/${circleId}/draw/open`, drawDeadlines(t.clock.now()));
    const secrets = memberIds.map(() => newSecret());
    for (let i = 0; i < 5; i += 1) {
      await (agents[i] as Agent).post(`/api/circles/${circleId}/draw/commit`, {
        commitment: commit(secrets[i] as string, memberIds[i] as string, sha256Hex),
      });
    }
    await p.org.post(`/api/circles/${circleId}/draw/close-commits`);
    for (let i = 0; i < 4; i += 1) await (agents[i] as Agent).post(`/api/circles/${circleId}/draw/reveal`, { secret: secrets[i] });
    t.clock.advance(5 * HOUR);
    const fin = (await p.org.post(`/api/circles/${circleId}/draw/finalize`)).json() as DrawView;
    const serverOne = fin.draw?.result;

    // A second, independent server: a fresh database holding only a copy of the ledger rows.
    const db2 = openDb(':memory:');
    migrate(db2);
    const now = new Date().toISOString();
    db2.prepare("INSERT INTO users (id, login, display_name, password_hash, password_changed_at, created_at) VALUES ('u', 'u', 'u', 'x', ?, ?)").run(now, now);
    db2
      .prepare("INSERT INTO circles (id, name, currency, minor_unit, contribution, period, due_day, created_by, created_at) VALUES (?, 'copy', 'OMR', 3, 1, 'monthly', 1, 'u', ?)")
      .run(circleId, now);
    const rows = t.db.prepare('SELECT circle_id, seq, ts, actor, type, payload, prev_hash, hash, created_at FROM ledger WHERE circle_id = ? ORDER BY seq').all(circleId);
    const insert = db2.prepare(
      'INSERT INTO ledger (circle_id, seq, ts, actor, type, payload, prev_hash, hash, created_at) VALUES (@circle_id, @seq, @ts, @actor, @type, @payload, @prev_hash, @hash, @created_at)',
    );
    for (const r of rows) insert.run(r);
    expect(verify(listLedger(db2, circleId), sha256Hex).ok).toBe(true);
    const state2 = loadDraw(db2, circleId);
    const serverTwo = computeResult(circleId, state2 as NonNullable<typeof state2>);
    expect(serverTwo.order).toEqual(serverOne?.order);
    expect(serverTwo.seed).toEqual(serverOne?.seed);
    expect(serverTwo.silent).toEqual([memberIds[4]]);

    const browser = await finalizeAsync(
      circleId,
      serverOne?.members as string[],
      new Map((serverOne?.reveals ?? []).map((r) => [r.memberId, r.secret])),
      webSha256Hex,
    );
    expect(browser.order).toEqual(serverOne?.order);
    expect(browser.seed).toEqual(serverOne?.seed);
  });
});
