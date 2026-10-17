import { expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { commit } from '../../shared/lottery.js';
import { addDays, isoDateOf } from '../../shared/schedule.js';
import { sha256Hex } from '../../server/crypto.js';
import { fixtureUser, testApp, type Agent, type FixtureUser, type TestApp } from './helpers.js';

/**
 * The fixture of the authorization matrix (S3): four people; circle A
 * (organized by organizerA, joined by memberA) and circle B (organized by
 * organizerB, joined by memberB). Every matrix request targets circle A or
 * organizerA's own objects; the roles vary.
 */
export type Role = 'anonymous' | 'memberA' | 'organizerA' | 'memberB';
export const ROLES: readonly Role[] = ['anonymous', 'memberA', 'organizerA', 'memberB'];
export type Person = Exclude<Role, 'anonymous'> | 'organizerB';

/**
 * base:    people only.
 * draft:   circles A and B exist in draft, each with its two members, and
 *          circle A has one open invite (ids.inviteA, ids.inviteTokenA).
 * ordered: as draft, with a start date and a manual order on both circles.
 * active:  as ordered, both circles started.
 * drawing:   as draft, with a draw open in both circles (commitments open).
 * committed: as drawing, every member of both circles committed; their
 *            secrets are in ids['secret:<memberId>'].
 * revealing: as committed, commitments closed by the organizers.
 * revealed:  as revealing, every member revealed.
 * finalized: as revealed, both draws finalized (circles still drawing).
 * round-open: as active, round 1 open in both circles. In both circles the
 *            organizer holds position 1 (recipient of round 1); ids.cidA is
 *            memberA's contribution id for round 1 of circle A.
 * reported:  as round-open, memberA reported 25.000 in A, memberB in B.
 * paid-out:  as round-open, the organizers recorded the round-1 payouts.
 */
export type WorldState =
  | 'base'
  | 'draft'
  | 'ordered'
  | 'active'
  | 'drawing'
  | 'committed'
  | 'revealing'
  | 'revealed'
  | 'finalized'
  | 'round-open'
  | 'reported'
  | 'paid-out';
const DRAW_STATES: readonly WorldState[] = ['drawing', 'committed', 'revealing', 'revealed', 'finalized'];

const HOUR = 60 * 60 * 1000;
export function drawDeadlines(now: Date): { commitDeadline: string; revealDeadline: string } {
  return {
    commitDeadline: new Date(now.getTime() + 2 * HOUR).toISOString(),
    revealDeadline: new Date(now.getTime() + 4 * HOUR).toISOString(),
  };
}

export function newSecret(): string {
  return randomBytes(32).toString('hex');
}

export interface World {
  t: TestApp;
  people: Record<Person, FixtureUser>;
  ids: Record<string, string>;
}

async function ok(res: Promise<{ statusCode: number; body: string }>, status = 200): Promise<unknown> {
  const r = await res;
  expect(r.statusCode, r.body).toBe(status);
  return JSON.parse(r.body) as unknown;
}

export const CIRCLE_INPUT = {
  currency: 'OMR',
  contribution: 50_000,
  period: 'monthly',
  dueDay: 5,
  rulesText: 'Pay by the 5th. Cash or bank transfer to the organizer.',
};

export async function createCircle(organizer: Agent, name: string, extra: Record<string, unknown> = {}): Promise<string> {
  const body = (await ok(organizer.post('/api/circles', { ...CIRCLE_INPUT, name, ...extra }), 201)) as { circle: { id: string } };
  return body.circle.id;
}

export async function invite(organizer: Agent, circleId: string): Promise<{ id: string; token: string }> {
  const body = (await ok(organizer.post(`/api/circles/${circleId}/invites`), 201)) as { invite: { id: string }; token: string };
  return { id: body.invite.id, token: body.token };
}

export async function join(member: Agent, token: string): Promise<string> {
  const body = (await ok(member.post(`/api/invites/${token}/accept`, {}))) as { memberId: string };
  return body.memberId;
}

export async function memberIds(agent: Agent, circleId: string): Promise<string[]> {
  const body = (await ok(agent.get(`/api/circles/${circleId}`))) as { members: { id: string }[] };
  return body.members.map((m) => m.id);
}

export async function buildWorld(state: WorldState = 'base'): Promise<World> {
  const t = testApp();
  const people = {
    organizerA: await fixtureUser(t, 'alice', 'Alice', '198.51.100.1'),
    memberA: await fixtureUser(t, 'bob', 'Bob', '198.51.100.2'),
    memberB: await fixtureUser(t, 'carol', 'Carol', '198.51.100.3'),
    organizerB: await fixtureUser(t, 'dan', 'Dan', '198.51.100.4'),
  };
  const ids: Record<string, string> = {};
  const w: World = { t, people, ids };
  if (state === 'base') return w;

  const startDate = state === 'draft' ? undefined : addDays(isoDateOf(t.clock.now()), 3);
  ids.circleA = await createCircle(people.organizerA.agent, 'Circle A');
  ids.circleB = await createCircle(people.organizerB.agent, 'Circle B');
  ids.memberAInA = await join(people.memberA.agent, (await invite(people.organizerA.agent, ids.circleA)).token);
  ids.memberBInB = await join(people.memberB.agent, (await invite(people.organizerB.agent, ids.circleB)).token);
  ids.organizerAInA = (await memberIds(people.organizerA.agent, ids.circleA)).find((m) => m !== ids.memberAInA) as string;
  const open = await invite(people.organizerA.agent, ids.circleA);
  ids.inviteA = open.id;
  ids.inviteTokenA = open.token;
  if (state === 'draft') return w;
  if (DRAW_STATES.includes(state)) {
    await runDraw(w, state);
    return w;
  }

  const organizerBInB = (await memberIds(people.organizerB.agent, ids.circleB)).find((m) => m !== ids.memberBInB) as string;
  for (const [org, circle, order] of [
    [people.organizerA.agent, ids.circleA, [ids.organizerAInA, ids.memberAInA]],
    [people.organizerB.agent, ids.circleB, [organizerBInB, ids.memberBInB]],
  ] as const) {
    await ok(org.patch(`/api/circles/${circle}`, { startDate }));
    await ok(org.post(`/api/circles/${circle}/order`, { order }));
  }
  if (state === 'ordered') return w;

  await ok(people.organizerA.agent.post(`/api/circles/${ids.circleA}/start`));
  await ok(people.organizerB.agent.post(`/api/circles/${ids.circleB}/start`));
  if (state === 'active') return w;

  await ok(people.organizerA.agent.post(`/api/circles/${ids.circleA}/rounds/1/open`));
  await ok(people.organizerB.agent.post(`/api/circles/${ids.circleB}/rounds/1/open`));
  const overview = (await ok(people.organizerA.agent.get(`/api/circles/${ids.circleA}/overview`))) as {
    round: { members: { memberId: string; contributionId: string }[] };
  };
  ids.cidA = overview.round.members.find((m) => m.memberId === ids.memberAInA)?.contributionId as string;
  if (state === 'reported') {
    await ok(people.memberA.agent.post(`/api/circles/${ids.circleA}/rounds/1/contributions`, { amount: 25_000, method: 'cash' }), 201);
    await ok(people.memberB.agent.post(`/api/circles/${ids.circleB}/rounds/1/contributions`, { amount: 25_000, method: 'cash' }), 201);
  }
  if (state === 'paid-out') {
    await ok(people.organizerA.agent.post(`/api/circles/${ids.circleA}/rounds/1/payout`, { amount: 100_000 }), 201);
    await ok(people.organizerB.agent.post(`/api/circles/${ids.circleB}/rounds/1/payout`, { amount: 100_000 }), 201);
  }
  return w;
}

async function runDraw(w: World, state: WorldState): Promise<void> {
  const { people, ids } = w;
  const circles = [
    { id: ids.circleA as string, org: people.organizerA.agent, all: [people.organizerA.agent, people.memberA.agent] },
    { id: ids.circleB as string, org: people.organizerB.agent, all: [people.organizerB.agent, people.memberB.agent] },
  ];
  const startDate = addDays(isoDateOf(w.t.clock.now()), 3);
  for (const c of circles) {
    await ok(c.org.patch(`/api/circles/${c.id}`, { startDate }));
    await ok(c.org.post(`/api/circles/${c.id}/draw/open`, drawDeadlines(w.t.clock.now())));
  }
  if (state === 'drawing') return;
  for (const c of circles) {
    for (const agent of c.all) {
      const view = (await ok(agent.get(`/api/circles/${c.id}`))) as { me: { memberId: string } };
      const secret = newSecret();
      ids[`secret:${view.me.memberId}`] = secret;
      await ok(agent.post(`/api/circles/${c.id}/draw/commit`, { commitment: commit(secret, view.me.memberId, sha256Hex) }));
    }
  }
  if (state === 'committed') return;
  for (const c of circles) await ok(c.org.post(`/api/circles/${c.id}/draw/close-commits`));
  if (state === 'revealing') return;
  for (const c of circles) {
    for (const agent of c.all) {
      const view = (await ok(agent.get(`/api/circles/${c.id}`))) as { me: { memberId: string } };
      await ok(agent.post(`/api/circles/${c.id}/draw/reveal`, { secret: ids[`secret:${view.me.memberId}`] }));
    }
  }
  if (state === 'revealed') return;
  for (const c of circles) await ok(c.org.post(`/api/circles/${c.id}/draw/finalize`));
}
