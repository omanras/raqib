import { fixtureUser, testApp, type FixtureUser, type TestApp } from './helpers.js';

/**
 * The fixture of the authorization matrix (S3): four people and, as the
 * circle routes arrive, circle A (organized by organizerA, joined by
 * memberA) and circle B (organized by organizerB, joined by memberB).
 * Every matrix request targets circle A or organizerA's own objects; the
 * roles vary.
 */
export type Role = 'anonymous' | 'memberA' | 'organizerA' | 'memberB';
export const ROLES: readonly Role[] = ['anonymous', 'memberA', 'organizerA', 'memberB'];
export type Person = Exclude<Role, 'anonymous'> | 'organizerB';

/** States the world can be built in; later tasks add circle states. */
export type WorldState = 'base';

export interface World {
  t: TestApp;
  people: Record<Person, FixtureUser>;
  /** Filled in by later tasks (circle ids, round numbers, invite tokens...). */
  ids: Record<string, string>;
}

export async function buildWorld(_state: WorldState = 'base'): Promise<World> {
  const t = testApp();
  const people = {
    organizerA: await fixtureUser(t, 'alice', 'Alice', '198.51.100.1'),
    memberA: await fixtureUser(t, 'bob', 'Bob', '198.51.100.2'),
    memberB: await fixtureUser(t, 'carol', 'Carol', '198.51.100.3'),
    organizerB: await fixtureUser(t, 'dan', 'Dan', '198.51.100.4'),
  };
  return { t, people, ids: {} };
}
