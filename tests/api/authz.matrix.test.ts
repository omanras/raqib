import { describe, expect, it } from 'vitest';
import { MATRIX } from './authz.matrix.js';
import { anonymousAgent, testApp } from './helpers.js';
import { ROLES, buildWorld } from './world.js';

describe('S3 authz.matrix', () => {
  it('S3.1 S3.2 authz.matrix: every route x role gets its expected status', async () => {
    const failures: string[] = [];
    for (const row of MATRIX) {
      for (const role of ROLES) {
        const w = await buildWorld(row.state ?? 'base');
        const agent = role === 'anonymous' ? await anonymousAgent(w.t, '192.0.2.99') : w.people[role].agent;
        const req = row.build ? row.build(w, role) : {};
        const url = req.url ?? row.route;
        const res = await agent.request(row.method, url, row.method === 'GET' ? undefined : (req.body ?? {}));
        const want = row.expect[role];
        if (res.statusCode !== want) {
          failures.push(`${row.method} ${row.route} as ${role}: expected ${want}, got ${res.statusCode} ${res.body.slice(0, 160)}`);
        }
        await w.t.app.close();
      }
    }
    expect(failures).toEqual([]);
  }, 300_000);

  it('S3.1 authz.coverage: every registered route has a matrix row (and every row a route)', async () => {
    const { app } = testApp();
    await app.ready();
    const registered = new Set(app.routeTable.map((r) => `${r.method} ${r.url}`));
    const listed = new Set(MATRIX.map((r) => `${r.method} ${r.route}`));
    const missing = [...registered].filter((r) => !listed.has(r)).sort();
    const stale = [...listed].filter((r) => !registered.has(r)).sort();
    expect(missing, 'routes without a matrix row').toEqual([]);
    expect(stale, 'matrix rows without a route').toEqual([]);
    expect(MATRIX.length).toBe(listed.size);
    await app.close();
  });
});
