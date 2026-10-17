import { describe, expect, it } from 'vitest';
import { auditByRequest } from '../../server/audit.js';
import { MATRIX } from './authz.matrix.js';
import { anonymousAgent, testApp } from './helpers.js';
import { ROLES, buildWorld } from './world.js';

describe('S6.1 audit.coverage', () => {
  it('every mutating route writes an audit row carrying its request id', async () => {
    const missing: string[] = [];
    const toured: string[] = [];
    for (const row of MATRIX.filter((r) => r.method !== 'GET')) {
      const role = ROLES.find((x) => row.expect[x] >= 200 && row.expect[x] < 300);
      if (!role) {
        missing.push(`${row.method} ${row.route}: no role succeeds in the matrix`);
        continue;
      }
      const w = await buildWorld(row.state ?? 'base');
      const agent = role === 'anonymous' ? await anonymousAgent(w.t, '192.0.2.77') : w.people[role].agent;
      const req = row.build ? row.build(w, role) : {};
      const res = await agent.request(row.method, req.url ?? row.route, req.body ?? {});
      expect(res.statusCode, `${row.method} ${row.route}: ${res.body}`).toBe(row.expect[role]);
      const requestId = res.headers['x-request-id'] as string;
      const rows = auditByRequest(w.t.db, requestId);
      if (rows.length === 0) missing.push(`${row.method} ${row.route}`);
      for (const a of rows) {
        expect(a.ipPrefix).toMatch(/\/(24|48)$/);
        expect(a.uaHash).toMatch(/^[0-9a-f]{16}$/);
        expect(a.action).toMatch(/^[a-z_]+\.[a-z_]+$/);
      }
      toured.push(`${row.method} ${row.route}`);
      await w.t.app.close();
    }
    expect(missing).toEqual([]);

    // The tour covered every mutating route the server registers.
    const { app } = testApp();
    await app.ready();
    const mutating = app.routeTable.filter((r) => r.method !== 'GET').map((r) => `${r.method} ${r.url}`);
    expect([...mutating].sort()).toEqual([...toured].sort());
    await app.close();
  }, 300_000);
});
