import type { AppOptions } from '../../server/app.js';
import { MATRIX } from './authz.matrix.js';
import { PASSWORD, anonymousAgent, type Agent } from './helpers.js';
import { ROLES, buildWorld } from './world.js';

export interface TourResult {
  requests: number;
  /** Every secret value seen during the tour: passwords, session tokens, CSRF and invite tokens, recovery codes, draw secrets. */
  secrets: Set<string>;
}

function collect(secrets: Set<string>, value: unknown): void {
  if (typeof value === 'string' && value.length >= 10) secrets.add(value);
  else if (Array.isArray(value)) for (const v of value) collect(secrets, v);
}

/**
 * The full API tour: every route of the authorization matrix, for every
 * role, each against a fresh world built with the given app options.
 */
export async function runTour(options: Partial<AppOptions> = {}): Promise<TourResult> {
  const secrets = new Set<string>([PASSWORD, 'a fresh passphrase 2026', 'a recovered passphrase 7']);
  let requests = 0;
  for (const row of MATRIX) {
    for (const role of ROLES) {
      const w = await buildWorld(row.state ?? 'base', options);
      const agent: Agent = role === 'anonymous' ? await anonymousAgent(w.t, '192.0.2.50') : w.people[role].agent;
      for (const p of Object.values(w.people)) {
        for (const v of p.agent.cookies.values()) collect(secrets, v);
        collect(secrets, p.agent.csrf);
        collect(secrets, p.recoveryCodes);
      }
      for (const [k, v] of Object.entries(w.ids)) if (k.startsWith('secret:') || k === 'inviteTokenA') collect(secrets, v);
      const req = row.build ? row.build(w, role) : {};
      const res = await agent.request(row.method, req.url ?? row.route, row.method === 'GET' ? undefined : (req.body ?? {}));
      requests += 1;
      if (res.headers['content-type']?.toString().includes('json')) {
        const body = res.json() as Record<string, unknown>;
        for (const k of ['csrfToken', 'token', 'recoveryCodes']) collect(secrets, body[k]);
      }
      if (req.body && typeof req.body === 'object') {
        for (const [k, v] of Object.entries(req.body as Record<string, unknown>)) {
          if (/password|secret|recoveryCode/i.test(k)) collect(secrets, v);
        }
      }
      for (const v of agent.cookies.values()) collect(secrets, v);
      await w.t.app.close();
    }
  }
  return { requests, secrets };
}
