import type { FastifyInstance } from 'fastify';
import { migrationCount, stmt } from '../db/db.js';
import { appVersion } from '../version.js';

/** `GET /api/health`: no auth; version, database state and applied migrations. */
export function healthRoutes(api: FastifyInstance): void {
  api.get('/health', async (req, reply) => {
    try {
      stmt(api.db, 'SELECT 1').get();
      return { ok: true, version: appVersion(), db: 'ok' as const, migrations: migrationCount(api.db) };
    } catch (err) {
      req.log.error({ err }, 'health: database check failed');
      return reply.status(503).send({ ok: false, version: appVersion(), db: 'error' as const, migrations: 0 });
    }
  });
}
