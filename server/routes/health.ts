import type { FastifyInstance } from 'fastify';
import { appVersion } from '../version.js';

/** `GET /api/health`: no auth; version and database state. */
export function healthRoutes(api: FastifyInstance): void {
  api.get('/health', async () => ({ ok: true, version: appVersion(), db: 'pending' as const }));
}
