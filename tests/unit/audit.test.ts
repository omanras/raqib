import { describe, expect, it } from 'vitest';
import { buildApp } from '../../server/app.js';
import { audit, auditByRequest, ipPrefix, listAudit, uaHash } from '../../server/audit.js';
import { migrate, openDb } from '../../server/db/db.js';
import { createLogger } from '../../server/logging.js';
import { Agent } from '../api/helpers.js';
import { seedCircle } from './support/fixtures.js';

describe('audit.ipPrefix', () => {
  it('truncates IPv4 to /24 and IPv6 to /48', () => {
    expect(ipPrefix('203.0.113.77')).toBe('203.0.113.0/24');
    expect(ipPrefix('127.0.0.1')).toBe('127.0.0.0/24');
    expect(ipPrefix('::ffff:198.51.100.9')).toBe('198.51.100.0/24');
    expect(ipPrefix('2001:db8:abcd:12:3456::1')).toBe('2001:db8:abcd::/48');
    expect(ipPrefix('2001:0db8:0000:0042:0000:8a2e:0370:7334')).toBe('2001:db8:0::/48');
    expect(ipPrefix('::1')).toBe('0:0:0::/48');
    expect(ipPrefix('fe80::1%eth0')).toBe('fe80:0:0::/48');
    expect(ipPrefix('not an ip')).toBe('unknown');
    expect(ipPrefix(undefined)).toBe('unknown');
  });

  it('hashes the user agent with a key, never storing it', () => {
    const a = uaHash('secret-one', 'Mozilla/5.0');
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(uaHash('secret-one', 'Mozilla/5.0')).toBe(a);
    expect(uaHash('secret-two', 'Mozilla/5.0')).not.toBe(a);
    expect(uaHash('secret-one', 'curl/8')).not.toBe(a);
  });
});

describe('audit(req, {...})', () => {
  it('writes actor, circle, action, target, request id, ip prefix and ua hash', async () => {
    const db = openDb(':memory:');
    migrate(db);
    const { userId, circleId } = seedCircle(db);
    const app = buildApp({ logger: createLogger({ level: 'silent' }), db, clientDir: false, config: { sessionSecret: 'k'.repeat(40) } });
    app.post('/api/test-audit', async (req) => {
      req.user = { id: userId, login: 'organizer', displayName: 'Organizer', sessionId: 's', sessionTokenHash: 'h' };
      audit(req, { circleId, action: 'circle.rule_changed', target: 'rules_text', details: { field: 'rules_text' } });
      return { ok: true };
    });
    const agent = new Agent(app, '203.0.113.77');
    agent.ua = 'Mozilla/5.0 (test)';
    await agent.refreshCsrf();
    const res = await agent.post('/api/test-audit', {});
    expect(res.statusCode).toBe(200);
    const requestId = res.headers['x-request-id'] as string;
    const rows = auditByRequest(db, requestId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      actorId: userId,
      circleId,
      action: 'circle.rule_changed',
      target: 'rules_text',
      requestId,
      ipPrefix: '203.0.113.0/24',
      uaHash: uaHash('k'.repeat(40), 'Mozilla/5.0 (test)'),
      details: { field: 'rules_text' },
    });
    expect(JSON.stringify(rows)).not.toContain('203.0.113.77');
    expect(JSON.stringify(rows)).not.toContain('Mozilla');
    expect(listAudit(db, circleId, 10)).toHaveLength(1);
    await app.close();
  });
});
