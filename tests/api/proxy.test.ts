import { describe, expect, it } from 'vitest';
import { auditByRequest } from '../../server/audit.js';
import { anonymousAgent, testApp } from './helpers.js';

/** The address used for rate limits and audit, with and without TRUST_PROXY=1. */
async function seenAddress(trustProxy: boolean, forwardedFor: string | undefined): Promise<string> {
  const t = testApp({ config: { trustProxy } });
  const a = await anonymousAgent(t, '203.0.113.9');
  const headers: Record<string, string> = forwardedFor ? { 'x-forwarded-for': forwardedFor } : {};
  const res = await a.post('/api/auth/login', { login: 'nobody', password: 'not the password' }, headers);
  const rows = auditByRequest(t.db, res.headers['x-request-id'] as string);
  await t.app.close();
  return rows[0]?.ipPrefix ?? 'none';
}

describe('deployment: client address behind the reverse proxy', () => {
  it('without TRUST_PROXY, X-Forwarded-For is ignored (the socket address counts)', async () => {
    expect(await seenAddress(false, '198.51.100.7')).toBe('203.0.113.0/24');
  });

  it('with TRUST_PROXY=1, only the immediate hop is trusted: a client cannot choose its address', async () => {
    // The proxy appends what it saw; anything the client put before that is ignored.
    expect(await seenAddress(true, '198.51.100.7')).toBe('198.51.100.0/24');
    expect(await seenAddress(true, '192.0.2.66, 198.51.100.7')).toBe('198.51.100.0/24');
    expect(await seenAddress(true, undefined)).toBe('203.0.113.0/24');
  });
});
