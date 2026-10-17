import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MATRIX } from './authz.matrix.js';
import { runTour } from './tour.js';
import { ROLES } from './world.js';

/**
 * S5.3 egress.none: Dawr makes no outbound network calls (A7). Every way out
 * a Node process has (fetch, DNS, raw sockets, TLS, http/https clients) is
 * stubbed to record and refuse, then the full API tour runs; nothing may be
 * called. The gate's grep checks the source; this checks the behaviour,
 * dependencies included.
 */
describe('S5.3 egress.none', () => {
  afterEach(() => vi.restoreAllMocks());

  it('the full API tour makes zero outbound calls', async () => {
    const calls: string[] = [];
    const refuse = (what: string) =>
      ((...args: unknown[]) => {
        calls.push(`${what} ${String(args[0]).slice(0, 80)}`);
        throw new Error(`egress refused: ${what}`);
      }) as never;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = refuse('fetch');
    vi.spyOn(dns, 'lookup').mockImplementation(refuse('dns.lookup'));
    vi.spyOn(dns, 'resolve').mockImplementation(refuse('dns.resolve'));
    vi.spyOn(dns.promises, 'lookup').mockImplementation(refuse('dns.promises.lookup'));
    vi.spyOn(net, 'connect').mockImplementation(refuse('net.connect'));
    vi.spyOn(net, 'createConnection').mockImplementation(refuse('net.createConnection'));
    vi.spyOn(tls, 'connect').mockImplementation(refuse('tls.connect'));
    vi.spyOn(http, 'request').mockImplementation(refuse('http.request'));
    vi.spyOn(http, 'get').mockImplementation(refuse('http.get'));
    vi.spyOn(https, 'request').mockImplementation(refuse('https.request'));
    vi.spyOn(https, 'get').mockImplementation(refuse('https.get'));
    try {
      const tour = await runTour();
      expect(tour.requests).toBe(MATRIX.length * ROLES.length);
    } finally {
      globalThis.fetch = originalFetch;
    }
    expect(calls).toEqual([]);
  }, 300_000);
});
