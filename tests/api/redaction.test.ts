import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { createLogger } from '../../server/logging.js';
import { runTour } from './tour.js';

/**
 * S6.2 logging.redaction: the operator log of the whole API tour, at debug
 * level, carries none of the secrets that went through the server:
 * passwords, session tokens, CSRF tokens, invite tokens, recovery codes,
 * draw secrets.
 */
describe('S6.2 logging.redaction', () => {
  it('the log stream of the full tour contains no known secret', async () => {
    const lines: string[] = [];
    const stream = new Writable({
      write(chunk: Buffer, _enc, cb) {
        lines.push(chunk.toString());
        cb();
      },
    });
    const logger = createLogger({ level: 'debug', stream });
    const tour = await runTour({ logger });
    const log = lines.join('');
    expect(lines.length).toBeGreaterThan(tour.requests);
    expect(tour.secrets.size).toBeGreaterThan(100);
    const leaked = [...tour.secrets].filter((s) => log.includes(s));
    expect(leaked).toEqual([]);
    // The log does carry what operators need: request ids, routes, statuses.
    const first = JSON.parse(lines.find((l) => l.includes('"msg":"request"')) as string) as Record<string, unknown>;
    expect(first).toMatchObject({ requestId: expect.any(String), route: expect.any(String), status: expect.any(Number) });
  }, 300_000);
});
