import { spawn } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verify } from '../../shared/ledger.js';
import { sha256Hex } from '../../server/crypto.js';
import { MIGRATIONS_DIR, MigrationError, listMigrations, migrate, migrationCount, openDb } from '../../server/db/db.js';
import { appendLedger, ledgerHead, listLedger } from '../../server/db/ledger.js';
import { seedCircle } from './support/fixtures.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'dawr-db-'));

describe('db: open and migrate', () => {
  it('opens a file database in WAL with foreign keys on', () => {
    const db = openDb(join(tmp(), 'a.sqlite'));
    expect(db.pragma('journal_mode', { simple: true })).toBe('wal');
    expect(db.pragma('foreign_keys', { simple: true })).toBe(1);
    db.close();
  });

  it('applies numbered migrations once and records them', () => {
    const db = openDb(join(tmp(), 'm.sqlite'));
    const first = migrate(db);
    expect(first.applied).toEqual(listMigrations().map((m) => m.name));
    expect(first.applied[0]).toBe('0001_init.sql');
    const second = migrate(db);
    expect(second.applied).toEqual([]);
    expect(second.total).toBe(first.total);
    expect(migrationCount(db)).toBe(first.total);
    const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[]).map(
      (t) => t.name,
    );
    for (const t of [
      'users',
      'sessions',
      'circles',
      'members',
      'rounds',
      'contributions',
      'payouts',
      'ledger',
      'invites',
      'audit',
      'recovery_codes',
      'migrations',
    ]) {
      expect(tables, t).toContain(t);
    }
    db.close();
  });

  it('every table has created_at', () => {
    const db = openDb(':memory:');
    migrate(db);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all() as {
      name: string;
    }[];
    for (const { name } of tables) {
      const cols = (db.prepare('SELECT name FROM pragma_table_info(?)').all(name) as { name: string }[]).map((c) => c.name);
      expect(cols, name).toContain('created_at');
    }
  });

  it('refuses to start when an applied migration was edited or removed', () => {
    const dir = tmp();
    const mig = join(dir, 'migrations');
    mkdirSync(mig);
    for (const f of readdirSync(MIGRATIONS_DIR)) copyFileSync(join(MIGRATIONS_DIR, f), join(mig, f));
    const db = openDb(':memory:');
    migrate(db, mig);
    writeFileSync(join(mig, '0001_init.sql'), '-- edited\n');
    expect(() => migrate(db, mig)).toThrow(MigrationError);
  });
});

describe('db: the ledger table is append-only', () => {
  it('raises on UPDATE and on DELETE (trigger), and keeps UNIQUE(circle_id, seq)', () => {
    const db = openDb(':memory:');
    migrate(db);
    const { userId, circleId } = seedCircle(db);
    appendLedger(db, circleId, userId, 'circle.created', { name: 'x' });
    appendLedger(db, circleId, userId, 'member.joined', { memberId: 'm' });
    expect(() => db.prepare("UPDATE ledger SET payload = '{}' WHERE seq = 1").run()).toThrow(/append-only: UPDATE/);
    expect(() => db.prepare('DELETE FROM ledger WHERE seq = 2').run()).toThrow(/append-only: DELETE/);
    expect(() => db.prepare('DELETE FROM ledger').run()).toThrow(/append-only/);
    expect(() =>
      db
        .prepare(
          `INSERT INTO ledger (circle_id, seq, ts, actor, type, payload, prev_hash, hash, created_at)
           VALUES (?, 1, 'x', 'a', 't', '{}', 'p', 'h', 'x')`,
        )
        .run(circleId),
    ).toThrow(/UNIQUE/);
    expect(listLedger(db, circleId)).toHaveLength(2);
  });

  it('the audit table is append-only too', () => {
    const db = openDb(':memory:');
    migrate(db);
    db.prepare(
      `INSERT INTO audit (ts, action, request_id, ip_prefix, ua_hash, created_at) VALUES ('t', 'a', 'r', 'i', 'u', 't')`,
    ).run();
    expect(() => db.prepare("UPDATE audit SET action = 'b'").run()).toThrow(/append-only/);
    expect(() => db.prepare('DELETE FROM audit').run()).toThrow(/append-only/);
  });
});

describe('db: appendLedger', () => {
  it('computes seq and hash and stores canonical payload; the stored chain verifies', () => {
    const db = openDb(':memory:');
    migrate(db);
    const { userId, circleId } = seedCircle(db);
    const a = appendLedger(db, circleId, userId, 'circle.created', { name: 'جمعية', z: 1, a: [1, 2] }, new Date('2026-10-17T10:00:00.000Z'));
    const b = appendLedger(db, circleId, userId, 'member.joined', { memberId: 'm1' });
    expect(a.seq).toBe(1);
    expect(a.prevHash).toBe('0'.repeat(64));
    expect(b.seq).toBe(2);
    expect(b.prevHash).toBe(a.hash);
    const raw = db.prepare('SELECT payload FROM ledger WHERE seq = 1').get() as { payload: string };
    expect(raw.payload).toBe('{"a":[1,2],"name":"جمعية","z":1}');
    expect(verify(listLedger(db, circleId), sha256Hex)).toMatchObject({ ok: true, count: 2, lastHash: b.hash });
    expect(ledgerHead(db, circleId)).toEqual({ seq: 2, hash: b.hash });
  });

  it('keeps one chain per circle', () => {
    const db = openDb(':memory:');
    migrate(db);
    const one = seedCircle(db);
    const two = seedCircle(db);
    appendLedger(db, one.circleId, one.userId, 'circle.created', {});
    appendLedger(db, two.circleId, two.userId, 'circle.created', {});
    appendLedger(db, one.circleId, one.userId, 'member.joined', {});
    expect(listLedger(db, one.circleId).map((e) => e.seq)).toEqual([1, 2]);
    expect(listLedger(db, two.circleId).map((e) => e.seq)).toEqual([1]);
  });

  it('rolls back with the caller transaction (no orphan entry)', () => {
    const db = openDb(':memory:');
    migrate(db);
    const { userId, circleId } = seedCircle(db);
    expect(() =>
      db.transaction(() => {
        appendLedger(db, circleId, userId, 'circle.created', {});
        throw new Error('boom');
      })(),
    ).toThrow('boom');
    expect(listLedger(db, circleId)).toHaveLength(0);
  });

  it('refuses a float in a payload', () => {
    const db = openDb(':memory:');
    migrate(db);
    const { userId, circleId } = seedCircle(db);
    expect(() => appendLedger(db, circleId, userId, 'contribution.reported', { amount: 1.5 })).toThrow(TypeError);
  });
});

describe('db: concurrent appends from separate processes', () => {
  function startWorker(file: string, circleId: string, count: number, actor: string) {
    const child = spawn(
      process.execPath,
      ['--import', './tests/unit/support/register-ts.mjs', 'tests/unit/support/append-worker.ts', file, circleId, String(count), actor],
      { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] },
    );
    let out = '';
    let err = '';
    child.stdout.on('data', (d: Buffer) => {
      out += d.toString();
    });
    child.stderr.on('data', (d: Buffer) => {
      err += d.toString();
    });
    const ready = new Promise<void>((res, rej) => {
      const t = setInterval(() => {
        if (out.includes('ready')) {
          clearInterval(t);
          res();
        }
      }, 10);
      child.once('exit', (code) => {
        clearInterval(t);
        if (!out.includes('ready')) rej(new Error(`worker exited early (${code}): ${err}`));
      });
    });
    const done = new Promise<void>((res, rej) => {
      child.once('exit', (code) => (code === 0 ? res() : rej(new Error(`worker failed (${code}): ${err}`))));
    });
    return { child, ready, done };
  }

  it('four writers x 150 appends never produce a gap or a duplicate seq', async () => {
    const file = join(tmp(), 'c.sqlite');
    const db = openDb(file);
    migrate(db);
    const { circleId } = seedCircle(db);
    const workers = ['w1', 'w2', 'w3', 'w4'].map((a) => startWorker(file, circleId, 150, a));
    await Promise.all(workers.map((w) => w.ready));
    for (const w of workers) w.child.stdin.write('go\n');
    await Promise.all(workers.map((w) => w.done));

    const entries = listLedger(db, circleId);
    expect(entries).toHaveLength(600);
    expect(entries.map((e) => e.seq)).toEqual(Array.from({ length: 600 }, (_, i) => i + 1));
    expect(verify(entries, sha256Hex).ok).toBe(true);
    const byWorker = new Map<string, number>();
    for (const e of entries) byWorker.set(e.actor, (byWorker.get(e.actor) ?? 0) + 1);
    expect([...byWorker.values()]).toEqual([150, 150, 150, 150]);
    // The writers really interleaved (not one after the other).
    const switches = entries.filter((e, i) => i > 0 && e.actor !== entries[i - 1]?.actor).length;
    expect(switches).toBeGreaterThan(3);
    db.close();
  }, 60_000);
});
