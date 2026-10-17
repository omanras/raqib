import { canonical, nextEntry, type JsonObject, type LedgerEntry, type LedgerType } from '../../shared/ledger.js';
import { sha256Hex } from '../crypto.js';
import { stmt, withTx, type DB } from './db.js';

interface LedgerRow {
  seq: number;
  ts: string;
  actor: string;
  type: string;
  payload: string;
  prev_hash: string;
  hash: string;
}

export function rowToEntry(row: LedgerRow): LedgerEntry {
  return {
    seq: row.seq,
    ts: row.ts,
    actor: row.actor,
    type: row.type,
    payload: JSON.parse(row.payload) as JsonObject,
    prevHash: row.prev_hash,
    hash: row.hash,
  };
}

/**
 * Appends one entry to a circle's chain. The last seq and hash are read and
 * the new row written inside one write transaction (BEGIN IMMEDIATE, or the
 * caller's transaction), so two writers can never take the same seq; the
 * UNIQUE(circle_id, seq) constraint is the second lock on that door.
 */
export function appendLedger(
  db: DB,
  circleId: string,
  actor: string,
  type: LedgerType,
  payload: JsonObject,
  now: Date = new Date(),
): LedgerEntry {
  return withTx(db, () => {
    const last = stmt(db, 'SELECT seq, hash FROM ledger WHERE circle_id = ? ORDER BY seq DESC LIMIT 1').get(circleId) as
      | { seq: number; hash: string }
      | undefined;
    const entry = nextEntry(last ?? null, { ts: now.toISOString(), actor, type, payload }, sha256Hex);
    stmt(
      db,
      `INSERT INTO ledger (circle_id, seq, ts, actor, type, payload, prev_hash, hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      circleId,
      entry.seq,
      entry.ts,
      entry.actor,
      entry.type,
      canonical(entry.payload),
      entry.prevHash,
      entry.hash,
      entry.ts,
    );
    return entry;
  });
}

/** Entries of a circle in seq order, from `fromSeq` (inclusive), at most `limit`. */
export function listLedger(db: DB, circleId: string, fromSeq = 1, limit = 10_000): LedgerEntry[] {
  const rows = stmt(
    db,
    `SELECT seq, ts, actor, type, payload, prev_hash, hash FROM ledger
     WHERE circle_id = ? AND seq >= ? ORDER BY seq LIMIT ?`,
  ).all(circleId, fromSeq, limit) as LedgerRow[];
  return rows.map(rowToEntry);
}

export function ledgerHead(db: DB, circleId: string): { seq: number; hash: string } | null {
  return (
    (stmt(db, 'SELECT seq, hash FROM ledger WHERE circle_id = ? ORDER BY seq DESC LIMIT 1').get(circleId) as
      | { seq: number; hash: string }
      | undefined) ?? null
  );
}

export function ledgerEntriesOfType(db: DB, circleId: string, types: readonly LedgerType[]): LedgerEntry[] {
  const all = listLedger(db, circleId);
  return all.filter((e) => (types as readonly string[]).includes(e.type));
}
