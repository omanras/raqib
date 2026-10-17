import { join } from 'node:path';
import Database from 'better-sqlite3';

/** The e2e server's database (playwright.config.ts sets DAWR_E2E_DATA_DIR for every worker). */
export function dbPath(): string {
  const dir = process.env.DAWR_E2E_DATA_DIR;
  if (!dir) throw new Error('DAWR_E2E_DATA_DIR is not set');
  return join(dir, 'dawr.sqlite');
}

/**
 * Rewrites one ledger payload underneath the application, as someone with
 * access to the database file could: the append-only triggers forbid
 * UPDATE, so the table is recreated without them, the row edited, and the
 * triggers put back so nothing looks touched. Only the hash chain can tell.
 */
export function tamperLedgerPayload(circleId: string, seq: number, edit: (payload: string) => string): void {
  const db = new Database(dbPath());
  db.pragma('busy_timeout = 10000');
  const table = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'ledger'").get() as { sql: string };
  const triggers = (db.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'ledger'").all() as { sql: string }[]).map(
    (r) => r.sql,
  );
  db.transaction(() => {
    db.exec('ALTER TABLE ledger RENAME TO ledger_old');
    db.exec(table.sql);
    db.exec('INSERT INTO ledger SELECT * FROM ledger_old');
    db.exec('DROP TABLE ledger_old');
    const row = db.prepare('SELECT payload FROM ledger WHERE circle_id = ? AND seq = ?').get(circleId, seq) as { payload: string };
    db.prepare('UPDATE ledger SET payload = ? WHERE circle_id = ? AND seq = ?').run(edit(row.payload), circleId, seq);
    for (const sql of triggers) db.exec(sql);
  })();
  db.close();
}
