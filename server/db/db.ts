import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { sha256Hex } from '../crypto.js';

export type DB = Database.Database;
export type Statement = Database.Statement;

export const MIGRATIONS_DIR = fileURLToPath(new URL('./migrations/', import.meta.url));
const MIGRATION_FILE = /^(\d{4})_[a-z0-9_]+\.sql$/;

/**
 * Opens the database: WAL journal (file databases), foreign keys enforced,
 * a busy timeout so concurrent writers wait instead of failing, and full
 * fsync on commit (the ledger is evidence; durability beats speed).
 */
export function openDb(file: string): DB {
  const db = new Database(file);
  if (file !== ':memory:') db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 10000');
  db.pragma('synchronous = FULL');
  return db;
}

const cache = new WeakMap<DB, Map<string, Statement>>();

/** A prepared statement, cached per connection. User data is only ever bound, never spliced. */
export function stmt(db: DB, sql: string): Statement {
  let byDb = cache.get(db);
  if (!byDb) {
    byDb = new Map();
    cache.set(db, byDb);
  }
  let s = byDb.get(sql);
  if (!s) {
    s = db.prepare(sql);
    byDb.set(sql, s);
  }
  return s;
}

/** Runs fn in a write transaction taken at BEGIN (IMMEDIATE), or as a savepoint if already in one. */
export function withTx<T>(db: DB, fn: () => T): T {
  const tx = db.transaction(fn);
  return db.inTransaction ? tx() : tx.immediate();
}

export interface MigrationFile {
  id: number;
  name: string;
  sql: string;
  checksum: string;
}

export function listMigrations(dir: string = MIGRATIONS_DIR): MigrationFile[] {
  return readdirSync(dir)
    .filter((f) => MIGRATION_FILE.test(f))
    .sort()
    .map((name) => {
      const sql = readFileSync(`${dir}/${name}`, 'utf8');
      return { id: Number(name.slice(0, 4)), name, sql, checksum: sha256Hex(sql) };
    });
}

export class MigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MigrationError';
  }
}

export interface MigrationResult {
  applied: string[];
  total: number;
}

/**
 * Applies numbered migrations in order, each in its own transaction, and
 * records them in `migrations`. An applied migration whose file changed
 * since (checksum) or disappeared stops the startup: history is not edited.
 */
export function migrate(db: DB, dir: string = MIGRATIONS_DIR, now: () => Date = () => new Date()): MigrationResult {
  db.exec(`CREATE TABLE IF NOT EXISTS migrations (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  ) STRICT`);
  const files = listMigrations(dir);
  const ids = new Set<number>();
  for (const f of files) {
    if (ids.has(f.id)) throw new MigrationError(`two migrations share number ${f.id}`);
    ids.add(f.id);
  }
  const done = db.prepare('SELECT id, name, checksum FROM migrations ORDER BY id').all() as {
    id: number;
    name: string;
    checksum: string;
  }[];
  for (const row of done) {
    const file = files.find((f) => f.id === row.id);
    if (!file) throw new MigrationError(`applied migration ${row.name} is missing from ${dir}`);
    if (file.checksum !== row.checksum || file.name !== row.name) {
      throw new MigrationError(`applied migration ${row.name} was modified after it ran`);
    }
  }
  const applied: string[] = [];
  const doneIds = new Set(done.map((d) => d.id));
  for (const f of files) {
    if (doneIds.has(f.id)) continue;
    db.transaction(() => {
      db.exec(f.sql);
      const ts = now().toISOString();
      db.prepare('INSERT INTO migrations (id, name, checksum, applied_at, created_at) VALUES (?, ?, ?, ?, ?)').run(
        f.id,
        f.name,
        f.checksum,
        ts,
        ts,
      );
    }).immediate();
    applied.push(f.name);
  }
  return { applied, total: done.length + applied.length };
}

export function migrationCount(db: DB): number {
  return (stmt(db, 'SELECT COUNT(*) AS n FROM migrations').get() as { n: number }).n;
}
