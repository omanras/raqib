#!/usr/bin/env node
// Operator tool for the Dawr database (docs/OPERATIONS.md).
//
//   node deploy/dbtool.mjs backup <database> <destination>
//   node deploy/dbtool.mjs verify <database>
//
// backup: an online copy through SQLite's backup API (what the sqlite3
//   shell's `.backup` uses), safe while the server runs. The copy is switched
//   to a self-contained rollback journal, then checked like `verify` before
//   it is renamed into place. A copy that fails the check is evidence, not a
//   backup: it is kept as <destination>.broken and the exit code is 2.
// verify: PRAGMA integrity_check, then every circle's hash chain recomputed
//   by the server's own code (shared/ledger.ts). Read-only.
//
// Exit codes: 0 all good, 2 integrity or chain broken, 1 usage or I/O error.
// Runs from the image (/app/deploy) or from a built checkout (npm run build).
import { chmodSync, existsSync, renameSync, statSync } from 'node:fs';
import Database from 'better-sqlite3';
import { verify } from '../server/dist/shared/ledger.js';
import { sha256Hex } from '../server/dist/server/crypto.js';
import { listLedger } from '../server/dist/server/db/ledger.js';

function fail(message, code = 1) {
  process.stderr.write(`dbtool: ${message}\n`);
  process.exit(code);
}

/** Integrity and chain report for an open database; true when everything holds. */
function check(db, label) {
  const integrity = db.pragma('integrity_check', { simple: false }).map((r) => r.integrity_check);
  const intact = integrity.length === 1 && integrity[0] === 'ok';
  process.stdout.write(`${label}: integrity ${intact ? 'ok' : `FAILED: ${integrity.slice(0, 5).join('; ')}`}\n`);
  const ids = db
    .prepare('SELECT id FROM circles UNION SELECT DISTINCT circle_id FROM ledger ORDER BY 1')
    .pluck()
    .all();
  let broken = 0;
  for (const id of ids) {
    const entries = listLedger(db, id);
    const result = entries.length === 0 ? { ok: false, reason: 'no entries', brokenSeq: 0 } : verify(entries, sha256Hex);
    if (result.ok) {
      process.stdout.write(`  ok      circle ${id}  ${result.count} entries, head ${result.lastSeq} ${result.lastHash.slice(0, 16)}\n`);
    } else {
      broken += 1;
      process.stdout.write(`  BROKEN  circle ${id}  at seq ${result.brokenSeq} (${result.reason})\n`);
    }
  }
  process.stdout.write(`${label}: ${ids.length} circle(s), ${broken} broken chain(s)\n`);
  return intact && broken === 0;
}

async function backup(source, destination) {
  if (!existsSync(source)) fail(`no database at ${source}`);
  if (existsSync(destination)) fail(`refusing to overwrite ${destination}`);
  const partial = `${destination}.partial`;
  const src = new Database(source, { readonly: true, fileMustExist: true });
  try {
    src.pragma('busy_timeout = 10000');
    await src.backup(partial);
  } finally {
    src.close();
  }
  chmodSync(partial, 0o600);
  const copy = new Database(partial);
  let good;
  try {
    copy.pragma('journal_mode = DELETE');
    good = check(copy, 'backup');
  } finally {
    copy.close();
  }
  if (!good) {
    renameSync(partial, `${destination}.broken`);
    fail(`the copy failed its check; kept as evidence at ${destination}.broken (docs/OPERATIONS.md, "If the ledger check is red")`, 2);
  }
  renameSync(partial, destination);
  process.stdout.write(`backup: wrote ${destination} (${statSync(destination).size} bytes)\n`);
}

function verifyFile(file) {
  if (!existsSync(file)) fail(`no database at ${file}`);
  const db = new Database(file, { readonly: true, fileMustExist: true });
  let good;
  try {
    good = check(db, 'verify');
  } finally {
    db.close();
  }
  if (!good) process.exit(2);
}

const [command, ...args] = process.argv.slice(2);
if (command === 'backup' && args.length === 2) await backup(args[0], args[1]);
else if (command === 'verify' && args.length === 1) verifyFile(args[0]);
else fail('usage: dbtool.mjs backup <database> <destination> | verify <database>');
