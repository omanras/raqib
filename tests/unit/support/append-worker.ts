// A separate OS process that appends to one circle's ledger through the real
// appendLedger, on its own connection. Used by the concurrency test.
// argv: <dbFile> <circleId> <count> <actor>
import { appendLedger } from '../../../server/db/ledger.js';
import { openDb } from '../../../server/db/db.js';

const [dbFile, circleId, countText, actor] = process.argv.slice(2) as [string, string, string, string];
const db = openDb(dbFile);
const count = Number(countText);
const pause = new Int32Array(new SharedArrayBuffer(4));
// Wait for the start signal on stdin so all workers begin together.
process.stdin.once('data', () => {
  for (let i = 0; i < count; i += 1) {
    appendLedger(db, circleId, actor, 'contribution.reported', { round: 1, amount: 100 + i, worker: actor, i });
    // Release the write lock for a moment so the other processes contend for it.
    Atomics.wait(pause, 0, 0, 1);
  }
  db.close();
  process.stdout.write('done\n');
  process.exit(0);
});
process.stdout.write('ready\n');
