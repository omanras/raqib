import { newId } from '../../../server/crypto.js';
import type { DB } from '../../../server/db/db.js';

/** Inserts the minimum rows the ledger's foreign keys need: one user, one circle. */
export function seedCircle(db: DB): { userId: string; circleId: string } {
  const userId = newId();
  const circleId = newId();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO users (id, login, display_name, password_hash, password_changed_at, created_at)
     VALUES (?, ?, ?, 'x', ?, ?)`,
  ).run(userId, `user-${userId.slice(0, 8).toLowerCase()}`, 'Test User', now, now);
  db.prepare(
    `INSERT INTO circles (id, name, currency, minor_unit, contribution, period, due_day, created_by, created_at)
     VALUES (?, 'Test circle', 'OMR', 3, 50000, 'monthly', 5, ?, ?)`,
  ).run(circleId, userId, now);
  return { userId, circleId };
}
