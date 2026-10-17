import type { DB } from '../db/db.js';

/**
 * Whether the circle's turn-order draw has been finalized. The draw arrives
 * in M1.3; until then no circle has one.
 */
export function drawFinalized(_db: DB, _circleId: string): boolean {
  return false;
}
