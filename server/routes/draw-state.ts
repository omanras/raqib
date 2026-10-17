import type { DB } from '../db/db.js';
import { loadDraw } from '../draw.js';

/** Whether the circle's turn-order draw has been finalized (start requires it for a drawing circle). */
export function drawFinalized(db: DB, circleId: string): boolean {
  return loadDraw(db, circleId)?.phase === 'finalized';
}
