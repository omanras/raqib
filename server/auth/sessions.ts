import { newId, newToken, sha256Hex } from '../crypto.js';
import { stmt, type DB } from '../db/db.js';

/** S2.1: idle expiry 30 days, absolute expiry 90 days. */
export const IDLE_MS = 30 * 24 * 60 * 60 * 1000;
export const ABSOLUTE_MS = 90 * 24 * 60 * 60 * 1000;
/** last_seen_at is written at most once a minute per session. */
const TOUCH_MS = 60 * 1000;

export interface SessionRow {
  id: string;
  token_hash: string;
  user_id: string;
  ua_hash: string;
  created_at: string;
  last_seen_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
}

export interface IssuedSession {
  /** The bearer value for the cookie; never stored, never logged. */
  token: string;
  row: SessionRow;
}

export function tokenHash(token: string): string {
  return sha256Hex(token);
}

/** Opaque 256-bit session id, stored only as its SHA-256 (S2.1). */
export function issueSession(db: DB, userId: string, now: Date, uaHash = ''): IssuedSession {
  const token = newToken();
  const t = now.getTime();
  const row: SessionRow = {
    id: newId(),
    token_hash: tokenHash(token),
    user_id: userId,
    ua_hash: uaHash,
    created_at: now.toISOString(),
    last_seen_at: now.toISOString(),
    idle_expires_at: new Date(t + IDLE_MS).toISOString(),
    absolute_expires_at: new Date(t + ABSOLUTE_MS).toISOString(),
    revoked_at: null,
    revoked_reason: null,
  };
  stmt(
    db,
    `INSERT INTO sessions (id, token_hash, user_id, ua_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(row.id, row.token_hash, row.user_id, row.ua_hash, row.created_at, row.last_seen_at, row.idle_expires_at, row.absolute_expires_at);
  return { token, row };
}

/** The live session for a cookie value, or null (unknown, revoked, idle or absolute expiry). Touches it. */
export function resolveSession(db: DB, token: string, now: Date): SessionRow | null {
  const row = stmt(db, 'SELECT * FROM sessions WHERE token_hash = ?').get(tokenHash(token)) as SessionRow | undefined;
  if (!row || row.revoked_at) return null;
  const t = now.getTime();
  if (t >= Date.parse(row.idle_expires_at) || t >= Date.parse(row.absolute_expires_at)) return null;
  if (t - Date.parse(row.last_seen_at) >= TOUCH_MS) {
    const idle = new Date(Math.min(t + IDLE_MS, Date.parse(row.absolute_expires_at))).toISOString();
    stmt(db, 'UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?').run(now.toISOString(), idle, row.id);
    row.last_seen_at = now.toISOString();
    row.idle_expires_at = idle;
  }
  return row;
}

export function revokeSession(db: DB, sessionId: string, reason: string, now: Date): void {
  stmt(db, 'UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE id = ? AND revoked_at IS NULL').run(
    now.toISOString(),
    reason,
    sessionId,
  );
}

/** Revokes every live session of a user; returns how many. */
export function revokeAllSessions(db: DB, userId: string, reason: string, now: Date): number {
  return stmt(db, 'UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE user_id = ? AND revoked_at IS NULL').run(
    now.toISOString(),
    reason,
    userId,
  ).changes;
}

export interface SessionSummary {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  current: boolean;
}

export function listLiveSessions(db: DB, userId: string, now: Date, currentId: string): SessionSummary[] {
  const rows = stmt(
    db,
    `SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL
       AND idle_expires_at > ? AND absolute_expires_at > ? ORDER BY last_seen_at DESC`,
  ).all(userId, now.toISOString(), now.toISOString()) as SessionRow[];
  return rows.map((r) => ({
    id: r.id,
    createdAt: r.created_at,
    lastSeenAt: r.last_seen_at,
    expiresAt: r.idle_expires_at < r.absolute_expires_at ? r.idle_expires_at : r.absolute_expires_at,
    current: r.id === currentId,
  }));
}

export function findSession(db: DB, sessionId: string): SessionRow | undefined {
  return stmt(db, 'SELECT * FROM sessions WHERE id = ?').get(sessionId) as SessionRow | undefined;
}
