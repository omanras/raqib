import { isIP } from 'node:net';
import type { FastifyRequest } from 'fastify';
import { canonical, type JsonObject } from '../shared/ledger.js';
import { hmacHex } from './crypto.js';
import { stmt, type DB } from './db/db.js';

/**
 * Truncates an address for the audit log: IPv4 to its /24, IPv6 to its /48,
 * an IPv4-mapped IPv6 address to the IPv4 /24. Anything else is "unknown".
 */
export function ipPrefix(ip: string | undefined): string {
  if (!ip) return 'unknown';
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  const addr = mapped ? (mapped[1] as string) : ip;
  const kind = isIP(addr);
  if (kind === 4) {
    const [a, b, c] = addr.split('.');
    return `${a}.${b}.${c}.0/24`;
  }
  if (kind === 6) {
    const groups = expandIPv6(addr.split('%')[0] as string);
    if (!groups) return 'unknown';
    return `${groups.slice(0, 3).map((g) => g.replace(/^0+(?=.)/, '')).join(':')}::/48`;
  }
  return 'unknown';
}

function expandIPv6(addr: string): string[] | null {
  let text = addr.toLowerCase();
  // An embedded IPv4 tail ("::1.2.3.4") becomes two hex groups.
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number) as [number, number, number, number];
    text = `${text.slice(0, v4.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - head.length - tail.length;
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return null;
  return [...head, ...Array<string>(fill).fill('0'), ...tail];
}

/** Keyed hash of the user agent: correlates requests without storing the string. */
export function uaHash(secret: string, userAgent: string | undefined): string {
  return hmacHex(`ua:${secret}`, userAgent ?? '').slice(0, 16);
}

/** Keyed hash of a user id for the operator log (ADR §7). */
export function logUserId(secret: string, userId: string): string {
  return hmacHex(`log:${secret}`, userId).slice(0, 16);
}

export interface AuditInput {
  circleId?: string | null;
  action: string;
  target?: string | null;
  details?: JsonObject;
  /** Override the actor (e.g. a sign-in attempt before a session exists). */
  actorId?: string | null;
}

export interface AuditRow {
  id: number;
  ts: string;
  actorId: string | null;
  circleId: string | null;
  action: string;
  target: string | null;
  requestId: string;
  ipPrefix: string;
  uaHash: string;
  details: JsonObject | null;
}

export interface AuditContext {
  db: DB;
  now: Date;
  secret: string;
  actorId: string | null;
  requestId: string;
  ip: string | undefined;
  userAgent: string | undefined;
}

export function writeAudit(ctx: AuditContext, input: AuditInput): void {
  const ts = ctx.now.toISOString();
  stmt(
    ctx.db,
    `INSERT INTO audit (ts, actor_id, circle_id, action, target, request_id, ip_prefix, ua_hash, details, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    ts,
    input.actorId !== undefined ? input.actorId : ctx.actorId,
    input.circleId ?? null,
    input.action,
    input.target ?? null,
    ctx.requestId,
    ipPrefix(ctx.ip),
    uaHash(ctx.secret, ctx.userAgent),
    input.details ? canonical(input.details) : null,
    ts,
  );
}

/**
 * The audit writer for routes (S6.1): actor, circle, action, target, the
 * request id, the truncated IP and the user-agent hash. Call it inside the
 * same transaction as the change it records.
 */
export function audit(req: FastifyRequest, input: AuditInput): void {
  const app = req.server;
  writeAudit(
    {
      db: app.db,
      now: app.clock.now(),
      secret: app.config.sessionSecret,
      actorId: req.user?.id ?? null,
      requestId: req.id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    },
    input,
  );
}

interface AuditDbRow {
  id: number;
  ts: string;
  actor_id: string | null;
  circle_id: string | null;
  action: string;
  target: string | null;
  request_id: string;
  ip_prefix: string;
  ua_hash: string;
  details: string | null;
}

function toAuditRow(r: AuditDbRow): AuditRow {
  return {
    id: r.id,
    ts: r.ts,
    actorId: r.actor_id,
    circleId: r.circle_id,
    action: r.action,
    target: r.target,
    requestId: r.request_id,
    ipPrefix: r.ip_prefix,
    uaHash: r.ua_hash,
    details: r.details ? (JSON.parse(r.details) as JsonObject) : null,
  };
}

/** Newest first; `before` is an audit id for paging. */
export function listAudit(db: DB, circleId: string, limit: number, before?: number): AuditRow[] {
  const rows = stmt(
    db,
    `SELECT id, ts, actor_id, circle_id, action, target, request_id, ip_prefix, ua_hash, details
     FROM audit WHERE circle_id = ? AND id < ? ORDER BY id DESC LIMIT ?`,
  ).all(circleId, before ?? Number.MAX_SAFE_INTEGER, limit) as AuditDbRow[];
  return rows.map(toAuditRow);
}

export function auditByRequest(db: DB, requestId: string): AuditRow[] {
  const rows = stmt(
    db,
    `SELECT id, ts, actor_id, circle_id, action, target, request_id, ip_prefix, ua_hash, details
     FROM audit WHERE request_id = ? ORDER BY id`,
  ).all(requestId) as AuditDbRow[];
  return rows.map(toAuditRow);
}
