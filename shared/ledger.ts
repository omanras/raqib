/**
 * The ledger (ADR-0001 §2, Constitution A2). Each entry carries
 *
 *   hash = SHA-256( seq || ts || actor || type || canonical(payload) || prev_hash )
 *
 * where || is plain string concatenation (no separator) of: seq in decimal,
 * ts as an ISO-8601 UTC timestamp with milliseconds, the actor id, the type,
 * the canonical JSON of the payload, and the previous entry's hash (64 zeros
 * for the first entry). The concatenation is unambiguous because every field
 * has a strict format, which verify() checks before hashing.
 *
 * Canonical JSON: object keys sorted by UTF-16 code unit, no whitespace,
 * strings as JSON.stringify writes them, numbers restricted to safe integers
 * (money is integer minor units; floats would not hash identically
 * everywhere), no undefined, no non-plain objects; hashed as UTF-8.
 */
import type { Sha256Hex, Sha256HexAsync } from './hash.js';
import { isHex64 } from './hash.js';

export const GENESIS_HASH = '0'.repeat(64);

export const LEDGER_TYPES = [
  'circle.created',
  'circle.rule_changed',
  'circle.started',
  'circle.cancelled',
  'circle.completed',
  'member.joined',
  'member.left',
  'member.substituted',
  'order.set',
  'draw.opened',
  'draw.committed',
  'draw.commits_closed',
  'draw.revealed',
  'draw.finalized',
  'round.opened',
  'round.closed',
  'contribution.reported',
  'contribution.confirmed',
  'contribution.waived',
  'payout.recorded',
  'payout.acknowledged',
] as const;

export type LedgerType = (typeof LEDGER_TYPES)[number];

export function isLedgerType(value: unknown): value is LedgerType {
  return typeof value === 'string' && (LEDGER_TYPES as readonly string[]).includes(value);
}

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface LedgerEntry {
  seq: number;
  ts: string;
  actor: string;
  type: string;
  payload: JsonObject;
  prevHash: string;
  hash: string;
}

export type UnhashedEntry = Omit<LedgerEntry, 'hash'>;

/** Canonical JSON of a value (see the module comment). Throws on what it refuses. */
export function canonical(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) throw new TypeError('canonical JSON allows safe integers only');
      return String(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map((v) => canonical(v)).join(',')}]`;
      const proto = Object.getPrototypeOf(value) as unknown;
      if (proto !== Object.prototype && proto !== null) throw new TypeError('canonical JSON allows plain objects only');
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const parts: string[] = [];
      for (const k of keys) {
        if (obj[k] === undefined) throw new TypeError(`canonical JSON refuses undefined at key ${k}`);
        parts.push(`${JSON.stringify(k)}:${canonical(obj[k])}`);
      }
      return `{${parts.join(',')}}`;
    }
    default:
      throw new TypeError(`canonical JSON refuses ${typeof value}`);
  }
}

const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ACTOR = /^[A-Za-z0-9_-]{1,64}$/;
const TYPE = /^[a-z][a-z_]*\.[a-z][a-z_]*$/;

export function isLedgerTimestamp(value: unknown): value is string {
  return typeof value === 'string' && TS.test(value) && !Number.isNaN(Date.parse(value));
}

/** The exact string that is hashed, or null when a field breaks its format. */
export function preimage(entry: UnhashedEntry): string | null {
  if (!Number.isSafeInteger(entry.seq) || entry.seq < 1) return null;
  if (!isLedgerTimestamp(entry.ts)) return null;
  if (typeof entry.actor !== 'string' || !ACTOR.test(entry.actor)) return null;
  if (typeof entry.type !== 'string' || !TYPE.test(entry.type)) return null;
  if (!isHex64(entry.prevHash)) return null;
  if (typeof entry.payload !== 'object' || entry.payload === null || Array.isArray(entry.payload)) return null;
  let payload: string;
  try {
    payload = canonical(entry.payload);
  } catch {
    return null;
  }
  return `${entry.seq}${entry.ts}${entry.actor}${entry.type}${payload}${entry.prevHash}`;
}

export function hashEntry(entry: UnhashedEntry, sha256: Sha256Hex): string {
  const pre = preimage(entry);
  if (pre === null) throw new TypeError(`ledger entry ${entry.seq} is malformed`);
  return sha256(pre);
}

export async function hashEntryAsync(entry: UnhashedEntry, sha256: Sha256HexAsync): Promise<string> {
  const pre = preimage(entry);
  if (pre === null) throw new TypeError(`ledger entry ${entry.seq} is malformed`);
  return sha256(pre);
}

export type BreakReason = 'format' | 'seq' | 'link' | 'hash';

export interface EntryCheck {
  seq: number;
  ok: boolean;
  reason?: BreakReason;
}

export type VerifyResult =
  | { ok: true; count: number; lastSeq: number; lastHash: string }
  | { ok: false; brokenSeq: number; reason: BreakReason; count: number };

export interface VerifyOptions {
  /** Hash the first given entry must link to (default: genesis). */
  prevHash?: string;
  /** Seq the first given entry must carry (default: 1). */
  startSeq?: number;
}

function evaluate(
  entries: readonly LedgerEntry[],
  computed: readonly (string | null)[],
  options: VerifyOptions,
): EntryCheck[] {
  const startSeq = options.startSeq ?? 1;
  let expectedPrev = options.prevHash ?? GENESIS_HASH;
  return entries.map((entry, i) => {
    const seq = typeof entry.seq === 'number' ? entry.seq : Number.NaN;
    const hash = computed[i] ?? null;
    let reason: BreakReason | undefined;
    if (hash === null) reason = 'format';
    else if (seq !== startSeq + i) reason = 'seq';
    else if (entry.prevHash !== expectedPrev) reason = 'link';
    else if (entry.hash !== hash) reason = 'hash';
    // The next entry must link to the hash as stored, so a single altered
    // entry shows as one break and the rest of the chain still verifies.
    expectedPrev = entry.hash;
    return reason === undefined ? { seq, ok: true } : { seq, ok: false, reason };
  });
}

function summarize(entries: readonly LedgerEntry[], checks: readonly EntryCheck[], options: VerifyOptions): VerifyResult {
  const broken = checks.find((c) => !c.ok);
  if (broken) {
    return { ok: false, brokenSeq: broken.seq, reason: broken.reason as BreakReason, count: entries.length };
  }
  const last = entries[entries.length - 1];
  return {
    ok: true,
    count: entries.length,
    lastSeq: last ? last.seq : (options.startSeq ?? 1) - 1,
    lastHash: last ? last.hash : (options.prevHash ?? GENESIS_HASH),
  };
}

/** Per-entry result for the whole list (every break, not only the first). */
export function inspect(entries: readonly LedgerEntry[], sha256: Sha256Hex, options: VerifyOptions = {}): EntryCheck[] {
  const computed = entries.map((e) => {
    const pre = preimage(e);
    return pre === null ? null : sha256(pre);
  });
  return evaluate(entries, computed, options);
}

export async function inspectAsync(
  entries: readonly LedgerEntry[],
  sha256: Sha256HexAsync,
  options: VerifyOptions = {},
): Promise<EntryCheck[]> {
  const computed = await Promise.all(
    entries.map(async (e) => {
      const pre = preimage(e);
      return pre === null ? null : sha256(pre);
    }),
  );
  return evaluate(entries, computed, options);
}

/** Recomputes the chain; ok with the last hash, or the first broken seq. */
export function verify(entries: readonly LedgerEntry[], sha256: Sha256Hex, options: VerifyOptions = {}): VerifyResult {
  return summarize(entries, inspect(entries, sha256, options), options);
}

export async function verifyAsync(
  entries: readonly LedgerEntry[],
  sha256: Sha256HexAsync,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  return summarize(entries, await inspectAsync(entries, sha256, options), options);
}

/** Builds the next entry of a chain (used by the server and by tests). */
export function nextEntry(
  previous: Pick<LedgerEntry, 'seq' | 'hash'> | null,
  fields: { ts: string; actor: string; type: string; payload: JsonObject },
  sha256: Sha256Hex,
): LedgerEntry {
  const unhashed: UnhashedEntry = {
    seq: previous ? previous.seq + 1 : 1,
    ts: fields.ts,
    actor: fields.actor,
    type: fields.type,
    payload: fields.payload,
    prevHash: previous ? previous.hash : GENESIS_HASH,
  };
  return { ...unhashed, hash: hashEntry(unhashed, sha256) };
}
