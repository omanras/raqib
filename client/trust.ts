/**
 * The checks a member runs in their own browser, on data the server sent,
 * with the same shared code the server uses and the browser's Web Crypto
 * SHA-256 (not the server's): the ledger chain, and the draw.
 */
import { csvDocument } from '../shared/csv.js';
import { bytesToHex, webSha256Hex } from '../shared/hash.js';
import { canonical, verifyAsync, type LedgerEntry, type VerifyResult } from '../shared/ledger.js';
import { commitAsync, finalizeAsync } from '../shared/lottery.js';

/** Web Crypto exists only in secure contexts (https, or localhost). */
export function canVerify(): boolean {
  return typeof globalThis.crypto?.subtle?.digest === 'function';
}

export function verifyLedger(entries: readonly LedgerEntry[]): Promise<VerifyResult> {
  return verifyAsync(entries, webSha256Hex);
}

export interface DrawRecord {
  seed: string;
  order: string[];
  members: string[];
  reveals: { memberId: string; secret: string; seq: number }[];
  commitments: { memberId: string; commitment: string; seq: number }[];
}

export interface Recomputed {
  ok: boolean;
  seed: string;
  order: string[];
  /** Members whose revealed secret does not open their commitment (should never happen). */
  badReveals: string[];
}

/**
 * Recomputes the turn order from the reveals alone, checks every reveal
 * against its commitment, and compares with what the server recorded.
 */
export async function recomputeDraw(circleId: string, record: DrawRecord): Promise<Recomputed> {
  const commitments = new Map(record.commitments.map((c) => [c.memberId, c.commitment]));
  const badReveals: string[] = [];
  for (const r of record.reveals) {
    const c = await commitAsync(r.secret, r.memberId, webSha256Hex);
    if (commitments.get(r.memberId) !== c) badReveals.push(r.memberId);
  }
  const result = await finalizeAsync(circleId, record.members, new Map(record.reveals.map((r) => [r.memberId, r.secret])), webSha256Hex);
  const same = result.seed === record.seed && result.order.length === record.order.length && result.order.every((m, i) => m === record.order[i]);
  return { ok: same && badReveals.length === 0, seed: result.seed, order: result.order, badReveals };
}

/** A fresh draw secret: 32 random bytes from the browser, as 64 hex characters. */
export function newSecret(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

export function ledgerJson(circleId: string, entries: readonly LedgerEntry[], fetchedAt: Date | null): string {
  return `${JSON.stringify({ circleId, fetchedAt: fetchedAt?.toISOString() ?? null, entries }, null, 2)}\n`;
}

export function ledgerCsv(entries: readonly LedgerEntry[]): string {
  return csvDocument(
    ['seq', 'ts', 'actor', 'type', 'payload', 'prev_hash', 'hash'],
    entries.map((e) => [e.seq, e.ts, e.actor, e.type, canonical(e.payload), e.prevHash, e.hash]),
  );
}

// ---------------------------------------------------------------- the member's draw secret

const secretKey = (circleId: string, memberId: string) => `dawr.draw.${circleId}.${memberId}`;

/** Stored on this device only (localStorage), keyed by circle and member. */
export function storeSecret(circleId: string, memberId: string, secret: string): boolean {
  try {
    window.localStorage.setItem(secretKey(circleId, memberId), secret);
    return true;
  } catch {
    return false;
  }
}

export function storedSecret(circleId: string, memberId: string): string | null {
  try {
    return window.localStorage.getItem(secretKey(circleId, memberId));
  } catch {
    return null;
  }
}

export function forgetSecret(circleId: string, memberId: string): void {
  try {
    window.localStorage.removeItem(secretKey(circleId, memberId));
  } catch {
    // ignore
  }
}
