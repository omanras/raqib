/**
 * Turn-order draw by commit-reveal (ADR-0001 §2 Lottery, Constitution A3).
 *
 *   commitment = SHA-256(secret || member_id)
 *   seed       = SHA-256(secrets of revealing members, concatenated in
 *                member-id order || circle_id)
 *   order      = revealing members sorted by SHA-256(seed || member_id)
 *                (ties, which need a hash collision, by member id),
 *                then every member who never revealed, in member-id order.
 *
 * "member-id order" is ascending UTF-16 code-unit order of the ids (the
 * default JavaScript string sort; ids are ASCII). A secret is 32 random
 * bytes written as 64 lowercase hex characters. Everything here is a pure
 * function of its inputs, so anyone holding the ledger entries can
 * recompute the result; tests/unit/lottery.vectors.json pins it.
 */
import type { Sha256Hex, Sha256HexAsync } from './hash.js';
import { isHex64 } from './hash.js';

export function isSecret(value: unknown): value is string {
  return isHex64(value);
}

export function isCommitment(value: unknown): value is string {
  return isHex64(value);
}

export function commitPreimage(secret: string, memberId: string): string {
  if (!isSecret(secret)) throw new TypeError('a secret is 64 lowercase hex characters');
  return `${secret}${memberId}`;
}

export function commit(secret: string, memberId: string, sha256: Sha256Hex): string {
  return sha256(commitPreimage(secret, memberId));
}

export async function commitAsync(secret: string, memberId: string, sha256: Sha256HexAsync): Promise<string> {
  return sha256(commitPreimage(secret, memberId));
}

/** True when the secret opens the commitment for this member. */
export function verifyReveal(commitment: string, secret: string, memberId: string, sha256: Sha256Hex): boolean {
  if (!isCommitment(commitment) || !isSecret(secret)) return false;
  return commit(secret, memberId, sha256) === commitment;
}

export function byId(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export interface LotteryResult {
  seed: string;
  /** Member ids by position: order[0] receives in round 1. */
  order: string[];
  /** Members whose secret entered the seed, in member-id order. */
  revealed: string[];
  /** Members who never revealed, placed last in member-id order. */
  silent: string[];
}

export type Reveals = ReadonlyMap<string, string> | Readonly<Record<string, string>>;

function toMap(reveals: Reveals): Map<string, string> {
  if (reveals instanceof Map) return new Map(reveals);
  return new Map(Object.entries(reveals as Record<string, string>));
}

interface Prepared {
  sortedMembers: string[];
  revealed: string[];
  silent: string[];
  seedPreimage: string;
}

function prepare(circleId: string, members: readonly string[], reveals: Reveals): Prepared {
  const sortedMembers = [...members].sort(byId);
  if (new Set(sortedMembers).size !== sortedMembers.length) throw new RangeError('duplicate member id');
  const map = toMap(reveals);
  for (const [memberId, secret] of map) {
    if (!sortedMembers.includes(memberId)) throw new RangeError(`reveal from a non-member ${memberId}`);
    if (!isSecret(secret)) throw new TypeError(`malformed secret for ${memberId}`);
  }
  const revealed = sortedMembers.filter((id) => map.has(id));
  const silent = sortedMembers.filter((id) => !map.has(id));
  const seedPreimage = `${revealed.map((id) => map.get(id) as string).join('')}${circleId}`;
  return { sortedMembers, revealed, silent, seedPreimage };
}

function arrange(p: Prepared, seed: string, keys: readonly string[]): LotteryResult {
  const keyed = p.revealed.map((id, i) => ({ id, key: keys[i] as string }));
  keyed.sort((a, b) => byId(a.key, b.key) || byId(a.id, b.id));
  return { seed, order: [...keyed.map((k) => k.id), ...p.silent], revealed: p.revealed, silent: p.silent };
}

/** The deterministic turn order from the reveals (see the module comment). */
export function finalize(circleId: string, members: readonly string[], reveals: Reveals, sha256: Sha256Hex): LotteryResult {
  const p = prepare(circleId, members, reveals);
  const seed = sha256(p.seedPreimage);
  return arrange(
    p,
    seed,
    p.revealed.map((id) => sha256(`${seed}${id}`)),
  );
}

export async function finalizeAsync(
  circleId: string,
  members: readonly string[],
  reveals: Reveals,
  sha256: Sha256HexAsync,
): Promise<LotteryResult> {
  const p = prepare(circleId, members, reveals);
  const seed = await sha256(p.seedPreimage);
  const keys = await Promise.all(p.revealed.map((id) => sha256(`${seed}${id}`)));
  return arrange(p, seed, keys);
}
