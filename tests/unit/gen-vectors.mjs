// Generates tests/unit/lottery.vectors.json and tests/unit/ledger.vectors.json
// from the written specification (ADR-0001 §2), using node:crypto directly and
// none of the code under test. Run: node tests/unit/gen-vectors.mjs
// The output is committed; the unit tests check shared/ against it, and the
// client recomputes against the same files.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const id = (label) => createHash('sha256').update(`id:${label}`).digest('base64url').slice(0, 22);
const secret = (label) => sha(`secret:${label}`);
const asc = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function lotteryCase(name, n, silentIdx) {
  const circleId = id(`circle:${name}`);
  const members = Array.from({ length: n }, (_, i) => id(`${name}:m${i}`));
  const secrets = {};
  const commitments = {};
  members.forEach((m, i) => {
    secrets[m] = secret(`${name}:${i}`);
    commitments[m] = sha(secrets[m] + m);
  });
  const reveals = {};
  members.forEach((m, i) => {
    if (!silentIdx.includes(i)) reveals[m] = secrets[m];
  });
  const sorted = [...members].sort(asc);
  const revealed = sorted.filter((m) => m in reveals);
  const silent = sorted.filter((m) => !(m in reveals));
  const seed = sha(revealed.map((m) => reveals[m]).join('') + circleId);
  const keyed = revealed.map((m) => ({ m, k: sha(seed + m) })).sort((a, b) => asc(a.k, b.k) || asc(a.m, b.m));
  const order = [...keyed.map((x) => x.m), ...silent];
  return { name, circleId, members, secrets, commitments, reveals, expected: { seed, order, revealed, silent } };
}

const lottery = {
  spec: 'commitment = sha256(secret || memberId); seed = sha256(reveals in member-id order || circleId); order = revealed sorted by sha256(seed || memberId), then silent in member-id order',
  cases: [
    lotteryCase('three-all-reveal', 3, []),
    lotteryCase('four-one-silent', 4, [2]),
    lotteryCase('five-two-silent', 5, [0, 4]),
    lotteryCase('two-none-reveal', 2, [0, 1]),
    lotteryCase('twelve-all-reveal', 12, []),
  ],
};

function canonical(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  return `{${Object.keys(v)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`)
    .join(',')}}`;
}

const organizer = id('user:organizer');
const member = id('user:member');
const payloads = [
  ['circle.created', organizer, { name: 'جمعية الحي', currency: 'OMR', contribution: 50000, period: 'monthly', dueDay: 5 }],
  ['member.joined', member, { memberId: id('member:b'), displayName: 'Sara "S." <b>', role: 'member' }],
  ['order.set', organizer, { order: [id('member:a'), id('member:b')] }],
  ['circle.started', organizer, { memberCount: 2, startDate: '2026-11-01', rounds: [{ n: 1, dueDate: '2026-11-05' }] }],
  ['contribution.reported', member, { round: 1, amount: 25000, method: 'cash', reference: 'line\nbreak   tab\t', nested: { z: 1, a: [true, false, null] } }],
  ['contribution.confirmed', organizer, { round: 1, contributionId: id('c:1'), amount: 25000 }],
];
let prev = '0'.repeat(64);
const entries = payloads.map(([type, actor, payload], i) => {
  const seq = i + 1;
  const ts = new Date(Date.UTC(2026, 9, 17, 12, 0, i, 7 * i)).toISOString();
  const c = canonical(payload);
  const pre = `${seq}${ts}${actor}${type}${c}${prev}`;
  const hash = sha(pre);
  const e = { seq, ts, actor, type, payload, prevHash: prev, hash, canonical: c, preimage: pre };
  prev = hash;
  return e;
});
const ledger = {
  spec: 'hash = sha256(seq || ts || actor || type || canonical(payload) || prevHash); genesis prevHash = 64 zeros',
  entries,
};

const dir = new URL('.', import.meta.url);
writeFileSync(new URL('lottery.vectors.json', dir), `${JSON.stringify(lottery, null, 2)}\n`);
writeFileSync(new URL('ledger.vectors.json', dir), `${JSON.stringify(ledger, null, 2)}\n`);
console.log('wrote lottery.vectors.json and ledger.vectors.json');
