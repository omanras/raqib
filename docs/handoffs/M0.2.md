# HANDOFF — M0.2  (phase 0: domain core in shared/)

Task: the pure domain of docs/specs/ADR-0001-architecture.md §2 in
`shared/`, with no I/O and no dependencies beyond node:crypto types.

Scope:
  shared/
  tests/unit/
  docs/review/

Exit criteria:
- E1 `shared/money.ts`: minor-unit integers; `parseAmount(text,
     minorUnit)` rejects more decimals than allowed, signs, exponents,
     thousands separators in other than the documented form; `format`
     per currency; sums in bigint or safe integers with overflow checks.
- E2 `shared/schedule.ts`: `dueDate(start, period, dueDay, n)` for
     monthly (day 1-28), weekly and biweekly; tested on month ends and
     leap years; `roundsFor(circle)`.
- E3 `shared/ledger.ts`: `canonical(payload)`, `hashEntry(entry)`,
     `verify(entries)` returning ok or the first broken seq; the genesis
     prev_hash of 64 zeros; a test that flips one byte and sees the
     break at that seq and every later seq still chained to it.
- E4 `shared/lottery.ts`: `commit(secret, memberId)`, `verifyReveal`,
     `finalize(circleId, members, reveals)` with the silent-member rule
     (never revealed -> last, in member-id order), deterministic, with a
     test vector file `tests/unit/lottery.vectors.json` committed so the
     client can recompute identically.
- E5 `shared/state.ts`: circle and round state machines with allowed
     transitions and the reason for each refusal. Property-style tests:
     100 random circles (seeded) keep invariants (pot = contribution x
     members; every member receives exactly once; due dates strictly
     increasing). Gate green.

Not in scope: database, routes, client.
Commit: `landed: M0.2 domain core` or `STOP: M0.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
