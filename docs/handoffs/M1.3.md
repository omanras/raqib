# HANDOFF — M1.3  (phase 1: the draw)

Task: the commit-reveal turn-order draw routes per ADR §2 (Lottery) and
§4, on top of shared/lottery.ts.

Scope:
  server/
  tests/api/
  tests/unit/
  docs/review/

Exit criteria:
- E1 `POST /api/circles/:id/draw/open` (organizer, draft -> drawing;
     commit deadline and reveal deadline in the body, each >= 1 hour
     ahead; ledger entry draw.opened), `POST .../draw/commit` (member;
     body {commitment}; once; ledger entry draw.committed with the hash
     only), `POST .../draw/close-commits` (organizer, or automatic at the
     deadline on the next request; ledger entry), `POST .../draw/reveal`
     (member; body {secret}; verified against the commitment; ledger
     entry draw.revealed with the secret), `POST .../draw/finalize`
     (organizer, after all reveals or after the reveal deadline; computes
     the order with shared/lottery.finalize; ledger entry draw.finalized
     with seed and order; positions set; circle stays drawing until
     start).
- E2 A member who never committed cannot reveal; a member who committed
     and never revealed is placed last per the silent-member rule and the
     ledger says so; a wrong secret is refused and audited.
- E3 `GET /api/circles/:id/draw` returns the state for the caller: my
     commitment status, counts, deadlines, and after finalize the seed and
     the order, so the client can recompute.
- E4 Matrix rows for every route; tests for each refusal and for
     determinism (two servers given the same ledger compute the same
     order). Gate green.

Not in scope: rounds, client.
Commit: `landed: M1.3 the draw` or `STOP: M1.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
