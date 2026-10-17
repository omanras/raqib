# HANDOFF — M2.3  (phase 2: ledger, statement, draw screens)

Task: the trust screens per ADR §5: Ledger with in-browser verification
and export, Statement, Draw.

Scope:
  client/
  shared/
  tests/e2e/
  tests/unit/
  docs/review/

Exit criteria:
- E1 Ledger: entries newest first with type, actor, time, a readable
     summary per type and the raw payload on expand; "Verify chain" runs
     `shared/ledger.verify` in the browser (Web Crypto SHA-256, same
     canonicalization; a unit test proves browser and node hashes agree
     on the test vectors) and shows green with the last hash, or red
     with the first broken seq; export JSON and CSV (copy and download).
- E2 Statement: whole circle and "mine"; per round and per member;
     totals; every line links to its ledger seqs; CSV export.
- E3 Draw: for members: commit (the browser generates the secret, shows
     it once, stores it in localStorage keyed by circle, warns to save
     it), reveal (from storage or pasted), status of others (counts, no
     secrets); for organizers: open with deadlines, close commits,
     finalize; result screen: the order, the seed, and "Recompute"
     running `shared/lottery.finalize` in the browser on the ledger's
     reveals and comparing with the server's order (green/red).
- E4 Offline-honest: the ledger screen shows the time of the last
     verified fetch and refuses to label stale data as current (A10).
- E5 e2e: a 3-member circle runs the full draw in three browser
     contexts; the client recompute matches; the ledger verifies green;
     an API-level tamper (test edits a payload through a raw SQL helper
     that bypasses the trigger by recreating the table in the test DB)
     turns the verify red at the right seq. Gate green.

Not in scope: new server routes beyond what M1.x delivered.
Commit: `landed: M2.3 ledger, statement, draw screens` or `STOP: M2.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
