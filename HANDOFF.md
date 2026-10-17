# HANDOFF — M0.3  (phase 0: persistence, audit, logging)

Task: SQLite persistence, the append-only ledger table, the audit writer
and request logging per docs/specs/ADR-0001-architecture.md §3, §6-§8.

Scope:
  server/
  tests/unit/
  tests/api/
  docs/review/

Exit criteria:
- E1 `server/db/`: open better-sqlite3 in WAL with foreign keys on;
     numbered migrations `server/db/migrations/NNNN_*.sql` applied at
     startup and recorded; schema for users, sessions, circles, members,
     rounds, contributions, payouts, ledger, invites, audit,
     recovery_codes, migrations; ledger has UNIQUE(circle_id, seq) and
     triggers that raise on UPDATE and DELETE (a test proves both).
- E2 Repositories with typed functions (no string-built SQL with user
     data; prepared statements only); `appendLedger(circleId, actor,
     type, payload)` computes seq and hash inside one transaction and
     returns the entry; a concurrent-append test (two transactions)
     never produces a gap or duplicate seq.
- E3 `server/audit.ts`: `audit(req, {circleId, action, target})` writes
     actor, action, target, requestId, ip prefix (/24 v4, /48 v6), ua
     hash; a test asserts the row.
- E4 Logging: pino with redaction (cookie, authorization, password,
     secret, token, recovery code), requestId per request, route-level
     log line with status and duration, no raw URL ids where a route
     pattern exists; a test captures the stream and asserts redaction of
     a known secret.
- E5 Config module per ADR §8: refuses to start in production without
     SESSION_SECRET; generates one into DATA_DIR in development. Health
     route reports db ok and the applied migration count. Gate green.

Not in scope: auth, circles routes, client.
Commit: `landed: M0.3 persistence, audit, logging` or `STOP: M0.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
