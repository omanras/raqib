# HANDOFF — M3.1  (phase 3: security proof and threat model)

Task: prove docs/SECURITY_REQUIREMENTS.md end to end and write the threat
model.

Scope:
  tests/
  server/
  client/
  docs/THREAT_MODEL.md
  docs/review/
  playwright.config.ts
  vitest.config.ts

Exit criteria:
- E1 Every S-item has a test named with its id, green; the matrix covers
     every registered route (the route-listing test); S6.1 audit
     coverage spans every mutating route.
- E2 e2e security: XSS payloads in every free-text field (names, rules,
     method, reference, reason) render as text; CSRF: a request without
     the header is 403; rate limit: the 31st auth request in a window is
     429; session: a copied cookie after logout is 401; IDOR: member B
     fetching circle A's ledger, statement, overview, audit -> 404.
- E3 Egress: a test that stubs `globalThis.fetch`, `dns.lookup` and
     `net.connect` and runs the full API tour; zero calls.
- E4 docs/THREAT_MODEL.md: STRIDE per component (client, API, session
     store, SQLite, ledger, draw, invites, logs, deployment), each threat
     with the control, the test id that proves it, or "open" with the
     plan; a section on what Dawr cannot protect against (a dishonest
     organizer lying about cash received: the ledger shows the claim and
     who made it, nothing more).
- E5 Fixes found by the tests are made in server/ or client/ and listed
     in the questions file. Gate green.

Not in scope: new features.
Commit: `landed: M3.1 security proof and threat model` or `STOP: M3.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
