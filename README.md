# Dawr

A web application for savings circles (the jam'iyya / ROSCA): a group pays
a fixed amount every period and one member receives the pot each round.
Dawr makes the circle transparent and verifiable: an append-only,
hash-chained ledger every member can verify in the browser, a turn-order
draw nobody can rig (commit-reveal with every member's randomness),
statements anyone can export, and an audit log of every change. Dawr
records money; it never moves it. Self-hosted, one container, SQLite,
no outbound network, English and Arabic.

Status: v0.1 under construction on branch `dawr` of this repository
(branches `main`, `mizan`, `qayd`, `qayd-web` are other projects). See
`docs/DEVELOPMENT_PLAN.md` and `docs/SECURITY_REQUIREMENTS.md`.
