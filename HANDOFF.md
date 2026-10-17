# HANDOFF — M3.2  (phase 3: operations, docs, release)

Task: make Dawr deployable and documented for a self-hosting organizer.

Scope:
  deploy/
  docs/OPERATIONS.md
  README.md
  SECURITY.md
  CHANGELOG.md
  tools/gate.sh
  .github/workflows/
  docs/review/

Exit criteria:
- E1 deploy/Dockerfile (multi-stage, node:22 slim, non-root user,
     read-only root fs, /data volume, HEALTHCHECK on /api/health),
     deploy/compose.yml (app + optional Caddy with automatic TLS,
     documented), deploy/backup.sh (sqlite `.backup`, dated, keep 30)
     and restore steps; `docker build` runs in CI if Docker is available
     there (else documented as a manual check with the command).
- E2 docs/OPERATIONS.md: first run (SESSION_SECRET, BASE_URL,
     TRUST_PROXY), upgrade, backup and restore, rotating the secret,
     reading logs (fields, request id lookup), retention of logs and
     audit, resource needs, and what to do if the ledger verify is red.
- E3 README.md: what Dawr is and is not (never moves money), the
     ten-minute self-host, how a circle runs from invite to completion
     (organizer and member paths, in text with the screen names), the
     trust guarantees (chain, draw, statements) in plain language, the
     languages, how to report a security issue (SECURITY.md).
- E4 CHANGELOG.md v0.1.0 listing the tasks; `npm version` field set to
     0.1.0; gate adds a check that README's commands exist as npm
     scripts.
- E5 Gate green; CI green on the branch.

Not in scope: new features or screens.
Commit: `landed: M3.2 operations, docs, release` or `STOP: M3.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
