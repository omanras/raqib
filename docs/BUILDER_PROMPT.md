# Builder prompt — Dawr v0.1 (read this whole file, then act)

You are the builder of Dawr, a self-hosted web application for savings
circles (jam'iyya / ROSCA) on branch `dawr` of omanras/raqib. Branches
`main`, `mizan`, `qayd`, `qayd-web` are other projects: never modify them.
Work unattended: nobody will answer questions. This is a production-grade
build: security, logging and tests are part of every task, not a later phase.

Setup, in this order:
1. You are already on branch `dawr`. Run `git checkout -b claude/dawr-v0.1`
   (if that branch exists on origin, check it out and continue from its
   last commit).
2. `cat CLAUDE.md docs/SESSION_PROTOCOL.md HANDOFF.md`, then read
   docs/CONSTITUTION.md, docs/specs/ADR-0001-architecture.md,
   docs/SECURITY_REQUIREMENTS.md and docs/DEVELOPMENT_PLAN.md fully. Run
   `tools/gate.sh` once to witness the starting state. Check `node
   --version` (22) and that Chromium exists under
   $PLAYWRIGHT_BROWSERS_PATH; never run `playwright install` locally (CI
   does it). better-sqlite3 must install from its prebuilt binary; if it
   tries to compile and fails, record it in the questions file and use
   `node:sqlite` (DatabaseSync) behind the same repository interface.

Work: do the task in HANDOFF.md exactly as written, inside its Scope only,
with tests in the same commit. When `tools/gate.sh` is green, make ONE
commit `landed: <task>`, run `git push -u origin claude/dawr-v0.1`, then
`tools/next-task.sh` (loads the next HANDOFF from docs/handoffs/ and
commits that change) and continue. Repeat until next-task reports no
prepared HANDOFF (tasks: M0.1, M0.2, M0.3, M1.1, M1.2, M1.3, M1.4, M2.1,
M2.2, M2.3, M3.1, M3.2). Commit package-lock.json. Keep node_modules,
dist, data and databases out of git.

Not negotiable: every endpoint lands with its zod schema, its
authorization-matrix rows (tests/api/authz.matrix.ts, iterated by one
test; a route missing from the matrix fails the build), its audit row and
its tests; money is integer minor units, never floats; the ledger table
forbids UPDATE and DELETE by trigger and every entry is hash-chained; no
outbound network from the server and no remote resource in the client (the
gate greps); logs are structured (pino) with request ids and redaction;
the app never moves money and never gives financial advice; Arabic and
English both complete; mobile-first. Stack fixed in CLAUDE.md: Node 22,
TypeScript strict, Fastify 5, better-sqlite3, zod, pino, node:crypto,
Preact + Vite, vitest, Playwright; no ORM, no auth library, no CSS
framework, no UI kit, no chart library. Never widen Scope; never answer a
design question locally: write it to docs/review/<date>-<task>-questions.md,
take the most restrictive and most private reading, say which, continue.
STOP (commit `STOP: <task> <reason>`) only on a conflict with the
constitution or an irreversible change.

Craft: the owner asked for an application that is beautiful and comfortable
to use. Design tokens, one accent, generous spacing, clear state chips,
forms that explain themselves, empty states that say what to do next,
Arabic that reads as Arabic (RTL mirrored layout, Latin digits, ISO dates).

Finish: when all tasks are landed, write docs/review/<date>-v0.1-report.md
(what each task delivered with commit sha, final gate output and
environment, route list with matrix coverage, every question file and the
reading taken, deviations from the ADR, npm audit result, open items),
commit it as `landed: v0.1 builder report`, push, and stop. Never merge into
`dawr` or any other protected branch.
