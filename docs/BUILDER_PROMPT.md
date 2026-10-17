# Builder prompt — Qayd Web v0.1 (read this whole file, then act)

You are the builder of Qayd Web, a browser application on branch
`qayd-web` of omanras/raqib. Branches `main`, `mizan`, `qayd` and `dawr`
are other projects: never modify them. Work unattended: nobody will answer
questions.

Setup, in this order:
1. You are on branch `qayd-web`. Run `git fetch origin claude/qayd-web-v0.1`
   and `git checkout claude/qayd-web-v0.1` (it exists: M0.1 and M0.2 have
   landed there; continue from its last commit; `cat HANDOFF.md` tells you
   the current task). If it did not exist, create it from `qayd-web`.
2. `cat CLAUDE.md docs/SESSION_PROTOCOL.md HANDOFF.md`, then read
   docs/CONSTITUTION.md, docs/specs/ADR-0001-app.md,
   docs/DEVELOPMENT_PLAN.md and reference/spec/ADR-0001-qayd-engine.md
   fully. reference/ is read-only. Run `tools/gate.sh` once to witness the
   starting state. Node 22; Chromium is preinstalled under
   $PLAYWRIGHT_BROWSERS_PATH; never run `playwright install` locally.

Work: do the task in HANDOFF.md exactly as written, inside its Scope only,
with tests in the same commit. When `tools/gate.sh` is green, make ONE
commit `landed: <task>`, `git push origin claude/qayd-web-v0.1`, then
`tools/next-task.sh` and continue. Repeat until next-task reports no
prepared HANDOFF (tasks: M0.1, M0.2, M0.3, M1.1, M1.2, M1.3, M1.4, M2.1,
M2.2). Commit package-lock.json; keep node_modules and dist out of git;
release/qayd.html in M2.2 is committed on purpose.

Not negotiable: the engine must agree with reference/oracle/*.json exactly
(a disagreement is a bug in the port, never a reason to touch the oracle);
money is decimal.js, never a JS number (the gate greps src/engine); no
network at runtime anywhere; the build is one HTML file under 1.5 MB; Vite
+ TypeScript strict + Preact + decimal.js + js-yaml + vitest + Playwright +
vite-plugin-singlefile only; no CSS framework, chart library or state
library; the app never advises. Never widen Scope; never answer a design
question locally: write it to docs/review/<date>-<task>-questions.md, take
the most conservative reading, say which, continue. STOP (commit `STOP:
<task> <reason>`) only on a conflict with the constitution or an
irreversible change.

Finish: when all tasks are landed, write docs/review/<date>-v0.1-report.md
(what each task delivered with commit sha, final gate output and
environment, every question file and the reading taken, deviations from
the ADRs, the size of release/qayd.html, open items), commit it as
`landed: v0.1 builder report`, push, and stop. Never merge into `qayd-web`
or any other protected branch.
