# Commander order, 2026-10-16 (recorded under A8)

On 2026-10-16 the commander gave this order in the builder's interactive
session (session_019bYV3XcpQGQtqJsEkrmbhY), verbatim:

> delete claude/M0.1b-alt. and start coding the full project don't come back
> to me until you finish the projetc

The constitution says only the commander may widen scope. What follows is how
the builder carries out this order. Each point departs from
SESSION_PROTOCOL; the commander should ratify or overrule each one.

- **One branch for every task.** All tasks after M0.1b land in sequence on
  `claude/v0.1`, based on `claude/M0.1b` (bdb41b0). Each task is one
  `landed:` commit, and gate green is required for every one.
- **The builder advances HANDOFF.md.** It writes HANDOFF.md before each task
  (SESSION_PROTOCOL 6 reserves this to the judge or commander). Handoffs that
  did not already exist are drafted from DEVELOPMENT_PLAN.md and the ADR, and
  stored in `docs/handoffs/`.
- **Review without a judge.** After each landing the read-only `reviewer`
  agent writes a packet to `docs/review/<date>-<task>.md`. Findings that can
  be fixed inside a task's scope are fixed in a `landed: <task> REDO` commit.
  The judge is not run, because it would STOP on every design question and
  the order says not to stop. STOP-class items (design questions, scope
  widening, SILENCE or SECRET) are collected in the per-task questions files
  for the commander.
- **Design questions** are answered with the narrowest reading of the ADR and
  the constitution. Each answer is written down as an assumption to ratify.
  None is treated as settled.
- **`main` is untouched.** Nothing is pushed to `main` and nothing is
  force-pushed (A-8). Merging is the commander's act.

Not doable by the builder: M3.3 (an outside reader runs the quickstart and
files an issue) needs a human. The real-model run in M2.2 needs a model
endpoint and the commander's credentials.
