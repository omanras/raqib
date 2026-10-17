# Session protocol

1. Open: `git checkout claude/qayd-web-v0.1` (create it from `qayd-web`
   if it does not exist). `cat HANDOFF.md`. State the task back in one
   line. Run `tools/gate.sh` to witness the starting state.
2. Work only inside `Scope:`. If the task needs a file outside scope, STOP.
3. Every engine module ships with its tests in the same commit; every
   screen ships with at least one e2e step once e2e exists.
4. Close: `tools/gate.sh` green -> single commit `landed: <task>`; else
   `STOP: <task> <reason>` with the reason in
   `docs/review/<date>-<task>-questions.md`.
5. Never answer a design question locally: write it to the questions file,
   take the most conservative reading, say which, continue. STOP only on a
   conflict with docs/CONSTITUTION.md or an irreversible change.
6. After a `landed:` commit: `git push origin claude/qayd-web-v0.1`, then
   `tools/next-task.sh`; when it reports no prepared HANDOFF, write
   `docs/review/<date>-v0.1-report.md`, commit `landed: v0.1 builder
   report`, push, stop.
7. `reference/` is read-only. Branches `main`, `mizan`, `qayd`, `qayd-web`
   are never written by the builder.
