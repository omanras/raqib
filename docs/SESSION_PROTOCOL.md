# Session protocol

1. Open: `git checkout claude/qayd-v0.1` (create it from `qayd` if it does
   not exist). `cat HANDOFF.md`. State the task back in one line. Run
   `tools/gate.sh` to witness the starting state.
2. Work only inside `Scope:`. If the task needs a file outside scope, STOP.
3. Every rule type ships with a holding case and a breaching case in the
   same commit; every loader ships with a valid and an invalid fixture.
4. Close: `tools/gate.sh` green -> single commit `landed: <task>`; otherwise
   `STOP: <task> <reason>` with the reason also in
   `docs/review/<date>-<task>-questions.md`.
5. Never answer a design question locally. Write it to the questions file,
   take the most conservative reading, say which reading you took, and
   continue. STOP only on a conflict with docs/CONSTITUTION.md or a change
   that cannot be undone.
6. After a `landed:` commit: `git push origin claude/qayd-v0.1`, then
   `tools/next-task.sh` to load the next HANDOFF and continue. When
   next-task reports no prepared HANDOFF, write the final report to
   `docs/review/<date>-v0.1-report.md`, commit it as
   `landed: v0.1 builder report`, push, and stop.
7. Branches `main`, `mizan` and `qayd` are never written by the builder.
