# Session protocol

1. Open: `cat HANDOFF.md`. State the task back in one line. Run `tools/gate.sh`
   to witness the starting state.
2. Work only inside `Scope:`. If the task needs a file outside scope, STOP.
3. Every new rule ships with fixtures (positive + negative) in the same commit.
4. Close: `tools/gate.sh` green → single commit `landed: <task>`; otherwise
   `STOP: <task> <reason>` with the reason also in
   `docs/review/<date>-<task>-questions.md`.
5. Never answer a design question locally. Write it to the questions file and STOP.
6. The next HANDOFF is written by the judge/commander, never by the builder.
