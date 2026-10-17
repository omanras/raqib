# MIZAN — read this first, every session

Mizan is a gate for detection rules. A Sigma rule may enter a rule set only
with evidence: events it must match, events it must not match, and a declared
false-positive budget measured on a benign corpus. Mizan is deterministic,
offline, and public. It lives on branch `mizan` of this repository; branch
`main` is a different project (Raqib) and is never touched from here.

## Non-negotiable rules
1. Read `HANDOFF.md` and do ONLY the task it specifies. Touch only the paths
   listed under `Scope:`. Anything else is out of scope -> STOP.
2. One micro-task per commit. Every commit message starts with `landed:` or
   `STOP:`. Never leave the tree dirty.
3. Deterministic only. There is no model anywhere in Mizan. A rule either
   matches an event or it does not, and the answer is the same on every run.
4. No evidence, no rule. A rule without positive and negative fixtures is red.
   A rule whose fixtures did not run is red, never "unknown is fine".
5. No network calls from check, test, match or corpus. They must work offline.
6. Design questions are returned in `docs/review/<date>-<task>-questions.md`,
   never answered locally; take the most conservative reading and continue.
7. Keep `HANDOFF.md` <= 30 lines. Keep every file ASCII-safe except docs.

## Layout
- `mizan/`        the package: loader, matcher, condition, fixtures, corpus,
                  report, cli (stdlib + PyYAML; pySigma only in export.py)
- `rules/`        example rule set: `<name>.yml` + sidecar fixtures
                  `<name>.positive.jsonl` and `<name>.negative.jsonl`
- `corpus/`       benign events, JSON lines, one file per logsource
- `docs/`         CONSTITUTION, DEVELOPMENT_PLAN, SESSION_PROTOCOL, specs/,
                  handoffs/, review/
- `tools/`        gate.sh, next-task.sh
- `tests/`        every feature has a test; every rule has fixtures

## Exit of every task
`tools/gate.sh` must be green. If it is not, the task is not landed.
