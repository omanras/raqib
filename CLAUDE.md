# RAQIB — read this first, every session

Raqib is an external watcher for AI agents. It records what an agent does,
judges it with deterministic rules first, and lets a model raise suspicion —
never acquit. It is a public project. Nothing from the private Haris tree is
ever copied here; only the doctrine.

## Non-negotiable rules
1. Read `HANDOFF.md` and do ONLY the task it specifies. Touch only the paths
   listed under `Scope:`. Anything else is out of scope → STOP.
2. One micro-task per session. End with exactly one commit whose message
   starts with `landed:` or `STOP:`. Never leave the tree dirty.
3. Deterministic first. A rule that can be expressed without a model MUST be
   expressed without a model. The model layer only adds suspicion on top.
4. Silence is an alarm. A capture gap, an empty log, a hook that did not fire —
   these are findings, not "nothing happened".
5. No network calls from the capture path. Capture must work offline.
6. Design questions are returned in `docs/review/<date>-<task>-questions.md`,
   never answered locally.
7. Keep `HANDOFF.md` ≤ 30 lines. Keep every file ASCII-safe except docs.
8. Commander's standing rule (2026-11-03): every file in the project is
   editable by the Table with his permission, and his permission for a
   session is given at its start; `HANDOFF.md`, the ADRs, `docs/handoffs/`
   and `docs/review/` are the Table's to write by his decision. The builder
   stays under rules 1-2: its scope is `Scope:` and nothing else.

## Layout
- `raqib/hooks/`   capture scripts (Claude Code hooks, later: proxy)
- `raqib/rules/`   deterministic rules (YAML) + engine
- `raqib/suspect/` model layer (schema-constrained; raises suspicion only)
- `raqib/ui/`      dashboard (later phase)
- `docs/`          CONSTITUTION, DEVELOPMENT_PLAN, SESSION_PROTOCOL, specs/, review/
- `tools/`         gate.sh, loop.sh, next-task.sh
- `tests/`         every rule has a fixture; every fixture has a positive and a negative

## Exit of every task
`tools/gate.sh` must be green. If it is not, the task is not landed.
