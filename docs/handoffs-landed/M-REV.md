# HANDOFF — M-REV  (independent review of REDO-2/REDO-3 + R#002 conditions)

Task: in a fresh session, review the diffs of commits 70c92f3, 55b280e,
3a20bdf and b91ad82 against docs/CONSTITUTION.md and ADR-0001 (incl.
Amendment B), then apply the three R#002 conditions.

Scope:
  raqib/suspect/
  tests/
  docs/review/
  docs/specs/ADR-0001-architecture.md
  tools/gate.sh
  raqib-M0.1.patch
  raqib-claude-M0.1.bundle

Exit criteria:
- E1 docs/review/<date>-M-REV.md: findings on the four commits with file:line
     citations; every finding either fixed in this task (inside scope) or
     listed as open for the commander. No redesign proposals.
- E2 Anthropic backend: server-side fallback OFF by default; `--allow-fallback`
     enables it; fallback answers remain labelled and counted. Tests cover
     both states.
- E3 `raqib-M0.1.patch` and `raqib-claude-M0.1.bundle` removed from the tree.
- E4 tools/gate.sh adds: fail if any file outside raqib/suspect/backends.py
     imports `anthropic` (Amendment B-3).
- E5 ADR-0001 Amendment B appended verbatim from docs/review/2026-10-17-v0.1-ruling.md
     (B-1..B-4). Gate green.

Not in scope: new rules, UI changes, README beyond the fallback flag line.
Commit: `landed: M-REV independent review + R#002 conditions` or `STOP: M-REV <reason>`.
Read HANDOFF.md and do only the task it specifies.
