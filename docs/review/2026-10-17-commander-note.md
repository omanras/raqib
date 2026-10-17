# Commander note 2026-10-17 — builder allow-list and the Mizan branch

- `.claude/settings.json`: allow-list widened for unattended cloud sessions
  (git fetch/pull/show, pip install, mkdir/cp/mv/chmod, wc/head/tail/diff,
  mktemp, date). Push to `mizan*` denied like `main*`.
- Branch `mizan` (orphan) hosts a separate project, Mizan, a gate for
  Sigma detection rules, built with the same method (CLAUDE.md, HANDOFF,
  gate, hooks). It shares this repository only; nothing of Raqib depends on
  it and nothing of it lands on `main`.
- Raqib is paused by the owner (hardware for the suspect layer not
  available). Open items stay in docs/review (M-FIX1, M3.3, eval).
