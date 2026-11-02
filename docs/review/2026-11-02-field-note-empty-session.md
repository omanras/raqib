# Field note: an empty session reads CLEAN (commander's first run, 2026-11-02)

First run of main (c58710f) on the commander's Ubuntu VM. Gate: 786 passed,
18 skipped, GREEN. install-hooks.sh wrote the six hooks; `claude -p` then
failed at once ("OAuth session expired"). The trace holds two records:
session_start at 13:36:10.229Z and session_end at 13:36:10.873Z, same
session, no tool, no stop. `raqib report` says CLEAN, exit 0, all 11 rules
active, none fired.

Reading: correct under the current rules (no gap over the limit, no open
session, no half pair, order intact; Stop never fires when no turn ran),
and still the wrong answer by A3. A session that started and ended in
644 ms with no tool and no turn is either a failed start or an agent whose
work was not seen. Neither is "clean". Raqib knows the difference between
nothing and silence for gaps, pairs and open sessions, but not yet for a
whole session that did nothing.

Candidate (ADR-0002 kind: demand, severity medium): SILENCE-EMPTY - a
session with session_start and session_end (or a start and nothing else)
and zero tool records. Fixtures: this trace (positive) and the quickstart
trace (negative). Place: Phase 4 (M4.2 or its own M4.4). Decided by the
commander at the next HANDOFF advance; recorded here so it is in the tree.
