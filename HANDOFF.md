# HANDOFF — M10.1  (ADR-0011 Amendment B: the event, `raqib-event/1`)

Task: the event as a shape and the one pure module that builds it; the rules' ATT&CK ids. The watch does not write events yet (M10.2).

Scope:
  raqib/event.py (new), raqib/rules/engine.py, raqib/rules/silence.py, raqib/rules/cross.py, raqib/rules/tree.py, raqib/rules/catalog/*.yaml (the `attack` keys only), raqib/report.py (rule_table), raqib/cli.py (check-rules only), docs/specs/EVENT.md (new), tests/, docs/review/2026-11-13-M10.1-questions.md

Exit criteria:
- E1 (B-1) raqib/event.py: pure functions, one per kind (finding, source-finding, note, tree, hole, knock, heartbeat, watch start and end), each from a ledger entry of raqib/host.py's HostWatch as it is (findings, source_findings, holes, notes, dark_notes, knock_rows(), the trees of state(), state()) plus the watch's facts and the time given by the caller. No import of host.py or watch.py at module level that runs code; no clock, file, network or environment read (a test greps the module for time, socket, os.environ, open). `event.check(obj)` returns a list of problems; `event.line(obj)` the one line (B-3).
- E2 (B-2, B-4) Every key of B-2, in B-2's order of meaning; a key the entry does not hold is absent. Tested per kind on entries made by fixture watches (B-7: tests/test_rhythm.py and tests/test_host_quiet_rhythm.py show how a fixture HostWatch is run; source findings and holes need a run that makes them, as tests/test_acts_judged.py or tests/test_host_sources.py do). Each built event has check() == [] and adds no text its entry or the report does not hold (tested: every string value of the event is found in the entry, the rule, or the watch's facts).
- E3 (B-3) The same entries give the same lines byte for byte (run twice); keys sorted, compact, ASCII; ids "<run>:<n>" unique and rising within a run.
- E4 (B-5) `attack` and `attack_note` are optional keys the engine validates when present (the id's pattern; a non-empty list or a note); every catalog rule declares B-5's table exactly (a test holds the table); `raqib check-rules` fails a catalog rule with neither; silence.py, cross.py and tree.py declare theirs; report.rule_table rows gain "attack". A user rule without the key loads as before (tested through engine.load_catalog with user_rules). The rules' matches, fixtures, budgets and summaries are byte for byte what they are apart from the added keys.
- E5 (B-6) docs/specs/EVENT.md: every key, required keys per kind, one example line per kind (equal to what the module builds from a named fixture run; a test compares), the mapping table to OCSF Detection Finding and ECS. A test fails on a key the module can emit that the document does not name, and the reverse.
- E6 Gate green; ASCII outside docs; no new test reads docs/review; no real host, user or address in any example (use host.example, 192.0.2.x).
Not in scope: raqib/host.py, raqib/watch.py, raqib/app.py, raqib/ui.py, raqib/ruleform.py, raqib/overlay.py, any sink or forwarder, README.md, docs/GUIDE.md.
If an exit criterion needs a file outside Scope: STOP and say which (the questions file).
Commit: `landed: M10.1 the event` or `STOP: M10.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
