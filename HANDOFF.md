# HANDOFF — M7.17  (the rhythm and a tree that is quiet at the sample: ADR-0007 Amendments AP and AQ)

Task: a tree's source beats are taken only in a round the tree is in; a tree that is quiet at the sample keeps a source
whose beats nothing judges (the final poll counts them "in no round"). Rulings AP-1 to AP-4.

Scope:
  raqib/host.py, raqib/rules/fixturegen.py (AQ-1), raqib/rules/catalog/HOST-RHYTHM.yaml, tests/ (the rule's fixtures and tests/fixtures/host/make.py included), tools/rig/check.py, docs/THREAT_MODEL.md, docs/review/

Exit criteria:
- E1 (AP-2) In a round, a quiet tree whose source gained a beat since the last round gets a HostTree line of that round written by the code that writes a candidate's line, with input_meta.class "quiet" and input_meta.rhythm from `_rhythm` (same ring, K, W, R). Tested through rounds and the report with a tree seen at one sample and then quiet, whose os source reads three cycles (a talk to one destination, a child within 30 s) between samples: HOST-RHYTHM fires in the round that reads the third, once, cites its beats, and knocks as a candidate's does; RHYTHM BEATS no longer counts those beats as "in no round".
- E2 (AP-2, not touched; a test each) A quiet line makes no NEW-AGENT or NEW-AGENT-UNKNOWN finding and changes no tree's history, candidate_before or first round; every rule of the catalog that reads a HostTree line gives on the existing fixtures what it gave (the gate's check-rules), and a test states what each gives on a quiet line; a quiet tree with no new beat has no line; a gone tree has none; a named quiet tree's rhythm does not fire HOST-RHYTHM (named: NEW-AGENT's); a benign quiet tree's rhythm is judged as a benign candidate's is.
- E3 (AP-3) HOST-RHYTHM.yaml: the match takes class candidate or quiet (by what the engine's match already offers; a new match operator is a design question: questions file); its fixtures gain one quiet positive and two quiet negatives (no cycle; a few beats of a long-lived service), made by tests/fixtures/host/make.py; fp_budget is the measured number and the comment says how it was measured; holes and description say the reach and what is out.
- E4 (AP-4) tools/rig/check.py X12: MET when no beat waits for the final poll, MISSED otherwise (no longer OPEN); tests/test_rig_check.py follows.
- E5 THREAT_MODEL says it (no milestone tokens). Gate green; code and tests ASCII; no test reads docs/review or asserts the real clock.
- E6 (AQ-1 to AQ-4) Every existing generated fixture is byte for byte what it is; a kept tree with a new beat gets its line (class kept) as a quiet one does; a line for a tree not in the round leaves its connections and children as the sample knows them (a test: back in a round, nothing is new that was old); a test states the ring's gap.
Not in scope: beats that arrive after the last round (said, as today); the final poll; raqib/discover.py; raqib/app.py; the clipboard; new rules.
Commit: `landed: M7.17 the rhythm of a quiet tree` or `STOP: M7.17 <reason>`.
Read HANDOFF.md and do only the task it specifies.
