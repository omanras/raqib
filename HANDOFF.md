# HANDOFF — M17.1  (ADR-0015 V-1 to V-4: a number for every Raqib)

Task: Raqib says its version where a person looks, the number is 0.2.0, and the gate holds the changelog to it. Read docs/specs/ADR-0015-a-number-for-every-raqib.md and CHANGELOG.md first (the Table wrote both; do not rewrite an entry).

Scope:
  raqib/__init__.py (the number), raqib/host.py (only: the first line the host watch prints and the first line of its report), raqib/watch.py and raqib/report.py (only: the same two lines of a project watch and its report, if they have them), raqib/app.py (only: where the window shows the number), tests/test_version.py (new), tools/gate.sh (only if a step is needed to hold the changelog; else a test does), docs/GUIDE.md (how to read the number and the changelog; the update steps), README.md (only where the sample report is the code's own and changes, and one sentence that points to CHANGELOG.md), docs/SESSION_PROTOCOL.md (one line: the merge moves the number and writes the entry), docs/specs/EVENT.md and any fixture or example a generator of the tree rewrites because the number moved (and for no other reason), docs/review/2026-11-20-M17.1-questions.md; and a test of tests/ ONLY where it holds the number 0.1.0 as a literal, or holds word for word a line this task changes (named in the questions file; no other assertion weakened).

Exit criteria:
- E1 (V-1) `raqib.__version__` is "0.2.0"; nothing else in raqib/ holds a version as a literal (a test greps). `raqib --version` prints `raqib 0.2.0`.
- E2 (V-2) The host watch's first printed line and the first line of its report end with the number in one fixed form (`raqib 0.2.0`, read from `raqib.__version__`); the same for a project watch where it prints such lines. The window shows `Raqib 0.2.0` in its title bar. Tests for each; every existing test that holds one of these lines word for word follows, and nothing else in a report moves.
- E3 (V-3) tests/test_version.py holds: CHANGELOG.md's first `## ` heading is `## <raqib.__version__> - <YYYY-MM-DD>`; the headings' numbers strictly go down the page (compared as numbers, not text); every entry but the oldest has the three parts `What is new:`, `To update:`, `Not measured:`, each with at least one line; the file is ASCII. Each check has a test that feeds a made-up changelog that breaks it.
- E4 Every example and fixture that holds an event's `version` is the code's own after the move (the generators are run; the questions file names each command and each file that changed, and a test that existed before holds that they are the code's own).
- E5 The documents: GUIDE.md says where the number is read, what a move of it means (V-1), where the changelog is, and the update steps for Windows and Linux as CHANGELOG.md gives them; SESSION_PROTOCOL.md's line; README.md's pointer. A test holds the sentences that matter.
- E6 Gate green in the foreground; ASCII outside docs (CHANGELOG.md is ASCII); no finding, no rule, no event's shape changes.
Not in scope: packages, installers, signatures (M17.2), the events' schema, any rule, CHANGELOG.md's entries (the Table's), ADRs.
If an exit criterion needs a file outside Scope: STOP and say which file and which line.
Commit: `landed: M17.1 a number for every Raqib` or `STOP: M17.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
