# HANDOFF — M7.13  (the third field run: ADR-0007 Amendment AF)

Task: what the third field run found (docs/review/2026-11-11-third-field-run.md, F1 to F4), fixed as ADR-0007
Amendment AF rules it: a watch that cannot read the Sysmon channel judges its trees by the host's own record, says so
at once, and its report says it truly and in one line.

Scope:
  raqib/host.py, tests/, docs/THREAT_MODEL.md, docs/GUIDE.md, README.md (the "Where it runs" sentence only), docs/review/

Exit criteria:
- E1 (AF-1) While no round of the watch has read the channel, each tree's source is the host's own record and its source text says why. Tested as the person meets it: a host watch whose reader finds Sysmon and fails every channel read (access denied), a tree with a child curl: the findings and knocks (ids, rules, trees) equal those of the same rounds on a reader with no Sysmon. Not touched, tested: a first round that reads the channel gives os sources in that round; the no-Sysmon machine's lines are today's.
- E2 (AF-2) The first failed read with no earlier read kept knocks once (HOST-HOLE, its own rate-limit id; in the KNOCKS ledger) and prints one terminal line naming the reason and an elevated terminal; 216 failed rounds are one knock; a failure after kept reads is one knock for its episode. Not touched, tested: no Sysmon is no such knock; each round's hole is still recorded.
- E3 (AF-3) The report's SYSMON line: all rounds read is byte for byte today's; none read and some read say so with the counts and the first reason; never "the rounds read its channel" beside a CHANNEL line with 0 reads kept.
- E4 (AF-4) The text report folds the round channel-read holes that differ only by round and time into one line (ranges, count, words once, first and last time); the HOLES header keeps the count and says the lines. Not touched, tested: other kinds, two reasons as two lines, rounds.jsonl, the state, the JSON, RESULT and the exit code.
- E5 (AF-5) A test states today's behaviour for an unnamed program under a benign tree whose child curl talks while it never does. If the act is only a note on the benign tree: change nothing, write docs/review/2026-11-11-M7.13-questions.md.
- E6 (AF-6) THREAT_MODEL and docs/GUIDE.md say: the channel needs an elevated terminal; a read after kept reads that fails leaves the os sources (a hole); what an agent without hooks reads with its own code is in no source; the watched read the watcher's record in the field. README's "Where it runs" names the elevated terminal in one clause. tests/test_docs.py and tests/test_readme_top.py stay green as written.
- E7 Gate green; code and tests ASCII; the kinds and every fp_budget unchanged; no address, host or user name of the field run anywhere in the tree.
Not in scope: raqib/app.py and the page (the window's list of holes), the os-sysmon command, new rules, Q-1 and Q-3, M7.10.
Commit: `landed: M7.13 the third field run` or `STOP: M7.13 <reason>`.
Read HANDOFF.md and do only the task it specifies.
