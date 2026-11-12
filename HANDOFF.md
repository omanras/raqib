# HANDOFF — M7.14  (a tree's follow that never returns: ADR-0007 Amendment AI)

Task: on the commander's machine every pass of a tree's os follow was ended at 10 s, because it asks wevtutil for the
whole Sysmon channel. Make the pass a bounded question, and judge a tree whose follow reads nothing by the host's own
record too (ADR-0007 Amendment AI, rulings AI-1 to AI-3).

Scope:
  raqib/hooks/os_sysmon.py, raqib/host.py, tests/, docs/THREAT_MODEL.md, docs/GUIDE.md, docs/review/

Exit criteria:
- E1 (AI-1) A follow's pass under `raqib watch --host` asks a bounded query: first pass since the watch's start, later passes the records after the highest read, capped as the round's read; a cut is a hole. Tested through the follow with a stand-in wevtutil that records its arguments and returns events across three passes: every event once, none lost, the arguments bounded. Not touched, tested: `raqib os-sysmon` by a person (live and --from) asks and writes what it did.
- E2 (AI-2) A tree whose os follow had two passes and none that read gets the host's own record too from the next round it is in; its source text says why with the cause word; a child curl in that round's sample is judged (NET-TOOL) as on a machine without Sysmon. When a pass reads, the host lines stop. Tested through rounds and the report. Not touched, tested: a tree whose follow reads has no host line.
- E3 (AI-1, said) THREAT_MODEL and the guide say what a bounded follow no longer reads (the tree's past before the watch; a child older than the watch unless seeded). If the follow cannot be seeded from the round's sample without a design choice, do not choose: write docs/review/2026-11-12-M7.14-questions.md.
- E4 (AI-3) The guide and THREAT_MODEL say "in no source of the host watch; the proxy source records the tool call where the agent is pointed at it; the host watch does not read the proxy's trace". The pin in tests/test_readme_top.py (HOST_UNREAD) is amended with the sentence; README.md is not touched.
- E5 Gate green; code and tests ASCII; no test reads docs/review; no address, host or user name of the field in the tree.
Not in scope: raqib/hostwin.py (the unread start time), raqib/app.py, new rules, ADR-0011, README.md.
Commit: `landed: M7.14 a follow that returns` or `STOP: M7.14 <reason>`.
Read HANDOFF.md and do only the task it specifies.
