# HANDOFF — M7.13 REDO  (ADR-0007 Amendment AG on review 2026-11-11-M7.13.md)

Task: the REDO of M7.13 (3c35d06): ADR-0007 Amendment AG, rulings AG-1 to AG-10, on top of Amendment AF. The code of
AF-1 to AF-4 and its tests stand; this changes what AG names and nothing else.

Scope:
  raqib/host.py, tests/, docs/THREAT_MODEL.md, docs/GUIDE.md, docs/review/2026-11-11-M7.13-questions.md

Exit criteria:
- E1 (AG-1) A tree given the host's record only because no round had read the channel is attached again as the os source in the first round it is in after a kept read; its earlier host lines stay judged; an act both sources saw is one act. Tested through rounds and the report: round 1's read not back in time, round 2 on read. Not touched, tested: a host source for another reason stays; a watch that never reads is AF-1's.
- E2 (AG-2) The cause is a word the code decides from the reader's error (denied, not back in time, could not be run, other); the elevated terminal is named only for denied; the knock's body starts with the cause and fits the notifier's cut, tested with a long real-shaped stderr. The hole's words unchanged.
- E3 (AG-3) AF-2's one terminal line also says what is not seen and how trees are judged until a round reads; a tree's attach line and source text carry the cause's few words only. Tested on a watch with trees: one line with the reason and the advice, however many trees.
- E4 (AG-4) The AB-3 note, the CHANNEL line with no read kept (headed by that fact; no "record None") and the SYSMON line's N are true; both lines of a watch whose every round read are byte for byte as before.
- E5 (AG-5) One folded line per episode: holes before the first kept read and after a restart are two lines; the moved-start clause is asserted.
- E6 (AG-6, AG-7) THREAT_MODEL's bullet is true as AG-6 says. docs/GUIDE.md "Watch the host" gets one paragraph written to AG-1 to AG-6; tests/test_readme_top.py GUIDE_NEW gains its sentences and tests/test_host_sources.py's paragraph count is 15. README.md is not touched.
- E7 (AG-10) No test reads a file under docs/review. The questions file notes which questions AG answered.
- E8 Gate green; code and tests ASCII; no address, host or user name of the field run anywhere in the tree.
Not in scope: README.md, raqib/app.py and the page, the os-sysmon command, new rules, a knock for a silent or restarted channel, Q-2's behaviour.
Commit: `landed: M7.13 REDO the third field run` or `STOP: M7.13 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
