# HANDOFF — M7.22 REDO  (ADR-0007 Amendment AZ on review 2026-11-13-M7.22.md)

Task: the REDO of M7.22 (b9788f6). AY stands as built except where AZ changes it. Rulings AZ-1 to AZ-6.

Scope:
  raqib/host.py (`_give_held` and what follows from it), raqib/rules/fixturegen.py, raqib/rules/catalog/HOST-RHYTHM.yaml (holes, description), tests/, docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.22-questions.md

Exit criteria:
- E1 (AZ-1) A child is given to a held tree only when that tree's root pid is in the act's `via` (strictly above the child). The act that is the held root itself stays its candidate's. So no candidate is left with no act by the giving, and none is dropped: the code that dropped one is gone. Tested through rounds: (a) the field case still makes no HOST-RHYTHM on the ancestor and the children are the held tree's; (b) trees that are not history: a talker that first talks in round n above a tree held quiet arrives in round n (NEW-AGENT-UNKNOWN on it, once), with one act (the held root) and none of the children under it; the held tree says no arrival again.
- E2 (AZ-2) A child is given only when the held tree's host record can be written this round (the same conditions `_host_lines` writes under: read them there, do not restate them differently); else it stays the candidate's, is judged there, and one note per held tree says why. Tested for a tree with no host record and for a source that ended with a hole.
- E3 (AZ-3) A child once given to a held tree is not new on another tree later: through rounds, the held tree's root leaves the sample and its still-living child appears under the ancestor (via []): no HostChild line, no finding and no act beat for it on the ancestor; a child the held tree never had is new there as before.
- E4 (AZ-4) The HostChild line of a given child carries the tree word of the candidate the inventory had it under (one key in input_meta; the rule's fixtures unchanged: byte for byte).
- E5 (AZ-5) The rule's holes and description and docs/THREAT_MODEL.md (no milestone tokens) say what is true: the giving covers the sample's children only; where the ancestor has an os source its follow still holds the held tree's events and its rhythm and source findings still read them; an act is in the held tree's record only where that record can be written; the held root is its parent's act. Every sentence the packet's section 7 names is corrected.
- E6 (AZ-6) The tests AZ-6 lists, each able to fail (the "no arrival again" assertion on trees that are not history; DESTRUCT-CMD on the held tree; two held roots on one path; a held tree a candidate again).
- E7 Gate green; ASCII outside docs; no new test reads docs/review; no real address.
Not in scope: raqib/discover.py, raqib/hooks/, raqib/event.py, raqib/eventlog.py, the os source's beats (M7.24), severity, any other rule.
If an exit criterion needs a file outside Scope: STOP and say which (the questions file). Do not change a guard test to pass.
Commit: `landed: M7.22 REDO a child under a held tree's root is that tree's` or `STOP: M7.22 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
