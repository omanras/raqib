# HANDOFF — M7.22  (ADR-0007 Amendment AY: a process under a tree the watch holds is that tree's)

Task: a child the inventory gives to a talking ancestor is given instead to the quiet or kept tree whose root is on its path (AY-1), and that tree has it as its own act (AY-2). The field case is ADR-0007 AX-4.

Scope:
  raqib/host.py (one place that decides whose a child is, before the round's lines; what follows from it), raqib/rules/fixturegen.py, raqib/rules/catalog/HOST-RHYTHM.yaml (holes, description), tests/, docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.22-questions.md

Exit criteria:
- E1 (AY-1) One function in raqib/host.py, called once per round before any HostTree, HostChild or rhythm line of the round is made: for each candidate of the inventory, each act whose path (the act's `via` pids and its own pid) holds the root pid of a tree the watch holds as quiet or kept, with the same key and its root in this round's process sample, is taken from the candidate and given to that tree. A candidate left with no act by this is what the inventory's own rule makes of a talker with no child (say in the questions file what that is, and test it).
- E2 (AY-2) The held tree's child is in its own host record (a HostChild line in its file), judged there (NET-TOOL and DESTRUCT-CMD on that tree, not the ancestor), and an act beat of its ring; the tree stays quiet; when it gained an act it has its line of the round by `_tree_line` with class quiet (or kept); NEW-AGENT and NEW-AGENT-UNKNOWN say nothing again.
- E3 The field case, through rounds on the fake clock (new inventories in fixturegen): an unknown ancestor that talks to one server every round (its bytes move), an unknown tree under it that is a candidate in round 1 and quiet after, and a new child under that tree in each later round. On this code: no HOST-RHYTHM on the ancestor; the children are the quiet tree's; one of them a network tool: NET-TOOL on the quiet tree. The same test's assertion on the ancestor fails on main's code (show it in the questions file by the finding main makes).
- E4 Not touched, each tested: a child with no held root on its path; a child under a tree that is gone; a nested candidate; a round whose connections were not read (kept); every existing generated fixture byte for byte (the regenerate-and-compare tests pass unchanged).
- E5 The rule's holes and description, and docs/THREAT_MODEL.md (no milestone tokens): the anchor's words ("every process goes to its nearest talking ancestor") gain this exception; AY-3's hole.
- E6 Gate green; ASCII outside docs; no new test reads docs/review; no real address.
Not in scope: raqib/discover.py, raqib/hooks/, raqib/event.py, raqib/eventlog.py, raqib/app.py, raqib/ui.py, severity, any other rule's YAML.
If an exit criterion needs a file outside Scope (the inventory does not give an act's path where the watch needs it): STOP and say which (the questions file).
Commit: `landed: M7.22 a child of a tree the watch holds is that tree's` or `STOP: M7.22 <reason>`.
Read HANDOFF.md and do only the task it specifies.
