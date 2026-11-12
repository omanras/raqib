# HANDOFF — M7.14 REDO 2  (ADR-0007 Amendment AK on review 2026-11-12-M7.14-redo.md)

Task: the second REDO of M7.14 (9e1aaa1). AI-1's bounded pass, AJ-1's rule (an os tree has the host's own record), AJ-2's
join and AJ-4's three fixes stand. What changes is how an os tree gets its host lines: by the host source's own road
(AK-1), and the rulings AK-2 to AK-8.

Scope:
  raqib/hooks/os_sysmon.py, raqib/host.py, tests/, docs/THREAT_MODEL.md, docs/GUIDE.md, docs/review/2026-11-12-M7.14-questions.md

Exit criteria:
- E1 (AK-1) An os tree's host lines are written to their own file and judged by their own feed with the host's rules and the host source's history rule, by the code a hooks tree uses for its host lines (one code path; `host_from` is gone). The os feed's history is as before M7.14.
- E2 (AK-2) An os follow that raises, ends or is still in a pass does not stop that round's host lines.
- E3 (AK-3) Host lines hold the sample only: no host line for a tree that is not sampled; no child or talk the channel alone gave. tests/test_round_channel.py ab10 asserts what it asserted before M7.14. If a sampled child cannot be told from a channel-only one: questions file, no guess.
- E4 (AK-4) The terminal line and the knock's body of a finding name the cited line's source; for a host line they are word for word those of the watch without Sysmon.
- E5 (AK-5, AK-6) The tree handed to a follow attached again is the one published after the earlier follow's last finished pass. A follow attached after a restart says in its source text that it reads from the restart's time.
- E6 (AK-7) The join's words are "taken for the same act (one image, starts within 1 s)"; the guide and THREAT_MODEL say the join is the listing's, the window and state count both, the catalog's rules knock for the pair at most once.
- E7 (AK-8) The property tests compare, between the watch with Sysmon and the same rounds without it, each host-line finding's rule, tree, child, history, notice, knock and terminal words, in these cases: a tree there at the start with a child in round 1; the tree's host file restarted; a follow that ends in the round of its attach; a tree known only from the channel (through rounds); a follow attached again knows the earlier one's child (through the watch); a restart through the rounds, with its hole's words.
- E8 Docs true of the code (the packet's W-4, W-5); the questions file's stale "REDO STOP" section replaced by the present state. Gate green; ASCII; no test reads docs/review or asserts the real clock.
Not in scope: raqib/hostwin.py, raqib/app.py, README.md, new rules, the act registry's keys, ADR-0011.
Commit: `landed: M7.14 REDO 2 a follow that returns` or `STOP: M7.14 REDO 2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
