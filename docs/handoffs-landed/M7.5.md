# HANDOFF — M7.5  (phase 7: after the first field run, ADR-0007 Amendment M)

Task: the three lessons of the first field run (Windows + Kimi, 2026-11-04): a dark footprint whose
tree was live in this watch is a note, not a knock; rhythm takes beats from every source; the knock
that did not reach the commander is found and fixed.

Scope:
  raqib/host.py, raqib/notify.py, raqib/rules/catalog/AGENT-DARK-LIVE.yaml, raqib/rules/catalog/HOST-RHYTHM.yaml,
  raqib/ui.py, raqib/app.py, tests/, README.md, docs/review/

Exit criteria:
- E1 AGENT-DARK-LIVE: a footprint whose linked tree was a candidate in THIS watch and then left
     (gone) does not knock at streak 3: the line carries `input_meta.was_live: true`, the match
     excludes it, report and page list it as "dark after a live tree (note)"; a footprint never
     linked knocks as today. YAML says so; fixtures +(never live) -(live then gone) -(linked again).
- E2 HOST-RHYTHM: the act beat comes from every source the tree has - host children, os
     (Sysmon event 1) children with their UtcTime, and hook lines' Bash calls where hooks are
     attached - all through one `act_beats(tree, round)`; the talk beat likewise from host
     connections and os event 3. Fixtures: an os-source tree with 3 cycles fires; the same with
     2 does not; a tree whose talks are os and acts are host fires. The YAML names the sources.
- E3 The missing knock: reproduce the field run's order (AGENT-DARK-LIVE round 3, NEW-AGENT
     round 10, AGENT-DARK-LIVE round 13) with the fake runner and assert three deliveries in
     three toasts; if NEW-AGENT's knock was folded or held behind the first AGENT-DARK-LIVE
     (shared limit id, fold token, or the FIRST-FINDING "by the rule" path), fix it so a high
     NEW-AGENT always knocks on its own id; the final report prints every knock's status.
- E4 Report, page and window show "note" lines apart from findings; a note is never an alarm. README:
     two lines. Tests per criterion; fixtures regenerated only where E1/E2 change them (say why). Kinds 4 : 7 : 11.
Not in scope: the rules control panel (next), new agents' catalog entries, macOS.
Commit: `landed: M7.5 after the first field run` or `STOP: M7.5 <reason>`.
Read HANDOFF.md and do only the task it specifies.
