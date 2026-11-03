# HANDOFF — M7.2  (phase 7: the host watch - NEW-AGENT, AGENT-DARK live, ADR-0007 decision 2)

Task: `raqib watch --host` watches the machine: discovery repeats while it runs; a tree that
starts talking and acting is NEW-AGENT with a knock; a footprint with no live tree is
AGENT-DARK live; "no agent seen" is said each round, never by silence.

Scope:
  raqib/host.py (new), raqib/discover.py (API only), raqib/watch.py (host mode), raqib/notify.py,
  raqib/ui.py (host section), raqib/cli.py, raqib/rules/catalog/, .github/workflows/gate.yml, tests/, README.md, docs/review/

Exit criteria:
- E1 `raqib watch --host [--every T] [--window S] [--rounds N]` (T default 10 s): a round
     = one live discover (collect_live / hostwin), read-only; inventory kept in
     `~/.raqib/host/inventory.json`, deltas in `~/.raqib/host/rounds.jsonl` (A5: round,
     sample, record cited). Ctrl-C/Stop/--rounds end it with a final report.
- E2 NEW-AGENT (anchor, high): a candidate tree absent from the previous round (root
     pid + image + first seen), "named" when the catalog matched, else "unknown"; an
     act-root that becomes a candidate too. Knocks once per tree (A-4 text: rule, image
     name, pid). Trees present in round 1 are history: listed, not knocked (B-3).
- E3 AGENT-DARK live (medium): a footprint with no linked tree for 3 rounds knocks once;
     clears with a note when a tree links. Both rules in the catalog with fixtures.
- E4 A round with no candidate prints one line (round, records read, holes); a reader not back within 2 x T is a hole and a knock (A3).
- E5 The page gains a HOST section (band: trees now, new, dark, last round; trees with evidence) from watch's memory; registry row "host"; watch.json extended.
- E6 Tests: rounds on fake inventories (new, unknown, gone-and-back, dark then linked,
     reader silent); knocks with the fake runner; the report. CI ubuntu + windows run
     `raqib watch --host --every 1 --rounds 2 --no-notify` and assert the report lists
     the runner's trees. Six jobs green. README: three lines.
Not in scope: source attachment (M7.2b), the window's host screen (M7.3), rhythm (M7.4).
Commit: `landed: M7.2 the host watch` or `STOP: M7.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
