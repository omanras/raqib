# HANDOFF — M7.4  (phase 7: rhythm and suspicion on unknown trees, ADR-0007 decision 4)

Task: a tree that talks to an endpoint the catalog does not know is judged by the think-act cycle
alone - talk to one destination, then a child starts, repeated - from times and counts the host
records, thresholds not a model (RHYTHM); the suspect layer may raise suspicion on an unknown
tree's record, never acquit (A2), only when the commander turns it on.

Scope:
  raqib/host.py, raqib/hostwin.py (API only), raqib/discover.py (API only), raqib/rules/catalog/ (one YAML),
  raqib/suspect/ (API only), raqib/ui.py, raqib/app.py, raqib/cli.py, .github/workflows/gate.yml, tests/, README.md, docs/review/

Exit criteria:
- E1 Per tree, per round, the host source records the two beats as it records connections and
     children: "talk" = a connection to one remote host:port new or still established (bytes where
     the host gives them read-only: Linux `ss -ti` by absolute path; Windows none = a named hole);
     "act" = a child started (started time where read).
- E2 RHYTHM (anchor, medium, YAML + fixtures, budget measured on the benign desktops): K cycles (talk
     to the SAME destination, then an act within W s) within the last R rounds, K=3 W=30 R=10 by
     default, declared in the YAML; once per tree per streak; cites the rounds and records of each
     beat (A5); evasions named (a relay, acts between rounds, a destination that changes each turn).
- E3 `raqib watch --host --suspect BACKEND` (window: a "suspect unknown trees" field, empty by
     default) runs the existing suspect layer over each UNKNOWN tree's source file every R rounds;
     "benign" = no finding (A2); suspicion listed on the tree, knocks once; the backend call is the
     only network call, never from a capture or discovery path; its text carries hashes and names only.
- E4 Report, page and window show RHYTHM and suspicion as other findings; exit codes as C-10. E5 Tests on fake rounds: K cycles fire, K-1 do not, a changing destination does not, acts between
     rounds a named hole; the bytes reader with a fake `ss`; the suspect call with a fake backend and
     the never-acquit contract; CI ubuntu + windows: the host step passes. Kinds 4 : 7 : 11; README 3 lines.
Not in scope: pcap, GetPerTcpConnectionEStats, proxy attachment, CROSS-SOURCE over host, macOS.
Commit: `landed: M7.4 rhythm and suspicion` or `STOP: M7.4 <reason>`.
Read HANDOFF.md and do only the task it specifies.
