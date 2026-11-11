# HANDOFF — M7.9  (the round reads the channel: ADR-0007 Amendment P, ruling P-4)

Task: where Sysmon is readable, a host round's inventory is the OS sample plus the channel's events since the previous
round began, so a tree that starts, talks, acts and ends between two rounds is a tree of that round.

Scope:
  raqib/host.py, raqib/discover.py, raqib/hooks/os_sysmon.py, raqib/ui.py, raqib/cli.py (help text only), tests/, README.md, docs/THREAT_MODEL.md, docs/review/, raqib/rules/catalog/NEW-AGENT-UNKNOWN.yaml (AB-5; NEW-AGENT.yaml: AA-5's sentence only; AGENT-DARK-LIVE.yaml: AC-7's sentence only)   (NOT raqib/app.py)

Exit criteria:
- E1 One read of the channel per round, by Raqib's own wevtutil as os_sysmon runs it (absolute path, SystemRoot-only environment, a timeout, the helper ended and recorded at Stop: I-5), asking only for records newer than the last one the previous round read (a bound in the query, never the whole channel); round 1 reads nothing older than the watch's start. A read that fails, times out or is cut is a hole of that round (A3) and the round keeps its sample. A cap on events per round, a hole when hit.
- E2 The round's inventory is the sample plus those events through discover's one Sysmon reader (events 1, 3, 11, 22). A tree known only from the channel is listed with the word `brief` (seen in the channel, not at the sample), cites its event lines (A5), and is judged by NEW-AGENT / NEW-AGENT-UNKNOWN, benign and history exactly as a sampled tree, once per tree: the ProcessGuid keys it, so a reused pid is another tree and a tree seen both ways is one.
- E3 A brief tree gets its os source like any other, rooted by pid AND guid, so its acts in the channel are judged by the catalog as M7.8 built it (history by the event's time, one act one finding, benign trees noted); its source ends without a hole once its events are read.
- E4 What the channel does not hold is said once per watch, in the first lines and the report: no event 3 (talk between rounds unseen), no event 1, no event 22. Without Sysmon, and on Linux, "a tree that lives between two rounds is not seen" stays a hole in the watch's first lines and in THREAT_MODEL, which says what M7.9 closed and what it did not.
- E5 Budgets (A6): the benign Windows desktop export read as rounds WITH its channel fires nothing new; NEW-AGENT-UNKNOWN's and act-root's budgets are measured again with the channel in, and the numbers are said. Nothing of the channel from before the watch's start is ever a tree.
- E6 Tests on fixture exports only (no live host, and every test passes on the windows jobs): a brief named tree gives NEW-AGENT in its round and its source lines are judged; a brief unknown tree; a read that times out (hole, sample kept); a reused pid; round 1 reads no history; the cap; Linux unchanged; no thread outlives its test (the M7.8 fixture). Gate green, CI six green; README and the help text say it; kinds unchanged or ADR-0002's note on the branch.
Not in scope: the clipboard rule (M7.10), a benign host of a model client (M7.11), raqib/app.py, new rules, any Linux audit source, any write outside ~/.raqib.
Commit: `landed: M7.9 the round reads the channel` or `STOP: M7.9 <reason>`.
Read HANDOFF.md and do only the task it specifies.
