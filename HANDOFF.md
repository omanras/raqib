# HANDOFF — M7.8  (the second field run's lessons: ADR-0007 Amendment P, rulings P-1, P-2, P-3)

Task: on a host with Sysmon a tree's acts are recorded and judged by nothing, a living tree is called gone, and
Defender is called an unknown agent. Fix the three, and write the host watch's holes into THREAT_MODEL.

Scope:
  raqib/hooks/os_sysmon.py, raqib/host.py, raqib/discover.py, raqib/discover/endpoints.yaml,
  raqib/rules/catalog/NET-TOOL.yaml, raqib/rules/catalog/DESTRUCT-CMD.yaml, raqib/rules/fixturegen.py, raqib/ui.py,
  raqib/cli.py (help text only), tests/, README.md, docs/THREAT_MODEL.md, docs/review/   (NOT raqib/app.py: M8.1 holds it)

Exit criteria:
- E1 (P-1) An os `process` line carries the image name in the one normalised form discover uses for a tree's image (one function, not a second normaliser), in a field the rules
     read; what Sysmon logged is still hashed as today; no argument is ever written. A line written before M7.8 lacks the field: said once per source, never guessed.
- E2 (P-1) NET-TOOL and DESTRUCT-CMD judge os `process` lines by that name, as they judge HostChild lines. Each list gains the Windows programs of its kind (propose them in the
     questions file with one line of reason each; the Table rules). Every new branch has a positive and a negative fixture; the budgets are measured again, the benign Windows
     desktop export included where it can be read as os lines; the evasions say what is still unseen (a shell builtin, a cmdlet, a renamed copy, an argument).
- E3 A finding of an os line shows on its tree in the report, the page and the state, cites its line (A5), and knocks by the rules that already hold for a source's findings
     (ADR-0007 I-6); nothing else about knocks changes.
- E4 (P-2) A tree seen in an earlier round whose root process is in this round's process sample and does not talk now is `quiet`: listed with that word, its source kept attached,
     in neither `gone` nor `back`, no "source ended" hole. Gone = the root process is not in the sample. Test: the field run's alternation gives one attach and no hole.
- E5 (P-3) Windows Defender's engine is benign by image AND directory (the system drive's ProgramData\Microsoft\Windows Defender, and Program Files\Windows Defender), with its
     evasion line; a copy elsewhere still knocks. Fixtures both ways.
- E6 THREAT_MODEL gains "The host watch": what a round sees and what lives between two rounds (still a hole; M7.9); the person's hands (ADR-0007 P-5: text an agent hands a
     person, who runs it, is outside every tree; why no timing rule); the clipboard's text is never read; Raqib watches and stops nothing (A4). True of the tree as M7.8 leaves
     it.
- E7 Tests for each of E1-E5 (fixtures, not a live host); the AST and A4 guards hold; gate green; kinds unchanged (no new rule) or ADR-0002's note on this branch; CI six green;
     README's rules table and host section say it.
Not in scope: the channel in the round (M7.9), the clipboard rule (M7.10), raqib/app.py, new rules, any write outside ~/.raqib.
Commit: `landed: M7.8 the acts are judged` or `STOP: M7.8 <reason>`.
Read HANDOFF.md and do only the task it specifies.
