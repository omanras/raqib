# HANDOFF — M7.27 REDO  (ADR-0007 Amendments BH and BI: the watch's own tree is what it started)

Task: on claude/M7.27 (506a9a6), build what Amendment BI rules. Everything else of M7.27 stands.

Scope:
  raqib/own.py, raqib/discover.py (snapshot_proc's forget guard; where a recorded pid is proven), raqib/hooks/os_sysmon.py and raqib/notify.py (only the start line, so the record keeps the image), raqib/hostwin.py (the Windows proving, if the image match needs it there), tests/, docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.27-redo-questions.md

Exit criteria:
- E1 (BI-1) snapshot_proc passes `since` to record.alive only where the sample is whole (unreadable == 0); a test: a recorded Linux helper absent from one sample that has an unreadable process is kept and is the watch's own at the next sample; a helper gone (FileNotFound) is still forgotten. It fails if `since` is passed unconditionally.
- E2 (BI-2) own.started records the image of what it started (Popen's args[0] basename, a string arg split; where args gives none, no image). record.alive (or the proving in discover) gives a recorded pid as the watch's own only where the sample's image for that pid equals the recorded image; a sample image not read does not prove it. A test through the parsers: a recorded helper pid reused by a process of ANOTHER image within the 2 s window is NOT the watch's - it is judged as any other and named (a talker among such is a candidate); the real helper, same image, still is. It fails if the image is not compared.
- E3 (BI-3) The act-roots test of BI-3: reverting any one of the three `_act_roots` self_tree walks fails it; it is not vacuous (an act-root really reached only through a member of the watch's tree, self_tree non-empty).
- E4 Every existing fixture under tests/fixtures and raqib/rules/hostdata gives the inventory it gave (the record now carries an image, but no fixture carries a record): the pins untouched. If one moves: STOP and say which.
- E5 (BI-4) docs/THREAT_MODEL.md (no new milestone token): the identity is pid, time and image, and what is still taken (a same-image reuse within 2 s); the evicted-while-alive backstop; the cross-build line.
- E6 Gate green in the foreground; ASCII outside docs; no real address, host or user name; no test reads docs/review.
Not in scope: raqib/host.py, raqib/event.py, raqib/eventlog.py, raqib/rules/, the tree key, how a start is read.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M7.27 REDO the watch's own tree is what it started` or `STOP: M7.27 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
