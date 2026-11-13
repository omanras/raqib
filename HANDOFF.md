# HANDOFF — M7.20  (ADR-0007 Amendment AU: one server, one destination)

Task: an os talk's destination no longer depends on whether Sysmon named the host (AU-1, AU-2), and a host talk and an os talk to one server are one destination (AU-3).

Scope:
  raqib/hooks/os_sysmon.py (the net line's meta only), raqib/host.py (the rhythm's beats and destinations only), raqib/rules/fixturegen.py, raqib/rules/catalog/HOST-RHYTHM.yaml (fixtures list, holes, description, the budget's comment), tests/ (the rule's fixtures and tests/fixtures/host/make.py included), docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.20-questions.md

Exit criteria:
- E1 (AU-1) os_sysmon's net line carries input_meta.dest_sha256: the hash (common.canonical_sha256) of the address in canonical form (the ipaddress module's; an IPv4-mapped IPv6 address as its IPv4), the port as an integer and the protocol in lower case. input_sha256 is byte for byte what it was (tested on an event with and without DestinationHostname: one dest_sha256, two input_sha256). An address that does not parse: no dest_sha256, never a guess.
- E2 (AU-2) host.py's talk beat of an os line uses dest_sha256 where the line has it; a line without it keeps "os:" and the first 12 of its input_sha256, and the watch says once per source that such lines were read (a note, as for a process line without an image).
- E3 (AU-3) A host talk to address:port and an os talk whose dest_sha256 is that server's (tcp) are one destination in the ring, in rhythm_of and in the finding: named address:port where the sample saw it, else as the os talk names it. Through rounds: one cycle from a host talk and two from os talks to the same server fire in the round that reads the third; the same with the os events named on some and not on others; K-1 do not fire.
- E4 (AU-4) fixturegen makes the new positives and negatives (AU-1's pair, AU-3's pair); `raqib check-rules` passes; the YAML's budget comment says the new counts as measured; existing fixtures change only where an os net line gains the key, and the questions file names which changed and why. The match, K, W, R, severity: unchanged (tests/test_rhythm.py's test_m718_e1 still passes untouched).
- E5 The rule's holes and description, and THREAT_MODEL (no milestone tokens): the hole "the same server reached by another name or address is another destination, and an os talk and a host talk to one server are two destinations" says what is still true (another address of one server is still another destination; a line written before this task; a protocol the sample does not see) and no longer what is not.
- E6 Gate green; ASCII outside docs; no new test reads docs/review; no real address (192.0.2.x, 198.51.100.x, 2001:db8::).
Not in scope: raqib/discover.py, raqib/app.py, raqib/ui.py, raqib/event.py, NET-TOOL, the hooks source, severity, any other rule.
If an exit criterion needs a file outside Scope: STOP and say which (the questions file).
Commit: `landed: M7.20 one server, one destination` or `STOP: M7.20 <reason>`.
Read HANDOFF.md and do only the task it specifies.
