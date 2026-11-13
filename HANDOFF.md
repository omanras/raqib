# HANDOFF — M10.3b REDO  (ADR-0011 Amendment P: the forwarder over syslog)

Task: on claude/M10.3b, build what Amendment P rules on the review docs/review/2026-11-13-M10.3b.md. The HTTP path and the cursor's machine stand.

Scope:
  raqib/forward.py (the syslog send, the message's fields, destination, the state's two keys), raqib/cli.py (only if a help string must say the port rule), tools/rig/syslog_collector.py, tools/rig/forward_run.py, tools/rig/check.py (X23 to X25 only), tests/test_forward.py, tests/test_forward_rig.py, docs/specs/FORWARD.md, docs/THREAT_MODEL.md, docs/review/2026-11-13-M10.3b-redo-questions.md

Exit criteria:
- E1 (P-1) An events line whose time is written in other digits than ASCII (as JSON escapes, so the line is ASCII and passes `event.check`), and lines with a host of 300 characters, a host with a space, a kind of 40 characters: each is sent with `-` in that field and the line whole as MSG; building a message raises for no line (a test feeds made-up odd events through the real send). The forwarder does not end.
- E2 (P-2) Over tcp and over tls a batch is taken only after the orderly end: the forwarder half-closes (tls: sends its close) and reads to the collector's end within the bound. Tests, each failing if the batch were taken at the write: a listener that reads everything then holds the connection open past the bound (failed, nothing passes); one that accepts and closes at once without reading; one that resets after reading; a tls listener that sends an alert after the handshake. And the positive: the tls test that failed on Windows (the listener holds all three lines when the forwarder says taken) - the listener's data is read only after the forwarder returned, with no sleep.
- E3 (P-3) `syslog+tcp://host` with no port is exit 2 with the reason; udp and tls defaults stay. The state holds `facility` and `framing` for a syslog destination; a start with another of either is exit 2; an older syslog state without them is read (say how in the questions file).
- E4 (P-4) The failure tests of P-4 not already under E2: an error in the middle of a batch; a collector that never reads (`late`, the next batch halved, bounds injected); Stop during a blocked write (the mechanism: the run ends long before the bound). The kill test's `after` case compares each connection's own messages.
- E5 (P-5) docs/specs/FORWARD.md and docs/THREAT_MODEL.md (no milestone token): P-5's sentences; no "client certificates"; the status words for syslog. A test holds the sentences that matter (udp down is `sent` and OK; `written` is an orderly end).
- E6 The rig's stand-in ends each tcp connection in order (reads to the forwarder's half-close, then closes) so X23 and X25 still hold; X23 to X25 MET by forward_run over a made-up events file; the check never raises.
- E7 Gate green in the foreground; ASCII outside docs; loopback and documentation addresses only; no test reads docs/review; the HTTP tests and X19 to X22 unchanged.
Not in scope: the HTTP send, the cursor's machine, raqib/host.py, raqib/eventlog.py, raqib/event.py (the contract accepts what it accepts: the forwarder must bear it), tests/test_rhythm.py, .github/workflows/.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M10.3b REDO the forwarder over syslog` or `STOP: M10.3b REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
