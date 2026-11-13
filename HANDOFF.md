# HANDOFF — M10.3b  (ADR-0011 Amendment J, J-6 and J-14: the forwarder over syslog)

Task: `raqib forward` sends to a syslog collector (udp, tcp, tls) as well as HTTP. Today a syslog destination is a usage error that says "not built yet"; build it. The HTTP transport and the whole machine (the cursor, the lines in question, the state, --status) stand unchanged: syslog is another way to send, not a new machine.

Scope:
  raqib/forward.py (the syslog transport beside the HTTP one; destination() stops rejecting syslog), tools/rig/collector.py (or a new tools/rig/syslog_collector.py: a loopback stand-in over udp and tcp), tools/rig/forward_run.py and tools/rig/check.py (a rig check for syslog), .github/workflows/rig.yml (the step), tests/test_forward.py, tests/test_forward_rig.py, docs/specs/FORWARD.md, docs/GUIDE.md (the destination forms), tests/test_readme_top.py (only the rows' text), docs/THREAT_MODEL.md, docs/review/2026-11-13-M10.3b-questions.md

Exit criteria (J-6 is the spec; read it in the ADR):
- E1 One line per message, RFC 5424: PRI from facility (13 log audit unless --facility N) and the event's severity (high 2, medium 4, low 5, none and info 6); VERSION 1; the event's time; `watch.host` as HOSTNAME; APP-NAME raqib; MSGID the event's kind; the line (the raqib shape, the event as written) as MSG. A test holds a built line to RFC 5424's shape and to each severity.
- E2 `syslog+udp://`, `syslog+tcp://`, `syslog+tls://`. Over tcp and tls, octet-count framing (RFC 6587); `--framing newline` for a collector that wants lines. tls verified as the HTTP path is (nothing turns it off; --ca adds an authority); plain udp/tcp only to a loopback address unless --plain. A message too long for a datagram (over 65000 bytes over udp) is refused locally, counted, named, passed - never cut (as J-6 rules, and as a too-long line is on HTTP).
- E3 At least once and in order, the same cursor machine as HTTP: a line is passed only when the transport took it - over tcp/tls "took" is the bytes handed to the system with no error (delivery word `written`), over udp nothing is known (`sent`), so udp passes a line once the datagram was sent. The state's `delivery` says which. A test over a loopback collector: every line arrives in order; the forwarder killed between two and restarted leaves no gap (tcp).
- E4 The token (J-7) is not sent over syslog (syslog carries no Authorization); --token-file with a syslog destination is a usage error that says so. No secret in any output, state or error.
- E5 (J-14) a loopback syslog collector (udp and tcp) in the rig; a check (X23+) that every whole line of the events file arrived in order; rig.yml runs it on both machines; the check never raises (a missing events file is a fact).
- E6 docs/specs/FORWARD.md and docs/GUIDE.md: the three syslog forms, the framing, the severity map, what `took` means per transport; docs/THREAT_MODEL.md (no milestone token): syslog is cleartext over udp/tcp unless tls, and what a collector learns.
- E7 Gate green in the foreground; ASCII outside docs; loopback and documentation addresses only; no test reads docs/review; the HTTP tests and X19 to X22 still pass untouched.
Not in scope: the cursor/in-question machine (J-1, L, M, N: reuse it), raqib/cli.py beyond the destination parsing already there, raqib/host.py, raqib/eventlog.py, raqib/event.py, a service.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M10.3b the forwarder over syslog` or `STOP: M10.3b <reason>`.
Read HANDOFF.md and do only the task it specifies.
