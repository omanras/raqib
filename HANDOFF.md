# HANDOFF — M7.21a  (ADR-0007 Amendments BK, BL: the tracing reader alone)

Task: a module that reads, on Windows, the bytes each TCP connection sent and received from the kernel's tracing (ETW), by a real-time session of its own. The watch is not joined yet (M7.21b).

Scope:
  raqib/etwnet.py (new), tests/test_etwnet.py (new), tools/rig/etw_read.py (new), docs/review/2026-11-13-M7.21a-questions.md

Exit criteria:
- E1 `raqib/etwnet.py`: ctypes only, standard library only, importable on every system (nothing of Windows is loaded at import); the system's calls go through one object a test replaces, as raqib/hostwin.py's `Api(loader)` does. It imports nothing of raqib but what hostwin itself imports, no socket, no network.
- E2 (BL-1) `Reader(pid)`: start() begins a real-time session named `raqib-net-<pid>` (no log file), enables Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88} at level 4 with keywords 0x30, and consumes it on a thread of its own. Events 10 and 26 are bytes sent, 11 and 27 received; the event's data begins PID u32, size u32, then daddr, saddr (4 bytes each for 10 and 11, 16 each for 26 and 27), dport u16, sport u16 (ports in network order). saddr:sport is this host's side.
- E3 (BL-5) `counts()` returns, at any time and from any thread, a copy: for each (pid, local addr, local port, remote addr, remote port) the bytes sent, received and the time of the last event; with `since` (the session's start), `unread` (events whose data is shorter than the shape or of another id of ours: counted, never guessed) and `lost`.
- E4 (BL-4) `lost` is what the session says it lost (events and real-time buffers), asked of the system at each counts(); a test where the fake system reports a loss.
- E5 (BL-2) stop() ends the consumer and stops the session, twice is harmless, and it runs on every way out (a context manager; a failed start leaves no session: a test for each step failing). `leftovers(alive)` lists sessions named `raqib-net-<n>` whose n is no live pid and stops them, returning their names; it never touches a session of another name (a test with other sessions present).
- E6 (BL-3) A start refused by the system returns a reason in the module's own words (no rights, the limit of sessions, a name already there, another error with its number) and raises nothing; no elevation is asked, no other source of counts is used (no GetPerTcpConnectionEStats: a test reads the module's source for it).
- E7 `tools/rig/etw_read.py SECONDS`: starts the reader, waits, prints one line per connection (pid, the four, sent, received) and a last line `since`, `unread`, `lost`, the leftovers stopped, or the refusal's reason; exit 0 read, 3 refused. On a system that is not Windows it says so and exits 3.
- E8 Tests run on Linux by the fake system (records built from bytes as the kernel lays them, v4 and v6); positive and negative for each criterion. Gate green in the foreground; ASCII; documentation addresses only.
Not in scope: raqib/host.py, raqib/hostwin.py, raqib/cli.py, the documents, .github/workflows/, tests/test_rhythm.py. The field check on a Windows runner is the Table's.
If an exit criterion needs a file outside Scope: STOP and say which. What you do not know of the system's structures for certain, say in the questions file: the Table checks it in the field.
Commit: `landed: M7.21a the tracing reader alone` or `STOP: M7.21a <reason>`.
Read HANDOFF.md and do only the task it specifies.
