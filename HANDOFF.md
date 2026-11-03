# HANDOFF — M7.1  (phase 7: Windows live discovery in-process, ADR-0007)

Task: `raqib discover` with no files runs live on Windows as on Linux: processes, TCP
and DNS names through the OS API (ctypes, stdlib), read-only, sampled; no PowerShell loop.

Scope:
  raqib/hostwin.py (new), raqib/discover.py (live path, --save), raqib/cli.py (discover
  options), raqib/doctor.py (one line), .github/workflows/gate.yml, tests/, README.md, docs/review/

Exit criteria:
- E1 `raqib/hostwin.py`: processes by Toolhelp32 (pid, ppid, image name; full path
     by QueryFullProcessImageNameW under PROCESS_QUERY_LIMITED_INFORMATION only,
     "?" when denied = a hole; no cmdline, no cwd); TCP v4+v6 with owning pid
     (GetExtendedTcpTable, OWNER_PID_ALL); DNS names from the resolver cache
     (dnsapi DnsGetCacheDataTable, DnsFree) - unavailable = hole "no names". argtypes/
     restype everywhere; handles closed; nothing beyond query; nothing written, signalled, attached (A4).
- E2 A sample = records of the kinds win-process, win-tcp, win-dns (the CSV
     parsers' shapes: one path to the inventory); a live run = N samples T s apart
     (`--samples N --every T`, default 6 x 10 s), merged as Linux merges; `--save
     DIR` writes win-*-<k>.csv so `--from DIR` repeats it (A5, A8); run.json
     records the APIs read and every hole.
- E3 The reader's own tree is never evidence; a failed snapshot refuses the live run in one line; `doctor` gains `host` (OK / MISSING per API).
- E4 Tests: a fake Win32 API (structures filled in code) yields records equal to
     the Kimi fixture's CSV records; win64 structure sizes; the denied path; the
     empty DNS path. CI windows: 2 samples x 1 s, inventory JSON, the reader is
     no candidate. E5 README Windows: first line `raqib discover` (live); the
     PowerShell loop becomes "repeat from an export". CI six jobs green.
Not in scope: host watch (M7.2), the window (M7.3), rhythm (M7.4), Sysmon.
Commit: `landed: M7.1 Windows live discovery` or `STOP: M7.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
