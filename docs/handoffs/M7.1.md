# HANDOFF — M7.1  (phase 7: Windows live discovery in-process, ADR-0007)

Task: `raqib discover` with no files runs live on Windows as it does on Linux:
the host's processes, TCP connections and DNS names read through the OS API
from the standard library (ctypes), read-only, sampled over a window; no
PowerShell, no loop by hand.

Scope:
  raqib/hostwin.py (new), raqib/discover.py (live path, --save), raqib/cli.py (discover
  options), raqib/doctor.py (one line), .github/workflows/gate.yml, tests/, README.md, docs/review/

Exit criteria:
- E1 `raqib/hostwin.py`: processes (CreateToolhelp32Snapshot/Process32FirstW/NextW:
     pid, ppid, image name; the full image path by QueryFullProcessImageNameW
     under PROCESS_QUERY_LIMITED_INFORMATION only, "?" when denied and counted
     as a hole; command line and cwd are not read); TCP v4 and v6 with the
     owning pid (GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL; state, local,
     remote); DNS names from the resolver cache (DnsGetCacheDataTable in
     dnsapi, freed with DnsFree) - unavailable = a hole "no names", never a
     crash. argtypes/restype on every call; every handle closed; nothing
     opened with a right beyond query; nothing written, signalled or attached.
- E2 Each sample becomes records of the existing kinds win-process, win-tcp,
     win-dns (the CSV parsers' shapes: one code path to the inventory); a
     live Windows run = N samples T s apart (`--samples N --every T`, default
     6 x 10 s, as the README loop), merged as the Linux window merges; `--save
     DIR` writes the samples as win-*-<k>.csv so `--from DIR` repeats the run
     (A5, A8); run.json records the API that was read and every hole.
- E3 The reader's own pid and its tree are never evidence (A-3); a live run on
     Windows is refused with one line when running under a debugger or when
     the Toolhelp snapshot fails; `doctor` gains `host` (OK / MISSING per API).
- E4 Tests: a fake Win32 API (structures filled in code) yields records equal
     to the Kimi fixture's CSV records; sizes of the structures on win64; the
     denied path, the empty DNS path. CI: on windows the live reader runs 2
     samples x 1 s and the inventory JSON names no candidate that is the reader.
- E5 README Windows section: first line `raqib discover` (live); the
     PowerShell loop becomes "repeat from an export". CI six jobs green.
Not in scope: host watch (M7.2), the window (M7.3), rhythm (M7.4), Sysmon.
Commit: `landed: M7.1 Windows live discovery` or `STOP: M7.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
