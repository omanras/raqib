# Changelog

Every merge into `main` that changes what Raqib does has a number and an entry here, the newest first (ADR-0015).
`raqib --version`, the first line of a watch's report, the window and every event say the number, so a person
knows which Raqib is running without reading sentences. Each entry says what is new, how to update, and what
was not measured.

## 0.2.0 - 2026-11-20

What is new:
- Three rules that judge what an agent's tree does to the host, whatever its programs are called (ADR-0014).
  PERSIST-AUTOSTART: a file written in a Windows Startup folder. NET-ADMIN-PORT: a connection a process of the
  tree makes to a login or administration port (22, 23, 135, 445, 3389, 5900, 5985, 5986) of a private
  address. PERSIST-RUN-KEY: a value set under a Run or RunOnce key of the registry. Each is high and knocks.
  They read Sysmon's events on Windows; on Linux nothing reads for them yet.
- A fault found and fixed (ADR-0007 Amendment BV): Sysmon can let go of a process that still runs, and then
  names it by an empty ProcessGuid in its children's starts. Raqib took the zeros for a process of its own,
  lost the children's lines and took the tree for quiet, in silence. Such an event is now joined by the pid it
  names, and the watch says so when it happens.
- The reader of Linux's process events (raqib/procevents.py, ADR-0007 Amendments BQ to BT): it hears every
  process that starts and ends, with its program, parent and exit code, asking no right. It is not joined to
  the watch yet: on Linux a process that ends between two samples is still not judged.
- `raqib service install | remove | status` (Linux, ADR-0013): the host watch as a unit of the system's, and
  `raqib watch --host --no-page`.
- The rig holds the three rules on every push (X32 to X34) and the reader (X31).

To update:
- Windows: `git pull`, then `py -m pip install --upgrade .`
- Linux: `git pull`, then `pipx install --force .`; root's copy for the service is built from a copy of the
  checkout (docs/specs/SERVICE.md).
- Then `raqib --version` says the number at the top of this file.

Not measured:
- How often the three rules fire on a real desktop's ordinary work (their budgets stand on a corpus that
  holds none).
- Whether Sysmon always logs a process's start before the value it sets.
- A Sysmon whose configuration logs none of these events: the rules then have nothing to read, and the watch
  does not say so yet.

## 0.1.0 - before 2026-11-20

Every copy before this file said 0.1.0, whatever it held: the host watch, the rhythm, the catalog of fourteen
rules, the window, the events and their forwarder, the service's first stage. Two such copies could be told
apart only by their sentences (seen in the field on 2026-11-20). From 0.2.0 on the number moves.
