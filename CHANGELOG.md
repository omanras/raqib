# Changelog

Every merge into `main` that changes what Raqib does has a number and an entry here, the newest first (ADR-0015).
`raqib --version`, the first line of a watch's report, the window and every event say the number, so a person
knows which Raqib is running without reading sentences. Each entry says what is new, how to update, and what
was not measured.

## 0.2.0 - 2026-11-20

What is new:
- The number itself (ADR-0015). `raqib --version`, the first line a watch prints, the first line of its report
  and the window's title bar say `raqib 0.2.0`. A script that matched one of those lines whole must now match
  its beginning.
- Three rules that judge what an agent's tree does to the host, whatever its programs are called (ADR-0014).
  PERSIST-AUTOSTART: a file written in a Windows Startup folder. NET-ADMIN-PORT: a connection a process of the
  tree makes to a login or administration port (22, 23, 135, 445, 3389, 5900, 5985, 5986) of a private
  address. PERSIST-RUN-KEY: a value set under a Run or RunOnce key of the registry. Each is high and knocks.
  They read Sysmon's events on Windows; on Linux nothing reads for them yet.
- What the watch could not read for those rules is said (ADR-0014 Amendments E and F): once, when three rounds
  read no file event of the channel, and as the blind spot `registry` when the channel held no registry value
  at the watch's first read. Both say what may be unseen, never that nothing was done.
- A fault found and fixed (ADR-0007 Amendment BV): Sysmon can let go of a process that still runs, and then
  names it by an empty ProcessGuid in its children's starts. Raqib took the zeros for a process of its own,
  lost the children's lines and took the tree for quiet, in silence. Such an event is now joined by the pid it
  names, and the watch says so when it happens.
- Linux's process events (raqib/procevents.py, ADR-0007 Amendments BQ to BX): a helper process of the watch's
  own hears the processes that start and end between two samples, with program, parent and exit code, asking
  no right. The report counts them under `PROCESS EVENTS (Linux)` and says what the helper lost. Nothing is
  judged from them yet: on Linux a process that ends between two samples is still not judged.
- The rig asks a stand-in for the three rules on GitHub's Windows machine at every push (X32 to X34), and for
  the reader and its helper on Linux (X31, X35). A claim it misses is reported; it does not fail the push.

To update:
- In the checkout's folder. First stop a running watch, window or service: a running one keeps the number it
  started with.
- `git pull`
- Installed with pipx, on Linux or Windows: `pipx install --force .`
- Installed with pip: `pip install --upgrade .` in the same venv; with Windows' launcher,
  `py -m pip install --upgrade .`
- The Linux service (root's copy, docs/specs/SERVICE.md), with DIR its folder and NUMBER this entry's: a new
  copy of the checkout for each number, `sudo cp -r . DIR/src-NUMBER`, then
  `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER` and `sudo DIR/bin/raqib service install` again (it writes
  the unit again and restarts it).
- Then `raqib --version` says the number at the top of this file. A watch with rules of your own measures its
  thresholds again at its first start after an update, and says so.

Not measured:
- How often the three rules fire on a real desktop's ordinary work (their budgets stand on a corpus that
  holds none).
- Whether Sysmon always logs a process's start before the value it sets.
- How long the watch's one question for the registry's values takes on a full channel that holds none
  (ADR-0014 AF-4): a slow answer can make the first round late.
- The helper under a real desktop's load: on GitHub's machines it missed 0 to 2 of 200 programs that live
  under a millisecond, and it counts what it knows it lost.
- The update steps of the service's copy: written from the service's spec, not run on a machine.

## 0.1.0 - before 2026-11-20

Every copy before this file said 0.1.0, whatever it held: the host watch, the rhythm, the catalog of fourteen
rules, the window, the events and their forwarder, the service's first stage. Two such copies could be told
apart only by their sentences (seen in the field on 2026-11-20). From 0.2.0 on the number moves.
