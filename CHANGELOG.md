# Changelog

Every merge into `main` that changes what Raqib does has a number and an entry here, the newest first (ADR-0015).
`raqib --version`, the first line of a watch's report, the window and every event say the number, so a person
knows which Raqib is running without reading sentences. Each entry says what is new, how to update, and what
was not measured.

## 0.4.0 - 2026-11-21

What is new:
- A chain in the events file (ADR-0016 and its Amendments A and B). Every event a host watch writes names the
  line its run wrote before it by that line's sha256 (`prev`; the run's first line says `first`). `raqib events
  FILE` says of each run whether its chain is whole, where it breaks (a line removed, changed, added or moved),
  which lines stand beside it, whether the run begins before the file, and whether a chain was taken out of a
  run whose version always writes one. A line of an older Raqib holds no `prev`: its run is said as not
  chained, which is not a problem.
- `raqib events FILE --against OTHER`: the lines a collector holds, side by side with the host's file, by host
  and id: which are in the file byte for byte, which are not there, which are there with other bytes. This is
  how a line changed on the host after the collector took it is seen; it needs the collector's lines as they
  were sent.
- No line of the events file can end `raqib events` or the forwarder: a line nested too deep, or with values
  that cannot be checked, is named and passed over.
- The events' schema keeps its name (`raqib-event/1`): `prev` is an addition, and a reader of the file must
  allow a key it does not know (the spec says so now).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- A run that began under an older Raqib and is still in the file stays as it is; the chain begins with the
  first watch started after the update.

Not measured:
- What the chain does not prove is not a measurement, and is said here all the same: the chain holds no
  secret. Whoever can write the file can cut its end, write a tail again with its hashes,
  or take a chain out and write an older version on its lines: the file alone then looks whole. The run's last
  line is named by no line. A collector that kept its lines sees a change of what it holds, by `--against`.
- A real collector's export brought back as lines (Splunk, a syslog server, the journal): whether its bytes are
  the bytes that were sent.
- `raqib events` on a very large file: it holds the file in memory.

## 0.3.0 - 2026-11-20

What is new:
- Raqib can read Windows' autostart places by itself, with no Sysmon and no right asked (ADR-0014 Amendments G
  and H; docs/specs/AUTOSTART.md): the Run and RunOnce values of every loaded user's hive and the machine's,
  the Startup folders, the services, the scheduled tasks where its rights give them, and Winlogon's Shell and
  Userinit. `python -m raqib.autostart --rounds N --every S` says what each read holds and each entry added,
  changed or removed between two reads, by its place, its name and the program it would run; never a value's
  text, a file's content or a SID. A place the rights refuse is said as refused, never read as empty.
- The watch does not read it yet and no rule judges it yet: that is the next step on this track (M15.3b).
- The rig makes a service that is never started, beside its Run value and its Startup file, and claims that
  the read sees each appear and go (X37).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.

Not measured:
- A real desktop: how often an updater makes its own task or service with nothing done, and how long a read
  takes with thousands of services (on GitHub's machine: 39 reads, the longest 0.157 s).
- What two reads can say that is not so (an entry that first appears while its place is unread; a hive loaded
  between two reads): said in the spec, ruled before the watch reads this.

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
