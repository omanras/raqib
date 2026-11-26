# Changelog

Every merge into `main` that changes what Raqib does has a number and an entry here, the newest first (ADR-0015).
`raqib --version`, the first line of a watch's report, the window and every event say the number, so a person
knows which Raqib is running without reading sentences. Each entry says what is new, how to update, and what
was not measured.

## 0.8.2 - 2026-11-27

What is new:
- A Raqib packed with its own runtime hands nothing of its packer to the programs it starts (ADR-0007 Amendments
  CI to CK). Measured first on GitHub's Windows, Linux and macOS machines: a packed start reads none of the ten
  interpreter's variables tried, but it adds the packer's own names to its environment - on Linux its own folder
  first on the loader's search path - and on Windows it sets the folder the system searches first for a library
  to its own; both reached what it started. Now the helper is started with the watch's environment as the watch
  was handed it, and on Windows Raqib's entry puts that folder back to none at its start.
- Where that call fails on Windows, the `raqib` command says so at once on its error stream, and the host watch
  says it once at its start as a blind spot that does not change the result. Never silent, never fatal.
- A test reads Raqib's own source and fails on a start of a program that hands on a whole environment by any
  road but that one; it holds the seven starts it finds.
- The threat model says what is not held: the loader's own variables are read by the system before the first
  line of Raqib, packed or plain. The defence is who starts the watch - the system's service manager, not a
  shell an agent holds.
- A Raqib that is not packed does exactly what it did: nothing changes for an install by pip or pipx.
- Measured with this number's code, packed, on the three systems: on Windows the folder searched first was the
  packed program's before the entry ran, none after it, and none for a program started after it; a program
  started with the cleaned environment saw exactly the environment the packed program was handed; on Linux the
  packed helper started as a start of its own and the watch's five asks were answered.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.

Not measured:
- No package and no installer exists yet.
- The packed window (`raqib-app`): its own entry makes no such call on Windows; a host watch run from it says so.
- The call failing on a real Windows machine; a starter that hands the packer's own names together, an empty
  loader's path, or a loader's variable that names a folder with a library in it.
- Another packer, another version of this one (PyInstaller 6.11.1 was read), or one file instead of one folder.
- On macOS the watch, packed or not, still reads the homes only: it has no reader there yet.

## 0.8.1 - 2026-11-26

What is new:
- A Raqib packed with its own runtime keeps its process events on Linux (ADR-0007 Amendments CG and CH). Packed
  into one folder so that a machine needs no Python - the first step toward packages a person installs with
  one command - the host watch lost the kernel's process events: its helper was started as "this Python, run
  that program", and a packed program is no Python. The watch said so itself (two asks, no answer, a blind
  spot each time). A packed Raqib now starts its helper as itself.
- A Raqib that is not packed starts its helper exactly as before; nothing else changes in this number.
- Measured on GitHub's machines: packed, Raqib is 24.5 MiB on Windows, 59.2 MiB on Linux and 40.4 MiB on macOS,
  starts in 0.1 to 0.2 s, and its watch holds 34 to 39 MiB of memory (read while the Linux helper was dead: a
  living packed helper adds about 34 MB, a plain one about 15). On the rig's Linux machine, as a user that is
  not root, a Raqib packed there answered four asks of four and heard the processes started beside it (the
  claim X47).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- A machine with more than one install (a virtual environment and the system's Python, say) is updated one
  install at a time: `raqib --version` of each says which is which.

Not measured:
- No package and no installer exists yet: this number is the first thing they need, not they.
- What a packed program reads of the environment at its start, and what it hands to the outside programs a
  watch starts: the plain helper is isolated from the environment, the packed one is not.
- The window and the service packed; a packed watch over hours; Windows on ARM64 packed.
- On macOS the watch, packed or not, still reads the homes only: it has no reader there yet.

## 0.8.0 - 2026-11-21

What is new:
- On Linux a short child is judged by everything it ran, and by the name it was called by (ADR-0007 Amendments
  CC to CF). A child's line names every program its process ran while the process events heard it (the newest
  eight; more are counted and said), so the command a shell runs in its own place (`bash -c "...; curl ..."`)
  is judged whenever it runs, in the round of the shell's line or a later one. Where the kernel's name for a
  process differs from its file's, the line names both: `nc`, whose file on Ubuntu is `nc.openbsd`, is judged
  as `nc`.
- A process is its maker's child. Where the process events heard a process made, the process that made it is
  its parent, though a sample already holds it under pid 1: what a tree starts through a shell that returns
  at once - a command left in the background - is the tree's child, is kept, and what it runs later is the
  tree's, also in a round where the tree itself is quiet.
- A program run through `sudo` gets a line. A plain reader cannot read the file of a process that runs as
  another user; until now such a child had no line at all. It is now named by the name the kernel gave it,
  and its line says that its file was not read (`files_unread`).
- Said, not hidden: a tree that has ended is written nothing, and how many processes its kept children were
  heard to start is in the report's PROCESS EVENTS section and is a hole of the result.
- Measured on GitHub's Linux machine (kernel 7.0; the rig's X43 to X46, each by the child's own entry in its
  line and a NET-TOOL finding that cites that line): the fetch a `bash -c` ran in its own pid a round after its
  own line; `nc -z`, named `nc`; the fetch of a bash that outlived the `sh` that started it; the same fetch
  run through `sudo -n`, its file not read. The first run of X45 was MISSED: that is how the maker's rule came.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- Nothing changes on Windows in this number.

Not measured:
- Under an act-root - an agent that holds no connection at a sample - the sample's parent still stands: what
  its shell leaves in the background is nobody's, as before. Ruled so until a desktop's measure; the next task.
- What a short child talks to, and a tree that lives whole between two samples: not seen yet (the next task).
- A tree kept alive by the children it left: today the tree ends and its children's later acts are counted,
  not written.
- A name is the process's own to choose: a tool run through `sudo` under another name is missed, and a
  process can call itself by a tool's name it is not (its tree then alarms by its own doing).
- A desktop's ordinary work for an hour: what these lines add to HOST-RHYTHM's and NET-TOOL's findings.
- Pid reuse, a tree that has gone, the bounds of 8 programs and 512 kept children: on made-up rounds only.
- How often the reader loses its race with a process that ends before it is read. On the rig's last run before
  this number one `nc` of 14 short acts was gone before the reader read anything of it (its record given, its
  program and name said as not read, so no line; the claim X31 MISSED); the same commit run again gave 14 of
  14, as every run before had. The watch counts such a child in PROCESS EVENTS (programs not read); the rate
  on a real desktop is not measured.

## 0.7.0 - 2026-11-21

What is new:
- The read of Windows' autostart places is made fit for a watch (ADR-0014 Amendments I to L). `python -m
  raqib.autostart` now keeps what every place, and every key inside it, last held, and says each change by its
  kind: an entry added, changed or removed; a task rescheduled (its triggers moved, its actions the same); a
  user's hive loaded or unloaded, as one change and not its entries; a Startup file that became a link. It
  still stands alone: the watch does not read it yet, and no rule judges a change (the next task).
- What it cannot say it says. A place the read's deadline cut, a key refused, a key or folder of more than a
  thousand entries, a file held open by its maker: each is said as not read, at each read, and nothing in it is
  said added or removed for having been out of reach. A part read for the first time late is taken as it is and
  said once as that, never as hundreds of entries planted.
- It does not get in the way: a Startup file is opened with every sharing and never through a link, and each
  read begins one place further than the last, so that one slow key cannot keep the others unread.
- A program's name is said `would run` where the text names one program however it is read, `may run` where it
  does not. Every hash is salted anew by each process, so that two runs cannot be set side by side.
- Measured on GitHub's Windows machines: a file held open with no sharing is said as added by the read made
  while it was held and read after it was let go; a real symbolic link is read as a link; a file the module
  holds is renamed and deleted by another call; of 687 services' texts 685 are `would run` (before the ruling
  that measured it, 444 of 689); the stand-in's Run value, Startup file and service each said added and later
  removed in 42 reads, the longest 0.125 s (X37 on the rig).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.

Not measured:
- No read on a real machine met the deadline or a bound (the longest took 0.219 s): the cut, the turn of the
  places and of the users, the bound of a thousand and a base taken late have run on made-up registries only.
- A real desktop: how often Windows itself changes a service or a task (one change of a service that nobody of
  the rig made was seen once), and so what a rule on these changes would cost.
- An open by another process that asks for no sharing while the read holds a file; a file swapped for a link
  between the listing and the open; a reparse point that is not a symbolic link; a hive loading at a logon.
- Whether a plain user can deny its own Run key to a reader of another identity while Windows still runs it
  (the service's case).

## 0.6.0 - 2026-11-21

What is new:
- Ready content for a SOC's search engine, under `siem/` (ADR-0017 and its Amendments A to C): for Elasticsearch
  and for OpenSearch an ingest pipeline and an index template that turn each line of the events file into one
  document - an event with the fields EVENT.md's Mapping names, or an error document that keeps the whole line
  and says why it is no event; none is dropped. Seven searches: every alarm, one rule's findings, the holes, the
  watches that did not end clean, the lines kept as error documents, the hosts that went silent, and the runs
  that stopped with no end. Nine Sigma rules with a pipeline of names, and a table and an ATT&CK layer of every
  rule the report lists. `siem/README.md` says how to install each and what the content trusts.
- Silence is judged by the engine's own clock against a deadline every line gives - its arrival and two of its
  own heartbeat's interval, an interval counted as a day at most - so no time is given by the person who asks,
  and a host's clock cannot hide it.
- Measured on GitHub's Linux machine against Elasticsearch 8.15.3 and OpenSearch 2.17.1 (the rig's claims X39 to
  X42, each run): 111 lines sent, none refused - the real watch's own file, every example of the spec, made-up
  events of each rule's class with a near miss for each, 23 malformed lines (each an error document with the
  reason the page names, and the line after it kept), and a shipper's own fields kept or moved aside; every
  search equal to a count made apart from the engine, the two searches of silence at four moments; each Sigma
  rule, converted by pinned tools, matching its own event and not its near miss.
- Nothing of the watch itself changes in this number: the same events, the same rules.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- The content is not installed with Raqib: it is files of the checkout, installed on the engine as
  siem/README.md says (the pipeline and the template before the first line reaches the index).

Not measured:
- Splunk, Microsoft Sentinel and Wazuh: no content for them yet (the next tasks), and nothing of this content
  was run on them. The Sigma rules were converted and run for Elasticsearch and OpenSearch only.
- A real shipper tailing the file on a host (Filebeat, Fluent Bit, Logstash): the rig sends the lines itself.
  A shipper's field of another shape than the ones the page names may make an engine refuse a line.
- Volume, more than one node or shard, retention, an engine with its security on, and either search of silence
  run on a schedule with an alert: each engine has its own way, and none was set up here.
- The two days a forged heartbeat can keep a host off the search for silence, and a bound of 10000 hosts or
  runs being met: ruled and said, not run.
- The ATT&CK layer was never loaded into a Navigator.

## 0.5.0 - 2026-11-21

What is new:
- On Linux, a program that starts and ends between two samples is judged (ADR-0007 Amendments BY to CB). The
  watch's helper hears the kernel's process events; each round takes the processes it heard, and one that began
  under a tree that talks at a sample is that tree's child: it gets its line, and NET-TOOL and DESTRUCT-CMD
  judge it by the name of its program's file. Measured on GitHub's Linux machine: a `wget` that lived under a
  second is a NET-TOOL finding of its tree. Until now such a program was not seen at all on Linux.
- The report's PROCESS EVENTS section says what was given to the rounds, what was joined to a tree, what the
  watch left out as its own, and every way the reader was not whole; a reader that was late, ended, lost
  events or held back a rest after it had answered is a hole of the result, so the result says INCOMPLETE
  unless a finding makes it an alarm.
- A line of a tree's children says where each was seen (`command_sources`: the sample, the process events, or
  both), in a round that heard the reader.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.

Not measured:
- Three things a child can do and not be judged, said in the report and the guide, measured for the next step:
  it changes its program after its line was written (a shell that runs its last command in its own place, in
  a later round); its parent was given in an earlier round and has ended; its program's file is not called as
  the tool is (on Ubuntu 24.04 `nc` is the file `nc.openbsd`, `telnet` is `inetutils-telnet`, `ftp` is
  `tnftp`), so a rule's list of names can miss it.
- A tree that lives whole between two samples, and what a short child talks to: not seen yet (the next tasks).
- A desktop's ordinary work for an hour: how many findings the short children add (HOST-RHYTHM counts them as
  acts now).

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
