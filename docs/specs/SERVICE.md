# The service: Raqib's watch as a unit of the system's (ADR-0013)

On Linux, an administrator can run the host watch (`raqib watch --host`) as a systemd unit of the system's,
`raqib-watch.service`. It runs with the system's rights, so the agent it watches cannot stop it, cannot write its
record again, and cannot leave its sight by becoming another user (ADR-0013 A-1). This is stage S1: the watch's
unit on Linux. The forwarder as a unit (S2), what a person without rights reads of the service (S3) and Windows
(S4) come later. The watch itself is unchanged; the unit runs it with `--no-page`, so it serves no page (below).

## The three commands

| Command | Does |
|---|---|
| `raqib service install [--no-start]` | As root only: checks that the code the unit would run is root's alone (below) and says how many paths of which kinds it checked. With no unit file it first asks systemctl whether systemd holds a unit of the name (LoadState, ActiveState, FragmentPath): one loaded from any place, or running, is not Raqib's to replace, and a systemctl that gives no answer is a refusal too. Then it writes the unit, runs `systemctl daemon-reload`, and asks systemctl how the unit is loaded (FragmentPath, DropInPaths, NeedDaemonReload): a unit not as installed is neither enabled nor started (exit 1, `RESULT: the unit is written; NOT AS INSTALLED, not started: ...`). Else it runs `systemctl enable --now raqib-watch.service` (over Raqib's own unit: `systemctl enable` and `systemctl restart`, so no watch keeps the old text), waits 3 s and asks systemctl whether the unit is active and still as installed. `--no-start` writes the unit, reloads and makes the same check after the reload; the unit is neither enabled nor started, and where a watch of Raqib's unit is running it says that watch keeps the text it started with. Exit 0 done (and, started, active and as installed after 3 s: `RESULT: installed, enabled, active 3 s after its start`), 1 the unit written but systemctl failed, or not as installed (then not started), or not active or not as installed after 3 s (said; left as it is), 2 refused (said, nothing written). |
| `raqib service remove [--purge]` | As root only: runs `systemctl disable --now raqib-watch.service` (stops and disables it), removes the unit's one file if it carries Raqib's mark, runs `systemctl daemon-reload`, and asks systemctl for the removed unit's ActiveState: where it is `failed` (a stop after a finding reads so, the watch's own exit 1), it runs `systemctl reset-failed raqib-watch.service` and says so; a reset that fails is said and the exit stays what it was. The record stays and its path is said. `--purge` removes `/var/lib/raqib` too, and only that folder. With no unit file it asks systemctl for the unit's LoadState and ActiveState: LoadState `not-found` with ActiveState `inactive` or `failed` is exit 0 (nothing installed, said); anything else, or no answer, is said and is exit 1, and nothing is touched and nothing purged. Exit 1 also when systemctl or a removal failed (said, left as it is), 2 refused (said, nothing touched). |
| `raqib service status` | Needs no rights: whether the unit is installed (the file with Raqib's mark), enabled and active, by systemctl's own words (`systemctl show`: UnitFileState, ActiveState, SubState), whether it is as installed (below), how many times it was restarted (NRestarts), and the unit's last result (Result, ExecMainStatus) when it is not active. With no unit file it asks systemctl too, and says a unit of the name that systemd holds (`RESULT: NOT INSTALLED BY RAQIB, YET A UNIT OF THE NAME IS ACTIVE`, or `IS LOADED`, exit 3). Exit 0 active as installed, 1 installed and not active, or active but not as installed (`RESULT: ACTIVE, NOT AS INSTALLED`), 3 not installed or not known (a unit file that cannot be read, no systemctl, or no state from it), 2 not Linux. |

`install` and `remove` do nothing unless run as root, and say so; they ask for no elevation themselves (run
them with `sudo`). Off Linux every one of the three is exit 2.

A systemctl that ran and gave no answer in its time is said as "no answer in N s" (what it was asked may still be
done); one that exited non-zero is said with its exit and what it said. Neither is said as not run. No line says
a thing was done before it was.

## As installed

"As installed" means all of these, by systemd's word and the file's: systemd loaded the unit from
`/etc/systemd/system/raqib-watch.service` (FragmentPath) with no drop-in (DropInPaths empty), and has not seen
the file change since it loaded it (NeedDaemonReload=no); and the file's whole text, read at most 16384 bytes
(UNIT_MAX; a longer file is not), is byte for byte the text this Raqib writes for the interpreter its ExecStart
names. A unit changed in place with its first line kept, a file changed and not reloaded, or a drop-in, is
`NOT AS INSTALLED`, and status is not exit 0: a change of the unit shows as a stop does.

What still does not show: a change of Raqib's own code by root, or by a user who is root by sudo or polkit,
after the install (the check is made when it installs); which interpreter the install named, since status takes
it from the file; and the drop-in folders, which are root's by default and are not walked: a drop-in that is
there shows by DropInPaths, a folder that would let a user add one is not checked.

## The unit

`/etc/systemd/system/raqib-watch.service`, root's, mode 0644. Its text is one constant in raqib/service.py.
Its one hole, `PYTHON`, is the whole path of the interpreter that ran the install. A path that holds anything
but letters, digits and `/._+-`, or that is not a plain whole path (an empty part, `.` or `..`), is refused,
never quoted (ADR-0013 A-7). Nothing else in the text comes from an argument, the environment or a file:

```ini
# raqib-service/1
# Raqib's watch of this host as a unit of the system's (ADR-0013). Written by `raqib service install`,
# removed by `raqib service remove`. A unit of this name whose first line is not the mark above is not Raqib's.

[Unit]
Description=Raqib: the watch of this host (raqib watch --host)

[Service]
Type=simple
ExecStart=PYTHON -I -m raqib watch --host --no-page --no-notify
Environment=HOME=/var/lib/raqib
StateDirectory=raqib
StateDirectoryMode=0700
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
```

The first line is Raqib's mark. A unit of this name whose first line is not the mark is not Raqib's: install
and remove refuse it and leave it as it is, and status says it is not installed. A unit path that is a link is
not Raqib's either. Status reads the unit's head without waiting and only from what is a regular file when it is
opened.

The interpreter runs in Python's isolated mode (`-I`): it reads no PYTHON* variable and no user's site folder,
and the folder it starts in is not on its path. Its environment is systemd's, with HOME set to the service's
own home. The hardening is the set the Table's probe ran with (ADR-0013 A-6), narrowed as measured (ADR-0013
Amendment C):
- no new privileges;
- the system read-only and the homes read-only;
- private temporary files and devices;
- the kernel's tunables and modules, the control groups, the clock and the host name protected;
- no realtime, no set-id, no new namespaces;
- the address families unix and netlink alone, and every IP address denied: the watch serves no page and calls
  no network;
- the capabilities to read other users' processes and sockets (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH), and no
  others;
- the system calls of a service;
- `Restart=always`, 5 s after any end but systemctl's own stop, whatever the watch's exit.

## No page

The unit's watch runs with `--no-page`: it opens no listener and nothing listens on a port for it. A person's
own watch serves its page on the local host to every user of the machine; root's watch must not, because what it
sees (every user's trees and findings, and what /proc shows only root of other users' processes) is not every
user's to read. So no person and no agent reads root's view over a port, root parses no user's request, and there
is no port for anyone to take first. The record is root's alone (mode 0700). What the watch writes to its output
goes to the system's journal, which root and the groups the system gives the journal to can read; whoever reads
the journal reads the findings' lines the unit prints. What a person without rights reads of the service is
stage S3's to design.

## Who can stop it, and what a stop costs

The watched agent, running as a person without rights, cannot stop, restart or change a unit of the system's.
Root can, and root is also any user with sudo (a password it knows, none asked, or a ticket still valid) and any
user a polkit rule lets manage units: an agent running as such a user can stop it. A watch made to exit comes
back after 5 s, a gap each time; systemd counts the restarts (NRestarts) and `raqib service status` says the
count. A watch's exit status 1 is its own ALARM at its end, or an error; the journal says which
(`journalctl -u raqib-watch.service`). A stop after a finding reads as `failed` to systemd, since the watch's own
exit is 1 then; this stays for S1, and `raqib service remove` clears it (`systemctl reset-failed`). A user who is
root by sudo or polkit can also change the unit or Raqib's code: a change of the unit shows in status (NOT AS
INSTALLED), a change of Raqib's own code does not.

## What install checks, and why

A unit of the system's runs as root what it is told to run. If that code is a file a user can write, the unit
gives that user the system. So before it writes anything, the install refuses (exit 2, nothing written;
ADR-0013 A-3, AB-3, Amendment C) where:
- the interpreter runs without its site (`-S`, `sys.flags.no_site`): what it would walk is not what the unit's
  interpreter loads;
- PYTHONHOME or PYTHONPLATLIBDIR is set and the interpreter reads its environment (`sys.flags.ignore_environment`
  is 0): they move the library the install would walk, and the unit's `-I` ignores them; unset them, or run the
  install with `-I` or `-E`;
- the raqib package's folder is not itself directly in one of that interpreter's own site folders
  (`site.getsitepackages()`): install raqib into this interpreter; a checkout run by `-m`, an editable install,
  or a copy deeper below a site folder is not it;
- a `.pth` file in a folder of sys.path holds a byte other than printable ASCII (0x20 to 0x7e), tab, LF and CR:
  the versions of site split and decode such a file differently, so it is refused, with its path, and not read
  into entries.

With those refused, the unit's `-I` only takes entries away from sys.path, so what the install walks holds all
the unit will load from by its path. Two things are outside that: the environment the unit's own `.pth` import
lines run in, which is the unit's and not the install's, and what such a line may add or reach that is not an
entry of sys.path (a finder that maps names to folders, for one); neither is walked.

Then it walks every path below from `/` down, as the system walks it. Each folder on the way and each path
itself must be owned by uid 0 and writable by neither its group nor others. The first path that is not is said,
with why, and the install is refused:

- the interpreter as it was started (sys.executable), walked to its end through every link;
- `pyvenv.cfg` beside the interpreter or one folder above it, where there is one (it says where a venv's code
  is);
- under every entry of sys.path, made whole against the folder the install runs in, every file and folder,
  whole: the standard library's files and folders, their compiled files, the extension modules, a
  `sitecustomize.py`, and every `*.pth` file;
- the lines of each `*.pth` file in those folders that are paths (not blank, not `#`, not `import`), each made
  whole against the file's folder, as entries too, existing or not; a `.pth` file is read as text only once it
  was found root's alone, and nothing is run (`-I` does not stop a `.pth` file's lines from running);
- every file and folder of the raqib package the install runs from;
- the systemctl it found, each of the watch's own ss paths, and the unit's folder, `/etc/systemd/system`.

A symbolic link is checked as itself, by its owner (a link's mode bits say nothing). Then what it points to is
checked whole, its folders too; where it points to a folder, that folder is walked whole as well, each real
folder once, so a loop of folder links walks nothing twice. A loop of links, or more than 40 links to follow for
one path, is a refusal, never a pass. A walk of more than 200000 entries is refused, and the number said: a walk
that is not whole is not a pass. A path that does not exist (an entry of sys.path, a `.pth` line, the end of a
link) is checked as far as it exists: the folders above it, so that no user can make it there by writing; it is
not otherwise a refusal. A missing path under a place the system makes for a user (a login's run folder, a
mounted medium, a new home) can become that user's when the system makes it, without the user writing in a
folder of root's. A path that cannot be read is a refusal.

The install says what it checked as counts: how many paths, of which kinds (folders, files, links), under how
many entries of sys.path, how many `.pth` files it read and how many of their lines were entries; a link among
them is checked by its owner, and then what it points to.

The install also refuses where:
- the platform is not Linux;
- the caller is not root;
- the interpreter's path holds a character outside `A-Za-z0-9/._+-`;
- no systemctl is at `/usr/bin/systemctl` or `/bin/systemctl` (it is never found by PATH);
- a unit of the name is there without Raqib's mark;
- there is no unit file, yet systemd holds a unit of the name: loaded from any place, or running (its
  FragmentPath is said), or systemctl gives no answer (ADR-0013 AD-1).

A raqib that a person installed for themselves (in their home, or a venv they own) is refused, by design. The
install that passes is root's own: a folder root makes for it, a venv in that folder (`python3 -m venv DIR`),
and `DIR/bin/pip install` run as root, then `sudo DIR/bin/raqib service install`. A venv in a folder a user can
write (on some machines `/opt` is one) is refused. Give pip a copy of the checkout that root made
(`sudo cp -r CHECKOUT DIR/src`, then `sudo DIR/bin/pip install DIR/src`), not the checkout itself: a build as
root leaves root's own `build/` folder in the folder it builds from, and the person's next install from that
checkout then fails (seen in the field, 2026-11-20: `Operation not permitted` under `build/lib`; the remedy
there is `sudo rm -rf build raqib.egg-info` in the checkout). `raqib watch` as a person runs it is unchanged and needs none
of this.

The check guards the unit's starts, not the install itself: an install run from code a user can write has
already run that code as root before it refuses. Not checked: the shared libraries the interpreter and its
extension modules load (libpython and the libraries they name); they are found by reading those files, not by
where they are.

The unit is written beside its place, then renamed over it, so a reader never sees half a unit.

## What the two capabilities still open

As the kernel's rules read, not as measured: CAP_SYS_PTRACE lets a defect in the watch reach other processes,
root's own included, and read and change their memory; CAP_DAC_READ_SEARCH lets it read every file and list
every folder, whatever their modes. The hardening narrows what such a defect does; it does not remove it.

## The helper of the process events

As every watch on Linux, the unit's watch starts the helper of the process events (ADR-0007 Amendment BU;
docs/specs/PROC-EVENTS.md): a child of the unit's process that runs the reader of the kernel's process events and
answers the watch over its own input and output. It runs under the unit's limits, which already let the reader
hear (measured under them: the two capabilities, AF_NETLINK allowed), and it is ended with the unit: it ends when
its input ends, and systemd ends the unit's processes at its stop. What it heard is counted in the watch's report,
not judged; the rig's service run says whether the unit's watch heard.

## Where the record is

The service's home is `/var/lib/raqib`: systemd makes it root's, mode 0700 (StateDirectory; ADR-0013 A-5). Its
watch writes there as any watch writes in its home. The record and the events are in
`/var/lib/raqib/.raqib/host/`, and the events file is `/var/lib/raqib/.raqib/host/events.jsonl`. The service's
rules and overlay are there too. No user's `~/.raqib` is read by it, so an agent that turns a rule off in its
user's overlay turns nothing off in the service. `raqib service status` says whether the service runs, and root
reads the record. ACTIVE says the unit runs, not that the watch writes: a blind or a stuck watch is still
active, and reading what it writes is stage S3's.

## What removal leaves

`raqib service remove` stops and disables the unit, removes its one file (only with Raqib's mark), and reloads
systemd; where systemd then holds the removed unit as failed, it runs `systemctl reset-failed` for that unit alone
and says so, so that systemd lists no failed unit Raqib removed. It leaves the record: `/var/lib/raqib`, whose path
it says. `raqib service remove --purge` also removes `/var/lib/raqib` and nothing else. That path is a constant,
never an argument. It must be a real folder owned by root, not a link, and the removal does not follow a link out
of it: a link inside is removed as a link. A state path that is a link, or that is not `/var/lib/raqib`, is refused
before anything is touched. A systemctl that fails is said, and what it did not do is left as it is: the file of a
unit that could not be stopped is not removed.

## What it does not do yet

- It does not say which of the unit's directives the system's systemd ignored. On the rig's machine the rig
  says what systemd warned of and what the main process holds: it reads systemd's own word on the installed
  unit (its directives as `systemctl show` gives them, and the manager's journal lines that name the unit and
  say unknown, ignored, invalid or not support), any such line a finding, and the unit's main process's own
  word from /proc (its bounding set of capabilities, its seccomp mode and its no-new-privileges bit), MET only
  where they are the unit's (X29). That is not every directive in force.
- It installs no forwarder (S2) and gives a person without rights no view of the record (S3), and there is
  nothing for Windows (S4).
- It checks the paths when it installs, not afterwards: a later change that root makes to them is root's own.
- An agent in a network namespace of its own holds sockets the watch, in the host's namespace, may not see: not
  measured.
- The service's watch and a person's own watch do not know each other. Each writes its own record.
