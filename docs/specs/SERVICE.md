# The service: Raqib's watch as a unit of the system's (ADR-0013)

On Linux, an administrator can run the host watch (`raqib watch --host`) as a systemd unit of the system's,
`raqib-watch.service`. It runs with the system's rights, so the agent it watches cannot stop it, cannot write its
record again, and cannot leave its sight by becoming another user (ADR-0013 A-1). This is stage S1: the watch's
unit on Linux. The forwarder as a unit (S2), what a person without rights reads of the service (S3) and Windows
(S4) come later. The watch itself is unchanged.

## The three commands

| Command | Does |
|---|---|
| `raqib service install [--no-start]` | As root only: checks that the code the unit would run is root's alone (below), writes the unit, runs `systemctl daemon-reload` and `systemctl enable --now raqib-watch.service`, and says what it did. `--no-start` writes the unit and reloads; the unit is neither enabled nor started. Exit 0 done, 1 the unit written but systemctl failed (said, left as it is), 2 refused (said, nothing written). |
| `raqib service remove [--purge]` | As root only: runs `systemctl disable --now raqib-watch.service` (stops and disables it), removes the unit's one file if it carries Raqib's mark, and runs `systemctl daemon-reload`. The record stays and its path is said. `--purge` removes `/var/lib/raqib` too, and only that folder. No unit installed is exit 0, saying so. Exit 1 when systemctl or a removal failed (said, left as it is), 2 refused (said, nothing touched). |
| `raqib service status` | Needs no rights: whether the unit is installed (the file with Raqib's mark), enabled and active, by systemctl's own words (`systemctl show`: UnitFileState, ActiveState, SubState), and the unit's last result (Result, ExecMainStatus) when it is not active. Exit 0 active, 1 installed and not active, 3 not installed or systemctl cannot be run (said), 2 not Linux. |

`install` and `remove` do nothing unless run as root, and say so; they ask for no elevation themselves (run
them with `sudo`). Off Linux every one of the three is exit 2.

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
ExecStart=PYTHON -I -m raqib watch --host --no-open --no-notify
Environment=HOME=/var/lib/raqib
StateDirectory=raqib
StateDirectoryMode=0700
Restart=on-failure
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
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
```

The first line is Raqib's mark. A unit of this name whose first line is not the mark is not Raqib's: install
and remove refuse it and leave it as it is, and status says it is not installed. A unit path that is a link is
not Raqib's either.

The interpreter runs in Python's isolated mode (`-I`): it reads no PYTHON* variable and no user's site folder,
and the folder it starts in is not on its path. Its environment is systemd's, with HOME set to the service's
own home. The hardening is the set the Table's probe ran with (ADR-0013 A-6; `systemd-analyze security`: 2.8,
OK):
- no new privileges;
- the system read-only and the homes read-only;
- private temporary files and devices;
- the kernel's tunables and modules, the control groups, the clock and the host name protected;
- no realtime, no set-id, no new namespaces;
- the address families unix, netlink, inet and inet6, with every address denied but the local host's (the
  watch calls no network);
- the capabilities to read other users' processes and sockets (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH,
  CAP_NET_ADMIN), and no others;
- the system calls of a service.

A directive that a system's systemd does not know is that system's to ignore. The status does not say which yet
(below).

## What install checks, and why

A unit of the system's runs as root what it is told to run. If that code is a file a user can write, the unit
gives that user the system. So before it writes anything, the install walks every path below from `/` down, as
the system walks it. Each folder on the way and each path itself must be owned by uid 0 and writable by neither
its group nor others. The first path that is not is said, with why, and the install is refused (exit 2, nothing
written; ADR-0013 A-3, AB-3):

- the interpreter as it was started (sys.executable), walked to its end through every link;
- `pyvenv.cfg` beside the interpreter or one folder above it, where there is one (it says where a venv's code
  is);
- every existing entry of sys.path, made whole against the folder the install runs in, and every `*.pth` file
  in each of those folders (`-I` does not stop a `.pth` file's lines from running);
- every file and folder of the raqib package the install runs from.

A symbolic link is checked as itself, by its owner (a link's mode bits say nothing). Then what it points to is
checked whole, its folders too. A loop of links, or more than 40 links to follow for one path, is a refusal,
never a pass. A path that cannot be read is a refusal too. These paths are found by where they are: nothing is
read or run to find them.

The install also refuses where:
- the platform is not Linux;
- the caller is not root;
- the interpreter's path holds a character outside `A-Za-z0-9/._+-`;
- no systemctl is at `/usr/bin/systemctl` or `/bin/systemctl` (it is never found by PATH);
- a unit of the name is there without Raqib's mark.

A raqib that a person installed for themselves (in their home, or a venv they own) is refused, by design. The
install that passes is root's own: a folder root makes for it, a venv in that folder (`python3 -m venv DIR`),
and `DIR/bin/pip install` run as root, then `sudo DIR/bin/raqib service install`. A venv in a folder a user can
write (on some machines `/opt` is one) is refused. `raqib watch` as a person runs it is unchanged and needs none
of this.

The unit is written beside its place, then renamed over it, so a reader never sees half a unit. A second
install over Raqib's own unit replaces it. A watch that is already running keeps the unit it started with
until it is restarted (`systemctl restart raqib-watch.service`); the install says so.

## Where the record is

The service's home is `/var/lib/raqib`: systemd makes it root's, mode 0700 (StateDirectory; ADR-0013 A-5). Its
watch writes there as any watch writes in its home. The record and the events are in
`/var/lib/raqib/.raqib/host/`, and the events file is `/var/lib/raqib/.raqib/host/events.jsonl`. The service's
rules and overlay are there too. No user's `~/.raqib` is read by it, so an agent that turns a rule off in its
user's overlay turns nothing off in the service. In this stage a person without rights cannot read the record.
`raqib service status` says whether the service runs, and root reads the record.

## What removal leaves

`raqib service remove` stops and disables the unit, removes its one file (only with Raqib's mark), and reloads
systemd. It leaves the record: `/var/lib/raqib`, whose path it says. `raqib service remove --purge` also removes
`/var/lib/raqib` and nothing else. That path is a constant, never an argument. It must be a real folder owned by
root, not a link, and the removal does not follow a link out of it: a link inside is removed as a link. A state
path that is a link, or that is not `/var/lib/raqib`, is refused before anything is touched. A systemctl that
fails is said, and what it did not do is left as it is: the file of a unit that could not be stopped is not
removed.

## What it does not do yet

- It does not say which of the unit's directives the system's systemd ignored (A-6 asks the status to say so;
  that needs the system's verification tool or its journal, a later stage).
- It installs no forwarder (S2) and gives a person without rights no view of the record (S3), and there is
  nothing for Windows (S4).
- It restarts nothing on a second install. It checks the paths when it installs, not afterwards: a later change
  that root makes to them is root's own.
- The service's watch and a person's own watch do not know each other. Each writes its own record.
