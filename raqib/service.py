"""`raqib service install | remove | status` (M12.1, ADR-0013): the host watch as a unit of the system's.

Linux only (systemd). The unit runs `raqib watch --host` with the system's rights, so that the agent it watches
cannot stop it, cannot write its record again, and cannot leave its sight by becoming another user (A-1). The
watch itself is not changed: this module writes one file, /etc/systemd/system/raqib-watch.service, and asks the
system's systemctl to load, enable and start it; removal undoes that, and leaves the service's record
(/var/lib/raqib) unless --purge is given (A-4).

A unit of the system's runs as root what it is told to run, so the install refuses unless the code it would run
is root's alone (A-3, AB-3): the interpreter, walked to its end through every link; pyvenv.cfg beside it or one
folder above; every existing folder of sys.path and every *.pth file in each; every file and folder of the
raqib package; and every folder above each of them up to /. Each must be owned by uid 0 and writable by
neither its group nor others; a link is checked as itself (its owner: a link's own mode bits say nothing) and
then as what it points to, whole, its folders too; a loop, or links past LINK_DEPTH, is a refusal.

Refuse rather than repair: a unit of the name without Raqib's mark, a unit path or a state path that is a link,
a systemctl that fails - each is said and left as it is. The unit's text is UNIT_TEXT with one hole, the
interpreter's path, which holds only `A-Za-z0-9/._+-` (A-7); nothing else in it comes from an argument, the
environment or a file. systemctl is run from a fixed list of paths (never found by PATH), with a list of
arguments, no shell, a fixed environment and a timeout, by one function, run_systemctl.

Every call of the system (the platform, the uid, stat and readlink, listing a folder, the unit's write and
removal, the record's removal, systemctl's run) goes through one object, System; a test hands its own, so no
test needs root or Linux, writes under /etc, or runs systemctl. Nothing runs at import. The standard library
only; no network module.

Exit codes: install 0 done, 1 the unit written but systemctl failed (said, left as it is), 2 refused (nothing
written); remove 0 done or nothing installed, 1 systemctl or a removal failed (said, left as it is), 2 refused
(nothing touched); status 0 active, 1 installed and not active, 3 not installed or systemctl cannot be run,
2 not Linux.
"""
from __future__ import annotations

import os
import posixpath
import re
import shutil
import stat as statmod
import subprocess
import sys

UNIT_NAME = "raqib-watch.service"
UNIT_DIR = "/etc/systemd/system"
UNIT_PATH = "/etc/systemd/system/raqib-watch.service"
STATE_DIR = "/var/lib/raqib"                 # A-5: the service's home, root's alone (StateDirectory, 0700)
RECORD = "/var/lib/raqib/.raqib/host"        # where the watch writes, HOME=/var/lib/raqib
MARK = "# raqib-service/1"                   # the first line of Raqib's unit; a unit without it is not Raqib's
SYSTEMCTLS = ("/usr/bin/systemctl", "/bin/systemctl")   # A-7: by its whole path, never by PATH
SYSTEMCTL_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat",
                 "SYSTEMD_COLORS": "0"}
SYSTEMCTL_TIMEOUT = 120.0                    # seconds; `enable --now` waits for the start
SAFE_PATH = re.compile(r"/[A-Za-z0-9/._+-]*\Z")   # A-7: refused, never quoted
LINK_DEPTH = 40                              # links followed at most for one path (the kernel's own bound)
HEAD_MAX = 4096                              # bytes of a unit file read to find the mark
TEXT_MAX = 2000                              # characters of systemctl's output kept
SHOW = ("LoadState", "UnitFileState", "ActiveState", "SubState", "Result", "ExecMainStatus")
FIX_ROOT = "run it as root (sudo raqib service ...): it asks for no elevation itself"

# E3 (A-3, A-5, A-6): the whole unit, one constant; its one hole is the interpreter's whole path (%s).
UNIT_TEXT = """# raqib-service/1
# Raqib's watch of this host as a unit of the system's (ADR-0013). Written by `raqib service install`,
# removed by `raqib service remove`. A unit of this name whose first line is not the mark above is not Raqib's.

[Unit]
Description=Raqib: the watch of this host (raqib watch --host)

[Service]
Type=simple
ExecStart=%s -I -m raqib watch --host --no-open --no-notify
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
"""


class Refused(Exception):
    """Exit 2: said, and nothing written or touched."""


def run_systemctl(systemctl, args, timeout=SYSTEMCTL_TIMEOUT):
    """(exit code or None, stdout, stderr) of the system's systemctl, at one of SYSTEMCTLS, with `args` (a list
    of constants): no shell, the environment SYSTEMCTL_ENV and nothing of the caller's, the folder /, stdin
    closed, at most `timeout` seconds (then stopped, and None). The one function that starts a program here
    (ADR-0013 AA-2: `raqib service` takes no process sample)."""
    if systemctl not in SYSTEMCTLS:
        return None, "", "%s is not one of %s" % (systemctl, ", ".join(SYSTEMCTLS))
    try:
        got = subprocess.run([systemctl] + [str(a) for a in args], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(SYSTEMCTL_ENV), cwd="/",
                             timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None, "", "no answer in %d s (stopped)" % timeout
    except OSError as exc:
        return None, "", "cannot be run (%s)" % type(exc).__name__
    return got.returncode, _text(got.stdout), _text(got.stderr)


def _text(data):
    text = (data or b"").decode("utf-8", "replace").strip()
    text = "".join(c if c.isprintable() or c == "\n" else "?" for c in text)
    return text[:TEXT_MAX]


class System:
    """Every call raqib service makes of the system, here alone (a test hands an object of its own)."""

    def platform(self):
        return sys.platform

    def euid(self):
        return os.geteuid()

    def python(self):
        return sys.executable

    def sys_path(self):
        return list(sys.path)

    def getcwd(self):
        return os.getcwd()

    def package_dir(self):
        return os.path.dirname(os.path.abspath(__file__))

    def stat(self, path, follow_symlinks=True):
        return os.stat(path, follow_symlinks=follow_symlinks)

    def readlink(self, path):
        return os.readlink(path)

    def listdir(self, path):
        return sorted(os.listdir(path))

    def walk(self, top):
        """(folder, [subfolders], [files]) of the package, links not followed; a folder that cannot be listed
        raises (silence is not a clean package)."""
        def fail(exc):
            raise exc
        return os.walk(top, onerror=fail, followlinks=False)

    def read_head(self, path):
        """The first HEAD_MAX bytes of a file, not through a link."""
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            return f.read(HEAD_MAX)

    def systemctl_path(self):
        for path in SYSTEMCTLS:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    def systemctl(self, path, args):
        return run_systemctl(path, args)

    def write_unit(self, text):
        """UNIT_PATH written whole: a file beside it (root, 0644), then a rename over it."""
        tmp = "%s/.%s.%d.tmp" % (UNIT_DIR, UNIT_NAME, os.getpid())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        try:
            with os.fdopen(fd, "wb") as f:
                os.fchown(f.fileno(), 0, 0)
                os.fchmod(f.fileno(), 0o644)
                f.write(text.encode("ascii"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, UNIT_PATH)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def remove_unit(self):
        os.unlink(UNIT_PATH)

    def remove_state(self):
        """STATE_DIR and what it holds, the constant and nothing else; links inside are removed as links,
        never followed (refused where this system's removal cannot promise that)."""
        if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
            raise OSError("this system's removal could follow a link out of %s" % STATE_DIR)
        shutil.rmtree(STATE_DIR)


# --- E1 (A-3, AB-3): the code a unit of the system's runs is the system's ----------------------------------------

def _bad(st):
    """Why a file or folder (not a link) is not root's alone, or None."""
    if st.st_uid != 0:
        return "owned by uid %d, not root" % st.st_uid
    if st.st_mode & statmod.S_IWOTH:
        return "writable by others (mode %04o)" % statmod.S_IMODE(st.st_mode)
    if st.st_mode & statmod.S_IWGRP:
        return "writable by its group (mode %04o)" % statmod.S_IMODE(st.st_mode)
    return None


def _walk(path, stat, readlink, good):
    """(where, why) of the first part of `path` that is not root's alone, walked from / as the system does:
    each folder on the way and the end; a link by its owner, then what it points to, whole. None: all good."""
    if not isinstance(path, str) or not path.startswith("/"):
        return str(path), "not an absolute path"
    todo = [c for c in path.split("/") if c]
    done, links = "/", 0
    if "/" not in good:
        try:
            why = _bad(stat("/", follow_symlinks=False))
        except OSError as exc:
            return "/", "cannot be read (%s)" % type(exc).__name__
        if why:
            return "/", why
        good.add("/")
    while todo:
        part = todo.pop(0)
        if part == ".":
            continue
        if part == "..":
            done = posixpath.dirname(done)
            continue
        here = posixpath.join(done, part)
        if here in good:
            done = here
            continue
        try:
            st = stat(here, follow_symlinks=False)
        except OSError as exc:
            return here, "cannot be read (%s)%s" % (type(exc).__name__, _on_way(here, path))
        if statmod.S_ISLNK(st.st_mode):
            if st.st_uid != 0:
                return here, "a link owned by uid %d, not root%s" % (st.st_uid, _on_way(here, path))
            links += 1
            if links > LINK_DEPTH:
                return here, "more than %d links to follow (a loop of links?)%s" % (LINK_DEPTH, _on_way(here, path))
            try:
                target = readlink(here)
            except OSError as exc:
                return here, "a link that cannot be read (%s)%s" % (type(exc).__name__, _on_way(here, path))
            if target.startswith("/"):
                done = "/"
            todo = [c for c in target.split("/") if c] + todo
            continue
        why = _bad(st)
        if why:
            return here, why + _on_way(here, path)
        good.add(here)
        done = here
    return None


def _on_way(here, path):
    return "" if here == path else " (on the way to %s)" % path


def owned_by_root(paths, stat=os.stat, readlink=os.readlink):
    """E1: (where, why) of the first of `paths` - or of a folder above it, or of a link on its way, or of what
    such a link points to - that is not owned by uid 0 or is writable by its group or by others; None where
    every one is root's alone. Folders are checked from / down, so the highest that is not is the one said."""
    good = set()
    for path in paths:
        bad = _walk(path, stat, readlink, good)
        if bad:
            return bad
    return None


def install_paths(system, python):
    """What the unit's interpreter reads as code, or as where code is, before and as Raqib runs (A-3, AB-3):
    the interpreter as started (walked to its end); pyvenv.cfg beside it or one folder above; every existing
    entry of sys.path and every *.pth file in each of its folders; every file and folder of the raqib package.
    Found by where they are: nothing is read or run to find them."""
    paths = [python]
    for folder in (posixpath.dirname(python), posixpath.dirname(posixpath.dirname(python))):
        cfg = posixpath.join(folder, "pyvenv.cfg")
        if _exists(system, cfg):
            paths.append(cfg)
    cwd = None
    for entry in system.sys_path():
        if not isinstance(entry, str):
            continue
        if not entry.startswith("/"):
            cwd = cwd or system.getcwd()
            entry = posixpath.join(cwd, entry) if entry else cwd
        entry = entry.rstrip("/") or "/"
        if not _exists(system, entry):
            continue
        paths.append(entry)
        try:
            is_dir = statmod.S_ISDIR(system.stat(entry).st_mode)
        except OSError:
            continue   # the walk says it
        if is_dir:
            paths += [posixpath.join(entry, n) for n in system.listdir(entry) if n.endswith(".pth")]
    for folder, dirs, files in system.walk(system.package_dir()):
        folder = folder.replace("\\", "/")
        paths.append(folder)
        paths += [posixpath.join(folder, n) for n in sorted(dirs) + sorted(files)]
    return paths


def _exists(system, path):
    try:
        system.stat(path, follow_symlinks=False)
        return True
    except OSError:
        return False


# --- E3: the unit's text --------------------------------------------------------------------------------------

def unit_text(python):
    """UNIT_TEXT with the interpreter's whole path in its one hole (A-7: refused where the path is not one)."""
    why = python_refused(python)
    if why:
        raise Refused(why)
    return UNIT_TEXT % python


def python_refused(python):
    if not isinstance(python, str) or not python:
        return "this interpreter does not say its own path (sys.executable is empty)"
    if not SAFE_PATH.match(python):
        return ("the interpreter's path %r holds a character outside A-Za-z0-9/._+- or is not absolute: it is"
                " refused, never quoted (ADR-0013 A-7)" % python)
    if any(c in ("", ".", "..") for c in python.split("/")[1:]):
        return "the interpreter's path %s is not a plain whole path (an empty part, . or ..)" % python
    return None


# --- E2, E4, E5: the commands -------------------------------------------------------------------------------------

def unit_state(system):
    """("none", None), ("ours", None) or ("other", why): what is at UNIT_PATH (a link or no regular file is not
    Raqib's; a file is Raqib's only where its first line is the mark)."""
    try:
        st = system.stat(UNIT_PATH, follow_symlinks=False)
    except FileNotFoundError:
        return "none", None
    if statmod.S_ISLNK(st.st_mode):
        return "other", "%s is a link, not Raqib's file" % UNIT_PATH
    if not statmod.S_ISREG(st.st_mode):
        return "other", "%s is not a regular file" % UNIT_PATH
    head = system.read_head(UNIT_PATH)
    first = head.split(b"\n", 1)[0].rstrip(b"\r")
    if first != MARK.encode("ascii"):
        return "other", "%s does not carry Raqib's mark (%s) as its first line: it is not Raqib's" % (
            UNIT_PATH, MARK)
    return "ours", None


def _linux(system, action):
    platform = system.platform()
    if not str(platform).startswith("linux"):
        raise Refused("raqib service %s: Linux only (systemd); this is %s" % (action, platform))


def _root(system, action):
    if system.euid() != 0:
        raise Refused("raqib service %s: not root, nothing done; %s" % (action, FIX_ROOT))


def _systemctl(system, action):
    path = system.systemctl_path()
    if not path:
        raise Refused("raqib service %s: no systemctl at %s; nothing done" % (action, " or ".join(SYSTEMCTLS)))
    return path


def _call(system, path, args, out):
    """Run systemctl with args, say what it said; True where it exited 0."""
    code, said, err = system.systemctl(path, args)
    words = " ".join([path] + list(args))
    if code == 0:
        out.write("  %s: done\n" % words)
        return True
    out.write("  %s: FAILED (%s)%s\n" % (words, "exit %s" % code if code is not None else "not run",
                                          (": " + (err or said).replace("\n", " ")[:300]) if err or said else ""))
    return False


def install(system, out, start=True):
    """E2: refused (Refused, nothing written) or the unit written and, with start, enabled and started."""
    _linux(system, "install")
    _root(system, "install")
    python = system.python()
    why = python_refused(python)
    if why:
        raise Refused("raqib service install: %s" % why)
    try:
        bad = owned_by_root(install_paths(system, python), stat=system.stat, readlink=system.readlink)
    except OSError as exc:
        bad = ("(the list of paths)", "cannot be made (%s: %s)" % (type(exc).__name__, exc))
    if bad:
        raise Refused("raqib service install: refused: %s is %s. A unit of the system's runs this code as root;"
                      " it must be root's alone (ADR-0013 A-3): install raqib where only root can write, e.g. a"
                      " venv in a folder root makes for it" % bad)
    path = _systemctl(system, "install")
    try:
        kind, why = unit_state(system)
    except OSError as exc:
        kind, why = "other", "%s cannot be read (%s)" % (UNIT_PATH, type(exc).__name__)
    if kind == "other":
        raise Refused("raqib service install: %s; not touched" % why)
    text = unit_text(python)
    try:
        system.write_unit(text)
    except OSError as exc:
        raise Refused("raqib service install: %s cannot be written (%s: %s); nothing written" % (
            UNIT_PATH, type(exc).__name__, exc))
    out.write("raqib service install\n")
    out.write("  %s %s (root, 0644): ExecStart=%s -I -m raqib watch --host --no-open --no-notify\n" % (
        "replaced Raqib's own" if kind == "ours" else "wrote", UNIT_PATH, python))
    out.write("  every path the unit loads code from is root's alone (ADR-0013 A-3)\n")
    if not _call(system, path, ["daemon-reload"], out):
        out.write("RESULT: the unit is written; systemctl failed; left as it is\n")
        return 1
    if not start:
        out.write("  --no-start: neither enabled nor started; start it with: systemctl enable --now %s\n" % UNIT_NAME)
        out.write("RESULT: installed, not started\n")
        return 0
    if not _call(system, path, ["enable", "--now", UNIT_NAME], out):
        out.write("RESULT: the unit is written; systemctl failed; left as it is (raqib service status says"
                  " more)\n")
        return 1
    if kind == "ours":
        out.write("  a watch that was already running keeps the unit it started with until: systemctl restart"
                  " %s\n" % UNIT_NAME)
    out.write("  the record: %s (root's alone); raqib service status says how it runs\n" % RECORD)
    out.write("RESULT: installed, enabled and started\n")
    return 0


def _purge_refused(system, state):
    """Why --purge may not remove `state`, or None (and "missing" where there is nothing to remove)."""
    if state != STATE_DIR:
        return "--purge removes %s and nothing else; %s is refused" % (STATE_DIR, state)
    try:
        st = system.stat(state, follow_symlinks=False)
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return "%s cannot be read (%s)" % (state, type(exc).__name__)
    if statmod.S_ISLNK(st.st_mode):
        return "%s is a link: not followed, not removed" % state
    if not statmod.S_ISDIR(st.st_mode):
        return "%s is not a folder: not removed" % state
    if st.st_uid != 0:
        return "%s is owned by uid %d, not root: not the service's, not removed" % (state, st.st_uid)
    return None


def remove(system, out, purge=False, state=STATE_DIR):
    """E4: the unit stopped, disabled and removed (only with Raqib's mark), then reloaded; the record stays and
    is said; with purge, the record's folder (STATE_DIR, and only it) is removed too."""
    _linux(system, "remove")
    _root(system, "remove")
    purge_why = _purge_refused(system, state) if purge else None
    if purge_why and purge_why != "missing":
        raise Refused("raqib service remove: %s; nothing touched" % purge_why)
    try:
        kind, why = unit_state(system)
    except OSError as exc:
        kind, why = "other", "%s cannot be read (%s)" % (UNIT_PATH, type(exc).__name__)
    if kind == "other":
        raise Refused("raqib service remove: %s; not touched" % why)
    out.write("raqib service remove\n")
    if kind == "ours":
        path = _systemctl(system, "remove")
        if not _call(system, path, ["disable", "--now", UNIT_NAME], out):
            out.write("RESULT: the unit is not removed; left as it is\n")
            return 1
        try:
            system.remove_unit()
        except OSError as exc:
            out.write("  %s cannot be removed (%s)\nRESULT: stopped and disabled, the file left as it is\n" % (
                UNIT_PATH, type(exc).__name__))
            return 1
        out.write("  removed %s\n" % UNIT_PATH)
        if not _call(system, path, ["daemon-reload"], out):
            out.write("RESULT: the unit is removed; systemctl's reload failed\n")
            return 1
    else:
        out.write("  no unit installed (no %s): nothing to stop or remove\n" % UNIT_PATH)
    if not purge:
        out.write("  the record stays: %s (its events: %s/events.jsonl); raqib service remove --purge removes"
                  " it\n" % (STATE_DIR, RECORD))
    elif purge_why == "missing":
        out.write("  --purge: no %s, nothing to remove\n" % STATE_DIR)
    else:
        try:
            system.remove_state()
        except OSError as exc:
            out.write("  --purge: %s cannot be removed (%s: %s); left as it is\nRESULT: the unit removed, the"
                      " record not\n" % (STATE_DIR, type(exc).__name__, exc))
            return 1
        out.write("  --purge: removed %s, and nothing else\n" % STATE_DIR)
    out.write("RESULT: %s\n" % ("removed" if kind == "ours" else "nothing installed"))
    return 0


def status(system, out):
    """E5: installed (the file with the mark), enabled and active by systemctl's own words; no rights needed."""
    _linux(system, "status")
    out.write("raqib service status\n")
    try:
        kind, why = unit_state(system)
    except OSError as exc:
        kind, why = "other", "%s cannot be read (%s)" % (UNIT_PATH, type(exc).__name__)
    if kind != "ours":
        out.write("  not installed: %s\n" % (why or "no %s" % UNIT_PATH))
        out.write("RESULT: NOT INSTALLED\n")
        return 3
    out.write("  installed: %s (it carries %s)\n" % (UNIT_PATH, MARK))
    path = system.systemctl_path()
    if not path:
        out.write("  systemctl cannot be run: none at %s\nRESULT: NOT KNOWN\n" % " or ".join(SYSTEMCTLS))
        return 3
    code, said, err = system.systemctl(path, ["show", UNIT_NAME, "--no-pager", "--property=" + ",".join(SHOW)])
    props = {}
    for line in said.splitlines():
        key, _, value = line.partition("=")
        if key in SHOW:
            props[key] = value
    if code != 0 or "ActiveState" not in props:
        out.write("  systemctl cannot be run: %s show %s: %s: %s\nRESULT: NOT KNOWN\n" % (
            path, UNIT_NAME, "exit %s" % code if code is not None else "not run",
            (err or said or "no answer").replace("\n", " ")[:300]))
        return 3
    out.write("  enabled: %s (systemctl's UnitFileState)\n" % (props.get("UnitFileState") or "?"))
    out.write("  active: %s, %s (systemctl's ActiveState, SubState)\n" % (props["ActiveState"] or "?",
                                                                         props.get("SubState") or "?"))
    out.write("  the record: %s (root's alone)\n" % RECORD)
    if props["ActiveState"] == "active":
        out.write("RESULT: ACTIVE\n")
        return 0
    out.write("  last result: %s, exit status %s (systemctl's Result, ExecMainStatus)\n" % (
        props.get("Result") or "?", props.get("ExecMainStatus") or "?"))
    out.write("RESULT: INSTALLED, NOT ACTIVE\n")
    return 1


def cli_run(args, out, system=None):
    """`raqib service ACTION` from raqib/cli.py (its only importer). Refused: exit 2, said by the caller."""
    system = system or System()
    if args.no_start and args.action != "install":
        raise Refused("raqib service: --no-start is install's only")
    if args.purge and args.action != "remove":
        raise Refused("raqib service: --purge is remove's only")
    if args.action == "install":
        return install(system, out, start=not args.no_start)
    if args.action == "remove":
        return remove(system, out, purge=args.purge)
    return status(system, out)
