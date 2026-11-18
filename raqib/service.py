"""`raqib service install | remove | status` (M12.1, ADR-0013): the host watch as a unit of the system's.

Linux only (systemd). The unit runs `raqib watch --host --no-page` with the system's rights, so that the agent it
watches cannot stop it, cannot write its record again, and cannot leave its sight by becoming another user (A-1);
it serves no page (AC-1). The watch itself is not changed: this module writes one file,
/etc/systemd/system/raqib-watch.service, and asks the system's systemctl to load, enable and start it; removal
undoes that, and leaves the service's record (/var/lib/raqib) unless --purge is given (A-4).

A unit of the system's runs as root what it is told to run, so the install refuses unless the code it would run
is root's alone (A-3, AB-3, AC-2 to AC-4, AD-4). It refuses an interpreter that runs without its site (-S), one
that reads PYTHONHOME or PYTHONPLATLIBDIR from its environment, and a raqib package that is not directly in one of
that interpreter's own site folders (a checkout, an editable install, a copy deeper below), so that what it
walks holds what the unit's `-I` will load from. Then it walks: the interpreter, to its end through every link;
pyvenv.cfg beside it or one folder above; under every entry of sys.path, every file and folder, whole; the lines
of each *.pth file in those folders that are paths, as entries too (a .pth file is read only once it was found
root's alone, and refused where it holds a byte outside printable ASCII, tab, LF and CR; nothing is run); every
file and folder of the raqib package; the systemctl found; each of the watch's ss paths; and the unit's folder;
and every folder above each of them up to /. Each must be owned by uid 0 and writable by neither its group nor
others. A link is checked as itself (its owner: a link's own mode bits say nothing) and then as what it points
to, whole, its folders too; where it points to a folder, that folder is walked whole as well, each real folder
once. A loop, or links past LINK_DEPTH for one path, is a refusal; so is a walk past WALK_MAX entries. A path
that does not exist (an entry of sys.path, a .pth line, a link's end) is checked as far as it exists: the
folders above it.

systemd is asked before a state is said or a file written (AD-1): a unit of the name that systemd holds with no
file at UNIT_PATH is not Raqib's to replace, remove or call absent. "As installed" (AD-2, AD-3) is: systemd
loaded the unit from UNIT_PATH with no drop-in and has not seen the file change since, and the file's whole text
is the text this Raqib writes for the interpreter it names; an install whose unit is not loaded so after the
reload is not started.

Refuse rather than repair: a unit of the name without Raqib's mark, a unit path or a state path that is a link,
a systemctl that fails - each is said and left as it is. The unit's text is UNIT_TEXT with one hole, the
interpreter's path, which holds only `A-Za-z0-9/._+-` (A-7); nothing else in it comes from an argument, the
environment or a file. systemctl is run from a fixed list of paths (never found by PATH), with a list of
arguments, no shell, a fixed environment and a timeout, by one function, run_systemctl. After the start the
install waits START_WAIT and asks systemctl whether the unit is active (AC-6); nothing is said that was not read
(AC-8, AC-9).

Every call of the system (the platform, the uid, the interpreter's flags and site folders, stat and readlink,
listing a folder, reading a file, the wait, the unit's write and removal, the record's removal, systemctl's run)
goes through one object, System; a test hands its own, so no test needs root or Linux, writes under /etc, or
runs systemctl. Nothing runs at import. The standard library only; no network module.

Exit codes: install 0 done (and, started, active and as installed after START_WAIT), 1 the unit written but
systemctl failed, or not as installed (then not started), or not active or not as installed after START_WAIT
(said, left as it is), 2 refused (nothing written); remove 0 done or no unit of the name held by systemd, 1
systemctl or a removal failed, or a unit of the name is still held by systemd with no file (said, nothing
touched); 2 refused (nothing touched); status 0 active as installed, 1 installed and not active, or active not
as installed, 3 not installed (a unit of the name systemd holds is said) or not known, 2 not Linux.
"""
from __future__ import annotations

import os
import posixpath
import re
import shutil
import site
import stat as statmod
import subprocess
import sys
import time

UNIT_NAME = "raqib-watch.service"
UNIT_DIR = "/etc/systemd/system"
UNIT_PATH = "/etc/systemd/system/raqib-watch.service"
STATE_DIR = "/var/lib/raqib"                 # A-5: the service's home, root's alone (StateDirectory, 0700)
RECORD = "/var/lib/raqib/.raqib/host"        # where the watch writes, HOME=/var/lib/raqib
MARK = "# raqib-service/1"                   # the first line of Raqib's unit; a unit without it is not Raqib's
SYSTEMCTLS = ("/usr/bin/systemctl", "/bin/systemctl")   # A-7: by its whole path, never by PATH
SS_PATHS = ("/usr/sbin/ss", "/usr/bin/ss", "/sbin/ss", "/bin/ss")   # AC-4: the watch's ss (raqib.discover's)
SYSTEMCTL_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat",
                 "SYSTEMD_COLORS": "0"}
SYSTEMCTL_TIMEOUT = 120.0                    # seconds; `enable --now` waits for the start
START_WAIT = 3                               # AC-6: seconds waited after the start before systemctl is asked
SAFE_PATH = re.compile(r"/[A-Za-z0-9/._+-]*\Z")   # A-7: refused, never quoted
LINK_DEPTH = 40                              # links followed at most for one path (the kernel's own bound)
WALK_MAX = 200000                            # AC-2: entries walked at most; past it the install refuses
PTH_MAX = 1 << 20                            # bytes of a .pth file read whole; a longer one is refused
PTH_ODD = re.compile(rb"[^\x20-\x7e\t\n\r]")     # AD-4: a .pth byte site's versions read differently: refused
UNIT_MAX = 16384                             # AD-2: bytes of the unit file status reads whole; longer is not ours
ENV_MOVES = ("PYTHONHOME", "PYTHONPLATLIBDIR")   # AD-4: they move the install's library, not the unit's (-I)
HEAD_MAX = 4096                              # bytes of a unit file read to find the mark
TEXT_MAX = 2000                              # characters of systemctl's output kept
SHOW = ("LoadState", "UnitFileState", "ActiveState", "SubState", "Result", "ExecMainStatus", "NRestarts",
        "FragmentPath", "DropInPaths", "NeedDaemonReload")
LOADED = ("LoadState", "ActiveState", "FragmentPath", "DropInPaths", "NeedDaemonReload")   # AD-3: after the reload
GONE = ("inactive", "failed")                # AD-1: ActiveStates of a unit nothing of which runs
RUNNING = ("active", "activating", "reloading", "deactivating", "refreshing")
EXEC = "-I -m raqib watch --host --no-page --no-notify"   # what ExecStart gives the interpreter (E3)
FIX_ROOT = "run it as root (sudo raqib service ...): it asks for no elevation itself"
JOURNAL = "journalctl -u %s" % UNIT_NAME

# E3 (A-3, A-5, A-6, AC-1, AC-5, AC-7): the whole unit, one constant; its one hole is the interpreter's path (%s).
UNIT_TEXT = """# raqib-service/1
# Raqib's watch of this host as a unit of the system's (ADR-0013). Written by `raqib service install`,
# removed by `raqib service remove`. A unit of this name whose first line is not the mark above is not Raqib's.

[Unit]
Description=Raqib: the watch of this host (raqib watch --host)

[Service]
Type=simple
ExecStart=%s -I -m raqib watch --host --no-page --no-notify
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
"""


class Refused(Exception):
    """Exit 2: said, and nothing written or touched."""


def run_systemctl(systemctl, args, timeout=SYSTEMCTL_TIMEOUT):
    """(exit code or None, stdout, stderr) of the system's systemctl, at one of SYSTEMCTLS, with `args` (a list
    of constants): no shell, the environment SYSTEMCTL_ENV and nothing of the caller's, the folder /, stdin
    closed, at most `timeout` seconds (then stopped, and None). The one function that starts a program here
    (ADR-0013 AA-2: `raqib service` takes no process sample)."""
    if systemctl not in SYSTEMCTLS:
        return None, "", "not run: %s is not one of %s" % (systemctl, ", ".join(SYSTEMCTLS))
    try:
        got = subprocess.run([systemctl] + [str(a) for a in args], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(SYSTEMCTL_ENV), cwd="/",
                             timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None, "", ("no answer in %d s (systemctl stopped; what it asked of systemd may still be done)"
                          % timeout)
    except OSError as exc:
        return None, "", "cannot be run (%s)" % type(exc).__name__
    return got.returncode, _text(got.stdout), _text(got.stderr)


def _text(data):
    text = (data or b"").decode("utf-8", "replace").strip()
    text = "".join(c if c.isprintable() or c == "\n" else "?" for c in text)
    return text[:TEXT_MAX]


def _open_flags():
    return (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))


class System:
    """Every call raqib service makes of the system, here alone (a test hands an object of its own)."""

    def platform(self):
        return sys.platform

    def euid(self):
        return os.geteuid()

    def python(self):
        return sys.executable

    def no_site(self):
        """AC-3: True where this interpreter runs without its site (-S)."""
        return bool(sys.flags.no_site)

    def ignores_environment(self):
        """AD-4: True where this interpreter ignores PYTHON* variables (-E, -I)."""
        return bool(sys.flags.ignore_environment)

    def env_set(self, names):
        """AD-4: those of `names` that are set in this process's environment (an empty value counts as set)."""
        return [n for n in names if n in os.environ]

    def site_packages(self):
        """AC-3: this interpreter's own site folders (site.getsitepackages(); none where it cannot say)."""
        try:
            return list(site.getsitepackages())
        except AttributeError:
            return []

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

    def read_head(self, path, limit=HEAD_MAX):
        """The first `limit` bytes of a file: not through a link, never waiting (O_NONBLOCK: a FIFO put there
        holds no reader), and only where fstat says the file opened is a regular one (AC-9)."""
        fd = os.open(path, _open_flags() | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            if not statmod.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise OSError("%s is not a regular file" % path)
            return f.read(limit)

    def read_bytes(self, path, limit):
        """A .pth file's bytes, whole: never waiting, only from a regular file, at most `limit` bytes (a longer
        one raises). Called only once the walk found it, and what it points to, root's alone (AC-2)."""
        fd = os.open(path, _open_flags())
        with os.fdopen(fd, "rb") as f:
            if not statmod.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise OSError("%s is not a regular file" % path)
            data = f.read(limit + 1)
        if len(data) > limit:
            raise OSError("%s is longer than %d bytes: not read whole" % (path, limit))
        return data

    def sleep(self, seconds):
        time.sleep(seconds)

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


# --- E1, E2 (A-3, AB-3, AC-2 to AC-4): the code a unit of the system's runs is the system's ----------------------

def _bad(st):
    """Why a file or folder (not a link) is not root's alone, or None."""
    if st.st_uid != 0:
        return "owned by uid %d, not root" % st.st_uid
    if st.st_mode & statmod.S_IWOTH:
        return "writable by others (mode %04o)" % statmod.S_IMODE(st.st_mode)
    if st.st_mode & statmod.S_IWGRP:
        return "writable by its group (mode %04o)" % statmod.S_IMODE(st.st_mode)
    return None


def _why(exc):
    return "cannot be read (%s)" % type(exc).__name__


def _walk(path, stat, readlink, good, missing_ok=False, links=None):
    """(bad, real, mode) of `path`, walked from / as the system walks it: each folder on the way and the end; a
    link by its owner, then what it points to, whole. bad: (where, why) of the first part that is not root's
    alone, else None; real: where the path ends with no link on it, and mode: its mode (None and None where,
    with missing_ok, a part does not exist: what exists above it was checked). `good` (real path: mode) holds
    what was found root's alone, `links` the links met."""
    if not isinstance(path, str) or not path.startswith("/"):
        return (str(path), "not an absolute path"), None, None
    todo = [c for c in path.split("/") if c]
    done, hops = "/", 0
    if "/" not in good:
        try:
            st = stat("/", follow_symlinks=False)
        except (OSError, ValueError) as exc:
            return ("/", _why(exc)), None, None
        why = _bad(st)
        if why:
            return ("/", why), None, None
        good["/"] = st.st_mode
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
        except (FileNotFoundError, NotADirectoryError) as exc:
            if missing_ok:
                return None, None, None
            return (here, _why(exc) + _on_way(here, path)), None, None
        except (OSError, ValueError) as exc:
            return (here, _why(exc) + _on_way(here, path)), None, None
        if statmod.S_ISLNK(st.st_mode):
            if st.st_uid != 0:
                return (here, "a link owned by uid %d, not root%s" % (st.st_uid, _on_way(here, path))), None, None
            if links is not None:
                links.add(here)
            hops += 1
            if hops > LINK_DEPTH:
                return (here, "more than %d links to follow (a loop of links?)%s" % (
                    LINK_DEPTH, _on_way(here, path))), None, None
            try:
                target = readlink(here)
            except (OSError, ValueError) as exc:
                return (here, "a link that cannot be read (%s)%s" % (type(exc).__name__, _on_way(here, path))), \
                    None, None
            if target.startswith("/"):
                done = "/"
            todo = [c for c in target.split("/") if c] + todo
            continue
        why = _bad(st)
        if why:
            return (here, why + _on_way(here, path)), None, None
        good[here] = st.st_mode
        done = here
    return None, done, good[done]


def _on_way(here, path):
    return "" if here == path else " (on the way to %s)" % path


def owned_by_root(paths, stat=os.stat, readlink=os.readlink):
    """AB-3: (where, why) of the first of `paths` - or of a folder above it, or of a link on its way, or of what
    such a link points to - that is not owned by uid 0 or is writable by its group or by others; None where
    every one is root's alone. Folders are checked from / down, so the highest that is not is the one said."""
    good = {}
    for path in paths:
        bad, _, _ = _walk(path, stat, readlink, good)
        if bad:
            return bad
    return None


class _Walk:
    """AC-2: one walk of the install's paths, each real folder walked once, every path met counted by kind."""

    def __init__(self, system):
        self.system, self.good, self.links, self.dirs, self.walked = system, {}, set(), set(), 0

    def path(self, path, missing_ok=False):
        return _walk(path, self.system.stat, self.system.readlink, self.good, missing_ok, self.links)

    def whole(self, path, missing_ok=True):
        """(where, why) or None: `path` (its folders above, its links) and, where it ends in a folder, every file
        and folder below it, whole; a link below that points to a folder makes that folder walked too."""
        bad, real, mode = self.path(path, missing_ok)
        if bad or real is None or not statmod.S_ISDIR(mode):
            return bad
        todo = [real]
        while todo:
            folder = todo.pop()
            if folder in self.dirs:
                continue
            self.dirs.add(folder)
            try:
                names = self.system.listdir(folder)
            except (OSError, ValueError) as exc:
                return folder, "cannot be listed (%s)" % type(exc).__name__
            for name in names:
                self.walked += 1
                if self.walked > WALK_MAX:
                    return folder, ("more than %d entries to walk (WALK_MAX): a walk that is not whole is not a"
                                    " pass (is the folder the install runs in, or a link to /, on its path?)"
                                    % WALK_MAX)
                bad, real, mode = self.path(posixpath.join(folder, name), missing_ok=True)
                if bad:
                    return bad
                if real is not None and statmod.S_ISDIR(mode) and real not in self.dirs:
                    todo.append(real)
        return None

    def kinds(self):
        modes = list(self.good.values())
        dirs = sum(1 for m in modes if statmod.S_ISDIR(m))
        files = sum(1 for m in modes if statmod.S_ISREG(m))
        return {"folders": dirs, "files": files, "links": len(self.links), "other": len(modes) - dirs - files}


def pth_entries(text, folder):
    """The lines of a .pth file's text that are paths, by site's own rule: not blank, not `#`, not `import`;
    each made whole against the folder the file is in, as site makes it (lexically), existing or not."""
    out = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip() or line.startswith(("import ", "import\t")):
            continue
        out.append(posixpath.normpath(posixpath.join(folder, line.rstrip())))
    return out


def install_check(system, python, systemctl):
    """E1, E2 (A-3, AB-3, AC-2 to AC-4): (bad, counts). bad is (where, why) of the first path that is not
    root's alone, or None; counts says what was checked. Nothing is run; a .pth file is read only once found
    root's alone."""
    walk = _Walk(system)
    counts = {"cfg": 0, "entries": 0, "missing": 0, "pth": 0, "pth_lines": 0, "ss": 0}

    def done(bad):
        return bad, dict(counts, **walk.kinds())
    bad, _, _ = walk.path(python)
    if bad:
        return done(bad)
    for folder in (posixpath.dirname(python), posixpath.dirname(posixpath.dirname(python))):
        cfg = posixpath.join(folder, "pyvenv.cfg")
        if _exists(system, cfg):
            counts["cfg"] += 1
            bad, _, _ = walk.path(cfg)
            if bad:
                return done(bad)
    cwd, entries = None, []
    for entry in system.sys_path():
        if not isinstance(entry, str):
            continue
        if not entry.startswith("/"):
            cwd = cwd or system.getcwd()
            entry = posixpath.join(cwd, entry) if entry else cwd
        entries.append(posixpath.normpath(entry))
    seen = set()
    while entries:
        entry = entries.pop(0)
        if entry in seen:
            continue
        seen.add(entry)
        counts["entries"] += 1
        bad, real, mode = walk.path(entry, missing_ok=True)
        if bad:
            return done(bad)
        if real is None:
            counts["missing"] += 1   # what exists above it was checked; it is not otherwise a refusal
            continue
        bad = walk.whole(entry)
        if bad:
            return done(bad)
        if not statmod.S_ISDIR(mode):
            continue
        for name in [n for n in system.listdir(real) if n.endswith(".pth")]:
            pth = posixpath.join(real, name)
            bad, _, _ = walk.path(pth)   # found root's alone (whole) before it is read
            if bad:
                return done(bad)
            try:
                data = system.read_bytes(pth, PTH_MAX)
            except (OSError, ValueError) as exc:
                return done((pth, "cannot be read whole (%s: %s)" % (type(exc).__name__, exc)))
            odd = PTH_ODD.search(data)
            if odd:   # AD-4: the versions of site split and decode such a file differently: not read into entries
                return done((pth, "a .pth file holding byte 0x%02x at offset %d, outside printable ASCII, tab, LF"
                                  " and CR (the versions of site split and decode such a file differently; it is"
                                  " not read)" % (data[odd.start()], odd.start())))
            counts["pth"] += 1
            lines = pth_entries(data.decode("ascii"), entry)
            counts["pth_lines"] += len(lines)
            entries += lines
    for path in [system.package_dir(), systemctl, UNIT_DIR]:
        bad = walk.whole(path, missing_ok=False) if path != UNIT_DIR else walk.path(path)[0]
        if bad:
            return done(bad)
    for path in SS_PATHS:
        counts["ss"] += 1 if _exists(system, path) else 0
        bad, _, _ = walk.path(path, missing_ok=True)
        if bad:
            return done(bad)
    return done(None)


def _exists(system, path):
    try:
        system.stat(path, follow_symlinks=False)
        return True
    except (OSError, ValueError):
        return False


def checked_words(counts):
    """AC-8: what the install checked, as counts by kind (never a sentence without them)."""
    total = counts["folders"] + counts["files"] + counts["links"] + counts["other"]
    return ("checked %d paths, each owned by root, and each but a link writable by neither its group nor others"
            " (a link is checked by its owner, then what it points to): %d folders, %d files, %d links, %d of"
            " another kind; they are the interpreter, %d pyvenv.cfg, under %d entries of"
            " sys.path every file and folder (%d entries missing: the folders above them), %d *.pth files read"
            " (%d of their lines entries), the raqib package, systemctl, %d ss, the unit's folder, and every"
            " folder above them" % (total, counts["folders"], counts["files"], counts["links"], counts["other"],
                                    counts["cfg"], counts["entries"], counts["missing"], counts["pth"],
                                    counts["pth_lines"], counts["ss"]))


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
    Raqib's; a file is Raqib's only where its first line is the mark). OSError: it cannot be read."""
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


def said_words(code, said, err):
    """AC-9: what a run of systemctl came to, as it was: its own reason where it gave no exit (no answer in N s,
    cannot be run), else its exit and what it said."""
    text = (err or said).replace("\n", " ")[:300]
    if code is None:
        return text or "no answer"
    return "exit %s, said: %s" % (code, text or "nothing")


def _call(system, path, args, out):
    """Run systemctl with args, say what it came to; True where it exited 0."""
    code, said, err = system.systemctl(path, args)
    words = " ".join([path] + list(args))
    if code == 0:
        out.write("  %s: done\n" % words)
        return True
    out.write("  %s: FAILED: %s\n" % (words, said_words(code, said, err)))
    return False


def _show(system, path, props=SHOW, need="ActiveState"):
    """({property: value}, None) by systemctl's show of the unit, or (None, what it came to) where it did not
    exit 0 or did not give `need`."""
    code, said, err = system.systemctl(path, ["show", UNIT_NAME, "--no-pager", "--property=" + ",".join(props)])
    got = {}
    for line in (said or "").splitlines():
        key, _, value = line.partition("=")
        if key in props:
            got[key] = value
    if code != 0 or need not in got:
        return None, said_words(code, said, err) + ("" if code != 0 else " (no %s)" % need)
    return got, None


def _state_words(props):
    return "ActiveState=%s, SubState=%s, Result=%s, ExecMainStatus=%s, NRestarts=%s" % tuple(
        props.get(k) or "?" for k in ("ActiveState", "SubState", "Result", "ExecMainStatus", "NRestarts"))


def _none_known(props):
    """AD-1: True where systemd holds no unit of the name: LoadState not-found, and nothing of it running."""
    return props.get("LoadState") == "not-found" and props.get("ActiveState") in GONE


def _held_words(props):
    return "LoadState=%s, ActiveState=%s, FragmentPath=%s" % (
        props.get("LoadState") or "?", props.get("ActiveState") or "?", props.get("FragmentPath") or "none")


def _not_as_installed(props):
    """AC-9, AD-2: what says systemd's unit is not the file installed: a FragmentPath other than UNIT_PATH, a
    drop-in, a file changed since it was loaded (NeedDaemonReload=yes)."""
    fragment, drops = props.get("FragmentPath") or "", (props.get("DropInPaths") or "").split()
    out = []
    if fragment != UNIT_PATH:
        out.append("NOT AS INSTALLED: systemd's unit is loaded from %s, not %s (systemctl's FragmentPath)" % (
            fragment or "no file", UNIT_PATH))
    if drops:
        out.append("NOT AS INSTALLED: drop-ins change the unit: %s (systemctl's DropInPaths)" % " ".join(drops))
    if props.get("NeedDaemonReload") == "yes":
        out.append("NOT AS INSTALLED: the unit's file changed since systemd loaded it (systemctl's"
                   " NeedDaemonReload=yes)")
    return out


def text_differs(data):
    """AD-2: None where `data` (the unit file's bytes, read whole) is, byte for byte, the text this Raqib writes
    for the interpreter its ExecStart names; else why not."""
    if len(data) > UNIT_MAX:
        return "the unit's file is longer than %d bytes (UNIT_MAX): not the text Raqib writes" % UNIT_MAX
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return "the unit's file holds a byte that is not ASCII: not the text Raqib writes"
    found = re.search(r"^ExecStart=(\S*)", text, re.M)
    python = found.group(1) if found else None
    if python_refused(python):
        return "the unit's file is a different text: its ExecStart names no interpreter of the safe characters"
    if text != UNIT_TEXT % python:
        return ("the unit's file is a different text from the one this Raqib writes for %s (changed after the"
                " install, or not Raqib's)" % python)
    return None


def install(system, out, start=True):
    """E2, E4: refused (Refused, nothing written) or the unit written and, where systemd loaded it as installed
    and with start, enabled, started (over Raqib's own unit: restarted) and asked after START_WAIT whether it is
    active and still as installed."""
    _linux(system, "install")
    _root(system, "install")
    python = system.python()
    why = python_refused(python)
    if why:
        raise Refused("raqib service install: %s" % why)
    if system.no_site():
        raise Refused("raqib service install: refused: this interpreter runs without its site (-S,"
                      " sys.flags.no_site), so what it would walk is not what the unit's interpreter loads (ADR-0013"
                      " AC-3); run it without -S")
    moved = [] if system.ignores_environment() else system.env_set(ENV_MOVES)
    if moved:
        raise Refused("raqib service install: refused: %s is set and this interpreter reads its environment, so"
                      " the library it would walk is not the one the unit's interpreter (-I) loads (ADR-0013"
                      " AD-4); unset it, or run the install with -I or -E" % " and ".join(moved))
    pkg, sites = system.package_dir(), [s for s in system.site_packages() if isinstance(s, str)]
    if posixpath.normpath(posixpath.dirname(pkg)) not in [posixpath.normpath(s) for s in sites]:
        raise Refused("raqib service install: refused: the raqib package it runs from, %s, is not directly in one"
                      " of this interpreter's site folders (%s): install raqib into this interpreter (DIR/bin/pip"
                      " install, as root); a checkout, an editable install or a copy deeper below a site folder"
                      " is not it (ADR-0013 AC-3, AD-4)" % (pkg, ", ".join(sites) or "none"))
    path = _systemctl(system, "install")
    try:
        bad, counts = install_check(system, python, path)
    except (OSError, ValueError) as exc:
        bad, counts = ("(the list of paths)", "cannot be made (%s: %s)" % (type(exc).__name__, exc)), None
    if bad:
        raise Refused("raqib service install: refused: %s is %s. A unit of the system's runs this code as root;"
                      " it must be root's alone (ADR-0013 A-3): install raqib where only root can write, e.g. a"
                      " venv in a folder root makes for it" % bad)
    try:
        kind, why = unit_state(system)
    except OSError as exc:
        kind, why = "other", "%s cannot be read (%s)" % (UNIT_PATH, type(exc).__name__)
    if kind == "other":
        raise Refused("raqib service install: %s; not touched" % why)
    if kind == "none":   # AD-1: the name, not only the path: systemd is asked before a file is written
        held, words = _show(system, path, ("LoadState", "ActiveState", "FragmentPath"), need="LoadState")
        if held is None:
            raise Refused("raqib service install: no %s, and systemd gave no word on a unit of the name"
                          " (systemctl show: %s); nothing written" % (UNIT_PATH, words))
        if not _none_known(held):
            raise Refused("raqib service install: refused: no %s, yet systemd holds a unit of the name (%s): it"
                          " is not Raqib's to replace; nothing written (ADR-0013 AD-1)" % (UNIT_PATH,
                                                                                          _held_words(held)))
    text = unit_text(python)
    try:
        system.write_unit(text)
    except OSError as exc:
        raise Refused("raqib service install: %s cannot be written (%s: %s); nothing written" % (
            UNIT_PATH, type(exc).__name__, exc))
    out.write("raqib service install\n")
    out.write("  %s\n" % checked_words(counts))
    out.write("  %s %s (root, 0644): ExecStart=%s %s\n" % (
        "replaced Raqib's own" if kind == "ours" else "wrote", UNIT_PATH, python, EXEC))
    if not _call(system, path, ["daemon-reload"], out):
        out.write("RESULT: the unit is written; systemctl failed; left as it is\n")
        return 1
    loaded, words = _show(system, path, LOADED, need="LoadState")   # AD-3: before anything is started
    if loaded is None:
        out.write("  systemctl show %s after the reload: %s\nRESULT: the unit is written; how systemd loaded it"
                  " NOT KNOWN, not started\n" % (UNIT_NAME, words))
        return 1
    differ = _not_as_installed(loaded)
    if differ:
        for line in differ:
            out.write("  %s\n" % line)
        out.write("RESULT: the unit is written; NOT AS INSTALLED, not started: %s\n" % "; ".join(
            d.split(": ", 1)[1] for d in differ))
        return 1
    if not start:
        out.write("  --no-start: neither enabled nor started; start it with: systemctl enable --now %s\n" % UNIT_NAME)
        if kind == "ours" and loaded.get("ActiveState") in RUNNING:
            out.write("  a watch is running: it keeps the text it started with until: systemctl restart %s\n"
                      % UNIT_NAME)
        out.write("RESULT: installed, not started\n")
        return 0
    calls = [["enable", UNIT_NAME], ["restart", UNIT_NAME]] if kind == "ours" else [["enable", "--now", UNIT_NAME]]
    for args in calls:
        if not _call(system, path, args, out):
            out.write("RESULT: the unit is written; systemctl failed; left as it is (raqib service status says"
                      " more)\n")
            return 1
    if kind == "ours":
        out.write("  Raqib's own unit was there: it was restarted, so no watch keeps the old text\n")
    system.sleep(START_WAIT)
    props, words = _show(system, path)
    if props is None:
        out.write("  after %d s, systemctl show %s: %s\n" % (START_WAIT, UNIT_NAME, words))
        out.write("RESULT: installed, enabled, its state %d s after its start NOT KNOWN\n" % START_WAIT)
        return 1
    out.write("  after %d s: %s (systemctl show)\n" % (START_WAIT, _state_words(props)))
    out.write("  the record: %s (root's alone); raqib service status says how it runs\n" % RECORD)
    differ = _not_as_installed(props)
    for line in differ:
        out.write("  %s\n" % line)
    active = props["ActiveState"] == "active"
    if active and not differ:
        out.write("RESULT: installed, enabled, active %d s after its start\n" % START_WAIT)
        return 0
    if active:
        out.write("RESULT: installed, enabled, active %d s after its start, NOT AS INSTALLED: %s\n" % (
            START_WAIT, "; ".join(d.split(": ", 1)[1] for d in differ)))
        return 1
    out.write("RESULT: installed, enabled, NOT ACTIVE %d s after its start%s (%s says why)\n" % (
        START_WAIT, ", NOT AS INSTALLED" if differ else "", JOURNAL))
    return 1


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
    """E4, E5: the unit stopped, disabled and removed (only with Raqib's mark), then reloaded, and a failed
    state of it forgotten (AD-5); the record stays and is said; with purge, the record's folder (STATE_DIR, and
    only it) is removed too. No file: systemd is asked whether it holds a unit of the name (AD-1), and if it
    does, nothing is touched."""
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
    path = _systemctl(system, "remove")
    out.write("raqib service remove\n")
    if kind == "ours":
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
        ended, words = _show(system, path, ("ActiveState",))   # AD-5: a stop after a finding reads as failed
        if ended is None:
            out.write("  whether systemd holds a failed state of the removed unit is not known: systemctl show:"
                      " %s\n" % words)
        elif ended["ActiveState"] == "failed":
            out.write("  systemd held the removed unit as failed (the watch's own exit at its stop); asked to"
                      " forget it:\n")
            _call(system, path, ["reset-failed", UNIT_NAME], out)
    else:
        held, words = _show(system, path, ("LoadState", "ActiveState", "FragmentPath"), need="LoadState")
        if held is None:
            out.write("  no %s; whether systemd still has a unit of the name is not known: systemctl show: %s\n"
                      "RESULT: nothing touched, not known\n" % (UNIT_PATH, words))
            return 1
        if not _none_known(held):
            out.write("  no %s, but systemd still has a unit of the name: %s (systemctl status %s says more);"
                      " nothing touched%s\nRESULT: nothing touched, a unit of the name is still held by systemd\n"
                      % (UNIT_PATH, _held_words(held), UNIT_NAME, ", nothing purged" if purge else ""))
            return 1
        out.write("  no unit installed (no %s; systemd: LoadState=not-found, ActiveState=%s): nothing to stop or"
                  " remove\n" % (UNIT_PATH, held["ActiveState"]))
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
    """E5: installed (the file with the mark), enabled and active by systemctl's own words, loaded from that file
    alone, its text the one this Raqib writes, unchanged since it was loaded; no rights needed. Nothing is said
    that was not read (AC-9). No file: systemd is asked whether it holds a unit of the name (AD-1)."""
    _linux(system, "status")
    out.write("raqib service status\n")
    try:
        kind, why = unit_state(system)
        whole = system.read_head(UNIT_PATH, UNIT_MAX + 1) if kind == "ours" else b""
    except OSError as exc:
        out.write("  %s cannot be read (%s): whether Raqib's unit is there is not known\nRESULT: NOT KNOWN\n" % (
            UNIT_PATH, type(exc).__name__))
        return 3
    path = system.systemctl_path()
    if kind != "ours":
        out.write("  not installed: %s\n" % (why or "no %s" % UNIT_PATH))
        if kind == "none":
            held, words = (_show(system, path, ("LoadState", "ActiveState", "FragmentPath"), need="LoadState")
                           if path else (None, "no systemctl at %s" % " or ".join(SYSTEMCTLS)))
            if held is None:
                out.write("  whether systemd holds a unit of the name is not known: %s\nRESULT: NOT INSTALLED BY"
                          " RAQIB, NOT KNOWN WHETHER A UNIT OF THE NAME RUNS\n" % words)
                return 3
            if not _none_known(held):
                out.write("  systemd holds a unit of the name: %s\nRESULT: NOT INSTALLED BY RAQIB, YET A UNIT OF"
                          " THE NAME IS %s\n" % (_held_words(held), "ACTIVE" if held.get("ActiveState") in
                                                 RUNNING else "LOADED"))
                return 3
        out.write("RESULT: NOT INSTALLED\n")
        return 3
    out.write("  installed: %s (it carries %s)\n" % (UNIT_PATH, MARK))
    if not path:
        out.write("  no systemctl at %s: the unit's state is not known\nRESULT: NOT KNOWN\n" % " or ".join(SYSTEMCTLS))
        return 3
    props, words = _show(system, path)
    if props is None:
        out.write("  systemctl show %s gave no state: %s\nRESULT: NOT KNOWN\n" % (UNIT_NAME, words))
        return 3
    active = props["ActiveState"] == "active"
    out.write("  enabled: %s (systemctl's UnitFileState)\n" % (props.get("UnitFileState") or "?"))
    out.write("  active: %s, %s (systemctl's ActiveState, SubState)\n" % (props["ActiveState"] or "?",
                                                                         props.get("SubState") or "?"))
    out.write("  restarts: %s (systemctl's NRestarts; each restart is a gap in the watch)\n" % (
        props.get("NRestarts") or "?"))
    differ = _not_as_installed(props)
    other = text_differs(whole)
    if other:
        differ.append("NOT AS INSTALLED: %s" % other)
    for line in differ:
        out.write("  %s\n" % line)
    as_installed = not differ
    if props.get("ExecMainStatus") == "1":
        out.write("  exit status 1: the watch's own ALARM at its end, or an error; the journal says which (%s)\n"
                  % JOURNAL)
    out.write("  the record: %s (root's alone)\n" % RECORD)
    if active and as_installed:
        out.write("  ACTIVE says the unit runs, not that the watch writes its record\n")
        out.write("RESULT: ACTIVE\n")
        return 0
    if active:
        out.write("RESULT: ACTIVE, NOT AS INSTALLED\n")
        return 1
    out.write("  last result: %s, exit status %s (systemctl's Result, ExecMainStatus)\n" % (
        props.get("Result") or "?", props.get("ExecMainStatus") or "?"))
    out.write("RESULT: INSTALLED, NOT ACTIVE%s\n" % ("" if as_installed else ", NOT AS INSTALLED"))
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
