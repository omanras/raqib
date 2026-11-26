"""The record of the programs this process started (ADR-0007 BH-1).

The watch knows its own by what it did, not by where a process stands: every
program Raqib starts - the channel's reader (wevtutil), the notifier - is
recorded here when it starts, by its pid, the time and its image (the
basename of the launcher's args[0]; ADR-0007 BI-2), in the statement that
starts it (`proc = own.started(subprocess.Popen(...))`), so that nothing is
started without the record. The live readers (raqib/hostwin.py's process
sample, discover.snapshot_proc) are handed the record and write the recorded
pids alive in their sample beside the reader's own pid (BH-2) - a pid is
alive only where the sample's image for it is the recorded image, so a pid
taken again by a process of another image is not the watch's; discover takes
those, proven by their dates, for the watch's own tree (BH-3).

Pure: the standard library only, no network, no process started or touched
here. ADR-0007 CI-1 (M17.2b): handed() gives the environment for a program this
process starts with its own environment - without what a packer added to it.
CI-3: library_folder(), called once by Raqib's entry, puts back on Windows the
folder a packed program set as the one searched first for a library; its
result is kept here, and a failure is said by the host watch (library_folder_hole).
Thread-safe (the watch starts helpers from several threads) and bounded:
a pid is forgotten once a sample shows it ended, and past KEPT_MAX records the
oldest is forgotten. The record lives in this process's memory only: a watch
started again does not know the helpers of the one before.
"""
from __future__ import annotations

import os
import sys
import threading
import time

KEPT_MAX = 256          # records kept at most; past it the oldest is forgotten (bounded)
STARTED_BEFORE = 60.0   # seconds a helper's start, as the OS gives it, may be before its record (Popen's own time)
STARTED_AFTER = 2.0     # seconds it may be after: one clock read against another (discover.GUID_SAME_SECONDS)


DELETED = " (deleted)"   # what the kernel adds to the exe link of a program whose file was replaced or removed


def _base(name):
    """The lower-case basename of an image path (either separator), or None
    where there is no usable name. The one shape a record's image and a
    sample's image are compared in (ADR-0007 BI-2). An image that ends with
    " (deleted)" is the image it was (BY-6: an interpreter replaced on disk
    while the helper runs is still the helper's)."""
    if not isinstance(name, str):
        return None
    if name.endswith(DELETED):
        name = name[:-len(DELETED)]
    name = name.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    return name or None


def _arg0(args):
    """The first element of a Popen's args (a list or tuple), or the first
    word of a string arg, or None where it gives no usable name."""
    if isinstance(args, (list, tuple)):
        return args[0] if args else None
    if isinstance(args, str):
        parts = args.split()
        return parts[0] if parts else None
    return None


class Record:
    """pid -> (the time, seconds since the epoch by `clock`, its start was
    recorded; the image of what was started, _base of the launcher's args[0],
    or None where none was read), in the order of the starts."""

    def __init__(self, kept_max=KEPT_MAX, clock=time.time):
        self._lock = threading.Lock()
        self._kept = {}
        self.kept_max = kept_max
        self.clock = clock

    def started(self, proc):
        """proc (the object that just started a program: subprocess.Popen),
        recorded by its pid, the time and its image (proc.args[0]'s basename;
        ADR-0007 BI-2), and returned as it is."""
        pid = getattr(proc, "pid", None)
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
            self.add(pid, image=_arg0(getattr(proc, "args", None)))
        return proc

    def add(self, pid, at=None, image=None):
        with self._lock:
            self._kept.pop(pid, None)
            self._kept[pid] = (self.clock() if at is None else at, _base(image))
            while len(self._kept) > self.kept_max:
                del self._kept[next(iter(self._kept))]

    def kept(self):
        """{pid: (time recorded, image)} (a copy)."""
        with self._lock:
            return dict(self._kept)

    def alive(self, starts, images, since=None):
        """The recorded pids alive in one sample, sorted. starts: {pid: its
        start in seconds since the epoch, or None where it was not read} of
        every process the sample lists. images: {pid: the image the sample
        reads for it} of the same pids. A recorded pid is the watch's own
        only where the sample holds it, its start is not read or inside the
        record's window (STARTED_BEFORE before, STARTED_AFTER after), AND the
        sample's image for it is the recorded image (ADR-0007 BI-2: a pid
        taken again by a process of another image is not the watch's). A
        record with no image of its own falls back to the pid and time alone;
        a pid the sample holds whose image it could not read is not proven
        this sample and is not forgotten (it may be transient). since: when
        the sample began (this record's clock), or None where the sample may
        not list every process (a cap, an error): a pid recorded before it
        that the sample does not hold, or holds as another process, ended -
        it is forgotten."""
        out = []
        with self._lock:
            for pid, (at, image) in list(self._kept.items()):
                present = pid in starts and (starts[pid] is None
                                             or at - STARTED_BEFORE <= starts[pid] <= at + STARTED_AFTER)
                if present and (image is None or _base(images.get(pid)) == image):
                    out.append(pid)
                elif present and image is not None and images.get(pid) is None:
                    pass   # held, its image not read: not proven this sample, not forgotten
                elif since is not None and at < since:
                    del self._kept[pid]
        return sorted(out)


RECORD = Record()     # this process's record: every program Raqib starts is in it


def started(proc):
    """RECORD.started: the one call every program start of Raqib goes through."""
    return RECORD.started(proc)


# --- ADR-0007 CI-1 (M17.2b): what this process hands to the programs it starts ----------------------------------
PACKER_PREFIX = "_PYI_"            # every name of the packer's (PyInstaller) that a packed start adds or reads
PACKER_NAMES = ("_MEIPASS2",)      # the packer's older name, read by no start measured (CI) and never handed on
LOADER_PATH = "LD_LIBRARY_PATH"    # Linux: a packed start puts its own folder first in it ...
LOADER_PATH_ORIG = "LD_LIBRARY_PATH_ORIG"   # ... and keeps here the value it was handed (none: not set)


def _frozen(frozen):
    return bool(getattr(sys, "frozen", False)) if frozen is None else bool(frozen)


def handed(environ=None, frozen=None, platform=None):
    """CI-1: the environment for a program this process starts with its own environment, a new dict. environ:
    the environment (default os.environ); frozen: whether this process is a packed program (default sys.frozen);
    platform: default sys.platform. Not packed: a copy of environ, value for value. Packed: that copy without
    every name that begins PACKER_PREFIX and without PACKER_NAMES (on Windows, whatever their case: the system
    takes a name in any case), and on Linux with LD_LIBRARY_PATH put back to LD_LIBRARY_PATH_ORIG's value and
    LD_LIBRARY_PATH_ORIG removed - LD_LIBRARY_PATH removed where there is no LD_LIBRARY_PATH_ORIG (the packed
    start set it, and nothing was handed). Every other name stays as handed (macOS's DYLD_ names among them:
    the packer adds none, CI). Pure: it starts nothing, and never changes environ or os.environ."""
    out = dict(os.environ if environ is None else environ)
    if not _frozen(frozen):
        return out
    platform = sys.platform if platform is None else platform
    windows = platform == "win32"
    for name in list(out):
        key = name.upper() if windows and isinstance(name, str) else name
        if isinstance(key, str) and (key.startswith(PACKER_PREFIX) or key in PACKER_NAMES):
            del out[name]
    if isinstance(platform, str) and platform.startswith("linux"):
        if LOADER_PATH_ORIG in out:
            out[LOADER_PATH] = out.pop(LOADER_PATH_ORIG)
        else:
            out.pop(LOADER_PATH, None)
    return out


# --- ADR-0007 CI-3 (M17.2b): Windows: the folder a packed program set as searched first, put back ------------------
LIBRARY_FOLDER = None   # the call's result in this process: None not called; True put back; else why not (words)
LIBRARY_WHY_MAX = 200   # characters of a failure's own words kept (ASCII, one line)
LIBRARY_HOLE = ("what the watch starts searches the packed program's folder first for its libraries: that folder"
                " could not be put back at the start (%s; ADR-0007 CI-3)")


def _words(text):
    text = "".join(c if " " <= c <= "~" else " " for c in str(text))
    return " ".join(text.split())[:LIBRARY_WHY_MAX] or "no words given"


def library_folder(call, frozen=None, platform=None):
    """CI-3: where this process is a packed program (frozen; default sys.frozen) and the system is Windows
    (platform; default sys.platform), call(None) - the entry gives the system's SetDllDirectoryW (raqib/cli.py
    main; this module imports no ctypes), a test a stand-in: the folder the system
    searches first for a library goes back to the system's own, so what this process starts after it loads the
    system's libraries, not the packed copies - once in this process, and keep its result in LIBRARY_FOLDER.
    Returns None where no call is made (not packed; Linux, macOS or another system; made already), True where
    the call returned a true value, else why not, in words (a false value, or what it raised). It never raises:
    a failure is a result, said by the host watch as a hole of its own (library_folder_hole), never fatal."""
    global LIBRARY_FOLDER
    try:
        if LIBRARY_FOLDER is not None or not _frozen(frozen) or (sys.platform if platform is None
                                                                  else platform) != "win32":
            return None
        try:
            got = call(None)
        except Exception as exc:
            result = "SetDllDirectoryW(NULL) failed: %s" % _words("%s: %s" % (type(exc).__name__, exc))
        else:
            result = True if got else "SetDllDirectoryW(NULL) returned %s" % _words(repr(got))
    except Exception as exc:   # a frozen or platform value that cannot be read is a result too
        result = "SetDllDirectoryW(NULL) was not called: %s" % _words("%s: %s" % (type(exc).__name__, exc))
    LIBRARY_FOLDER = result
    return result


def library_folder_hole():
    """CI-3: the words of the host watch's hole of its own where library_folder() failed in this process, else
    None (not called, or put back)."""
    result = LIBRARY_FOLDER
    if result is None or result is True:
        return None
    return LIBRARY_HOLE % _words(result)
