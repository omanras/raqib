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
here. Thread-safe (the watch starts helpers from several threads) and bounded:
a pid is forgotten once a sample shows it ended, and past KEPT_MAX records the
oldest is forgotten. The record lives in this process's memory only: a watch
started again does not know the helpers of the one before.
"""
from __future__ import annotations

import threading
import time

KEPT_MAX = 256          # records kept at most; past it the oldest is forgotten (bounded)
STARTED_BEFORE = 60.0   # seconds a helper's start, as the OS gives it, may be before its record (Popen's own time)
STARTED_AFTER = 2.0     # seconds it may be after: one clock read against another (discover.GUID_SAME_SECONDS)


def _base(name):
    """The lower-case basename of an image path (either separator), or None
    where there is no usable name. The one shape a record's image and a
    sample's image are compared in (ADR-0007 BI-2)."""
    if not isinstance(name, str):
        return None
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
