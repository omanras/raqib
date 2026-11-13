"""The record of the programs this process started (ADR-0007 BH-1).

The watch knows its own by what it did, not by where a process stands: every
program Raqib starts - the channel's reader (wevtutil), the notifier - is
recorded here when it starts, by its pid and the time, in the statement that
starts it (`proc = own.started(subprocess.Popen(...))`), so that nothing is
started without the record. The live readers (raqib/hostwin.py's process
sample, discover.snapshot_proc) are handed the record and write the recorded
pids alive in their sample beside the reader's own pid (BH-2); discover takes
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


class Record:
    """pid -> the time (seconds since the epoch, `clock`) its start was
    recorded, in the order of the starts."""

    def __init__(self, kept_max=KEPT_MAX, clock=time.time):
        self._lock = threading.Lock()
        self._kept = {}
        self.kept_max = kept_max
        self.clock = clock

    def started(self, proc):
        """proc (the object that just started a program: subprocess.Popen),
        recorded by its pid and the time, and returned as it is."""
        pid = getattr(proc, "pid", None)
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
            self.add(pid)
        return proc

    def add(self, pid, at=None):
        with self._lock:
            self._kept.pop(pid, None)
            self._kept[pid] = self.clock() if at is None else at
            while len(self._kept) > self.kept_max:
                del self._kept[next(iter(self._kept))]

    def kept(self):
        """{pid: time recorded} (a copy)."""
        with self._lock:
            return dict(self._kept)

    def alive(self, starts, since=None):
        """The recorded pids alive in one sample, sorted. starts: {pid: its
        start in seconds since the epoch, or None where it was not read} of
        every process the sample lists. A pid the sample holds with a start
        read outside its record's window (STARTED_BEFORE before it,
        STARTED_AFTER after it) is another process (the pid taken again):
        not given. since: when the sample began (this record's clock), or
        None where the sample may not list every process (a cap, an error):
        a pid recorded before it that the sample does not hold, or holds as
        another process, ended - it is forgotten."""
        out = []
        with self._lock:
            for pid, at in list(self._kept.items()):
                if pid in starts and (starts[pid] is None
                                      or at - STARTED_BEFORE <= starts[pid] <= at + STARTED_AFTER):
                    out.append(pid)
                elif since is not None and at < since:
                    del self._kept[pid]
        return sorted(out)


RECORD = Record()     # this process's record: every program Raqib starts is in it


def started(proc):
    """RECORD.started: the one call every program start of Raqib goes through."""
    return RECORD.started(proc)
