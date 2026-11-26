"""M14.1a and its REDO (ADR-0007 Amendments BQ and BR): the reader of Linux's process events alone,
raqib/procevents.py. The system is a fake here (System): the socket's maker, the reads of /proc and the
clocks are its; the datagrams it hands the reader are laid out here by hand, as the Table measured them on kernels
6.8 and 7.0 (nlmsghdr =IHHII, cn_msg =IIIIHH, the event's header =IIQ, its data at 16), and not taken from the
module's structures, so the module's layouts are checked against a statement of them made apart. One test opens a
real netlink socket and hears children of its own; it is skipped off Linux and where the kernel refuses. Pids,
paths and times are made up. An error is named as the system names it (errno.errorcode), never by another
system's name (BR-8)."""
import ast
import atexit
import builtins
import datetime
import errno
import itertools
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import procevents  # noqa: E402

SOURCE = (ROOT / "raqib" / "procevents.py").read_text(encoding="ascii")
PID = 4242
WALL = datetime.datetime(2026, 11, 20, 10, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
MONO = 5_000_000_000_000           # the monotonic clock at a datagram's receipt, in ns
TS = MONO - 250_000_000            # an event stamped 0.25 s before its receipt
FORK, EXEC, EXIT, COMM, SID, UID, GID = 0x1, 0x2, 0x80000000, 0x200, 0x80, 0x4, 0x40
MARK_BYTES = b"\x11\x22\x33\x44"   # the made-up random mark of the ask
MARK = 0x44332211
BOOT_OFF = 7_000_000_000           # the boot clock is ahead of the monotonic one by 7 s (time asleep)
HZ = 100


def name(code):
    """An error's name as this system names it, the way the module takes it (BR-8)."""
    return errno.errorcode[code]


def text_of(seconds):
    return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- the messages, by hand ------------------------------------------------------------------------------------
SEQS = {}                          # cpu -> the kernel's count of events on it, as the made-up kernel keeps it


def message(what, data, ts=TS, cpu=1, idx=1, val=1, seq=None, ack=0, nltype=3, cut=None, size=None):
    """One netlink message of the connector: nlmsghdr (16), cn_msg (20: its seq the kernel's count of events on the
    event's CPU, one more for each message made here unless a test names it), the event (what, cpu, time; its
    data), padded to 4 bytes. The kernel's union is 24 bytes, so every event of the measured kernels is 40."""
    if seq is None:
        SEQS[cpu] = seq = SEQS.get(cpu, 1000) + 1
    ev = struct.pack("=IIQ", what, cpu, ts) + data
    if cut is not None:
        ev = ev[:cut]
    cn = struct.pack("=IIIIHH", idx, val, seq, ack, len(ev) if size is None else size, 0) + ev
    out = struct.pack("=IHHII", 16 + len(cn), nltype, 0, seq, 0) + cn
    return out + b"\0" * (-len(out) % 4)


def fork(ppid, pid, ptgid=None, tgid=None, **kw):
    return message(FORK, struct.pack("=IIII", ppid, ppid if ptgid is None else ptgid, pid,
                                     pid if tgid is None else tgid) + bytes(8), **kw)


def exec_(pid, tgid=None, **kw):
    return message(EXEC, struct.pack("=II", pid, pid if tgid is None else tgid) + bytes(16), **kw)


def exit_(pid, code=0, tgid=None, parent_signal=17, **kw):
    """code: the kernel's exit_code (the wait status); parent_signal: its exit_signal (SIGCHLD)."""
    return message(EXIT, struct.pack("=IIIIII", pid, pid if tgid is None else tgid, code, parent_signal, 1, 1), **kw)


ANSWER_SEQ = itertools.count(15821)


def answer(err=0, ack=MARK + 1, seq=None, cpu=7):
    """The kernel's answer as measured (BT): it carries a real CPU and that CPU's next number of the count. The
    stand-in's answers are on a CPU of their own, each with the next number, unless a test says otherwise."""
    return message(0, struct.pack("=I", err) + bytes(20), ack=ack, seq=next(ANSWER_SEQ) if seq is None else seq,
                   cpu=cpu)


def asked(op, pid=PID):
    """The ask as measured: nlmsghdr (40, type 3, flags 0, seq 0, the pid), cn_msg (idx 1, val 1, seq 0, ack: the
    reader's random mark; len 4, flags 0), the u32 op (1 listen, 2 ignore)."""
    return struct.pack("=IHHII", 40, 3, 0, 0, pid) + struct.pack("=IIIIHH", 1, 1, 0, MARK, 4, 0) + \
        struct.pack("=I", op)


NAME = "a) (b"   # M14.1d (CC-2): the name the fake's stat gives every process (one that holds ") (" too)


def stat_line(pid, ppid, ticks, comm=NAME):
    """/proc/PID/stat as Linux writes it (a name that holds ") (" too); starttime is the 22nd field."""
    rest = "S %d 1 1 0 -1 4194304 1 0 0 0 0 0 0 0 20 0 1 0 %d 1000 100 18446744073709551615" % (ppid, ticks)
    return ("%d (%s) %s\n" % (pid, comm, rest)).encode("ascii")


# --- the fake system --------------------------------------------------------------------------------------------
class Sock:
    def __init__(self, system):
        self.system, self.inbox, self.sent, self.bound, self.timeout, self.opts, self.closed = system, [], [], None, \
            None, [], False

    def _fail(self, step):
        if step in self.system.fail:
            raise self.system.fail[step]

    def setsockopt(self, level, name, value):
        self._fail("setsockopt")
        self.opts.append((level, name, value))

    def getsockopt(self, level, name):
        return self.system.rcvbuf if self.system.rcvbuf is not None else self.opts[-1][2] * 2   # Linux doubles it

    def bind(self, address):
        self._fail("bind")
        self.bound = address

    def settimeout(self, value):
        self.timeout = value

    def send(self, data):
        self._fail("send" if not self.sent else "send again")
        self.sent.append(bytes(data))
        op = struct.unpack_from("=I", data, 36)[0]
        if op == 1 and self.system.answer is not None:     # the kernel answers the ask: its ack plus 1
            nonce = struct.unpack_from("=IIIIHH", data, 16)[3]
            self.inbox.extend(self.system.before + [answer(self.system.answer, ack=nonce + 1)])
        elif op == 1:
            self.inbox.extend(self.system.before)
        return len(data)

    def recv(self, size):
        if self.inbox:
            item = self.inbox.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        if self.system.wait:
            time.sleep(0.005)
        raise socket.timeout("timed out")

    def close(self):
        self._fail("close")
        self.closed = True


class System:
    def __init__(self, answer=0):
        self.answer = answer             # the errno the kernel answers the ask with; None: no answer
        self.before = []                 # datagrams that come before the answer
        self.made, self.socks, self.fail, self.asked = [], [], {}, []
        self.links, self.stats = {}, {}  # pid -> the text (or the exception) of its exe link / its stat
        self.wait = False                # recv sleeps a little when there is nothing (a real thread's loop)
        self.rcvbuf = None               # what the system kept of the receive queue (None: what was asked, doubled)

    def socket(self, family, type_, proto):
        self.made.append((family, type_, proto))
        if "socket" in self.fail:
            raise self.fail["socket"]
        self.socks.append(Sock(self))
        return self.socks[-1]

    def _get(self, table, path):
        self.asked.append(path)
        got = table.get(int(path.split("/")[2]), FileNotFoundError(errno.ENOENT, "No such file or directory"))
        if isinstance(got, BaseException):
            raise got
        return got

    def readlink(self, path):
        return self._get(self.links, path)

    def read_bytes(self, path):
        return self._get(self.stats, path)

    def proc(self, pid, exe, ppid, ticks):
        self.links[pid], self.stats[pid] = exe, stat_line(pid, ppid, ticks)


class Clock:
    def __init__(self, step=1_000_000):
        self.now, self.step = MONO, step

    wall_s = WALL

    def wall(self):
        return self.wall_s

    def mono(self):
        self.now += self.step
        return self.now - self.step

    def boot(self):
        return self.now + BOOT_OFF


class NoThread:
    """A thread class that starts nothing: a test pumps the reader with _once()."""
    made = []

    def __init__(self, target=None, name=None, daemon=None):
        self.target, self.name, self.daemon, self.started = target, name, daemon, False
        NoThread.made.append(self)

    def start(self):
        self.started = True

    def join(self, timeout=None):
        pass

    def is_alive(self):
        return False


class Registry:
    def __init__(self):
        self.registered = []

    def register(self, fn):
        self.registered.append(fn)

    def unregister(self, fn):
        self.registered = [f for f in self.registered if f != fn]


def reader(system, clock=None, thread=NoThread, platform="linux"):
    clock = clock or Clock()
    return procevents.Reader(pid=PID, sockets=system.socket, readlink=system.readlink, read_bytes=system.read_bytes,
                             clock=clock.wall, mono=clock.mono, thread=thread, at_exit=Registry(), platform=platform,
                             boot=clock.boot, urandom=lambda n: MARK_BYTES[:n], ticks_per_second=HZ)


def started(system, clock=None):
    clock = clock or Clock()
    r = reader(system, clock)
    assert r.start() is None
    clock.step, clock.now = 0, MONO            # from here the receipt of every datagram is at MONO
    return r


def feed(r, *datagrams):
    sock = r._sock
    sock.inbox.extend(datagrams)
    while sock.inbox:
        assert r._once() is True


# --- the messages, as measured -------------------------------------------------------------------------------------
def test_e1_the_socket_the_bind_and_the_ask_as_measured_and_the_stop_asks_to_ignore():
    system = System()
    r = started(system)
    sock = system.socks[0]
    assert system.made == [(16, socket.SOCK_DGRAM, 11)] and procevents.AF_NETLINK == 16
    assert sock.bound == (PID, 1) and sock.sent == [asked(1)] and len(asked(1)) == 40
    assert sock.timeout == procevents.POLL_SECONDS and NoThread.made[-1].started and NoThread.made[-1].daemon
    assert r.stop() == [] and sock.sent == [asked(1), asked(2)] and sock.closed and r._sock is None


def test_e1_fork_exec_and_exit_in_one_datagram_each_padded_to_four_bytes():
    system = System()
    system.proc(5001, "/usr/bin/curl", 4000, 123456)
    r = started(system)
    born = fork(4000, 5001)                 # made in the kernel's order: its count of events is in that order
    odd = message(COMM, struct.pack("=II", 5001, 5001) + b"curl\0\0\0\0\0\0\0\0\0\0\0\0\0")   # 77: padded to 80
    assert len(odd) % 4 == 0 and struct.unpack_from("=I", odd, 0)[0] == 77
    feed(r, born + odd + exec_(5001) + exit_(5001, code=7 << 8))
    got = r.read()
    assert got == {"processes": [{"pid": 5001, "ppid": 4000, "exe": "/usr/bin/curl", "name": NAME, "earlier": [],
                                  "dropped": 0,
                                  "started_ticks": 123456, "began": text_of(WALL - 0.25),
                                  "ended": text_of(WALL - 0.25), "code": 7, "signal": None, "unread": {}}],
                   "ends": [], "older": []}
    c = r.counts()
    assert c["events"] == {"fork": 1, "exec": 1, "exit": 1} and c["unread"] == {"comm": 1} and c["given"] == 1
    assert procevents.parse(fork(1, 2, seq=33, cpu=2))[0] == ("fork", TS, (1, 1, 2, 2), 2, 33)
    assert procevents.parse(exit_(9, code=9, seq=34, cpu=2))[0] == ("exit", TS, (9, 9, 9, 17), 2, 34)


def test_e1_shorter_than_its_shape_or_of_another_what_is_unread_by_its_kind_never_guessed():
    system = System()
    r = started(system)
    head = struct.pack("=IHHII", 64, 3, 0, 0, 0)
    feed(r, message(COMM, bytes(24)), message(SID, bytes(24)), message(UID, bytes(24)), message(GID, bytes(24)),
         message(0x1234, bytes(24)), fork(1, 2, cut=28), exec_(3, cut=20), exit_(4, cut=24),
         message(FORK, bytes(24), cut=12), message(EXEC, bytes(24), size=60),
         message(FORK, bytes(24), nltype=2), message(FORK, bytes(24), idx=5, val=1),
         struct.pack("=IHHII", 30, 3, 0, 0, 0) + struct.pack("=IIIIHH", 1, 1, 0, 0, 0, 0)[:12] + bytes(2),
         head + bytes(10), bytes(8), b"", answer(0, ack=1))
    assert r.read()["processes"] == [] and system.asked == []
    assert r.counts()["unread"] == {
        "comm": 1, "sid": 1, "uid": 1, "gid": 1, "what 0x1234": 1, "fork shorter than its shape": 1,
        "exec shorter than its shape": 1, "exit shorter than its shape": 1, "an event shorter than its header": 1,
        "a connector length longer than its message": 1,
        "a netlink message of type 2": 1, "a message of another connector (5, 1)": 1,
        "a connector message shorter than its header": 1,
        "a netlink message whose length is not in its datagram": 1,
        "a datagram's tail shorter than a netlink header": 1, "an empty datagram": 1,
        "an answer to another listener's ask": 1}
    assert r.counts()["events"] == {"fork": 0, "exec": 0, "exit": 0}


# --- E1 (BR-1): a process ends with its last thread ----------------------------------------------------------------
def test_e1_br1_a_thread_that_is_not_the_leader_execs_as_measured_one_process_its_real_end():
    """The measured order (a): fork(P -> C/C), exec(C/C), fork(C/C -> T/C), exit(C/C, 0, 17), exec(C/C),
    exit(C/C, the real code)."""
    system = System()
    system.proc(5001, "/usr/bin/python3", 4000, 50)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), fork(5001, 5002, tgid=5001), exit_(5001, code=0))
    first = r.read()["processes"]
    assert [(p["pid"], p["ended"], p["code"]) for p in first] == [(5001, None, None)]   # the leader's end only
    system.links[5001] = "/usr/bin/curl"
    feed(r, exec_(5001), exit_(5001, code=6 << 8))
    got = r.read()
    assert [(p["pid"], p["exe"], p["earlier"], p["code"], p["started_ticks"], p["unread"]) for p in got["processes"]] \
        == [(5001, "/usr/bin/curl", [{"exe": "/usr/bin/python3", "name": NAME, "unread": {}}], 6, 50, {})]
    assert got["ends"] == [] and got["older"] == [] and r.counts()["older"] == 0 and r.counts()["live"] == 0
    assert r.counts()["threads"] == 1


def test_e1_br1_the_leader_ends_first_and_the_process_ends_with_its_last_threads_code():
    """The measured order (b): fork(P -> C/C), exec(C/C), fork(C/C -> T/C), exit(C/C, 0), exit(T/C, 1792 = 7<<8)."""
    system = System()
    system.proc(5001, "/usr/bin/node", 4000, 50)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), fork(5001, 5002, tgid=5001), exit_(5001, code=0, ts=TS - 1000))
    assert r.counts()["live"] == 1
    feed(r, exit_(5002, tgid=5001, code=1792))
    p = r.read()["processes"][0]
    assert (p["exe"], p["ended"], p["code"], p["signal"]) == ("/usr/bin/node", text_of(WALL - 0.25), 7, None)
    assert r.counts()["live"] == 0 and r.counts()["threads"] == 2 and r.counts()["older"] == 0


def test_e1_br1_an_exec_after_an_exit_with_no_fork_between_is_the_same_process_never_no_fork_heard():
    system = System()
    system.proc(5001, "/usr/bin/sh", 4000, 50)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), exit_(5001))       # its thread's fork was not heard
    assert r.read()["processes"][0]["ended"] is not None
    system.links[5001] = "/usr/bin/wget"
    feed(r, exec_(5001))
    p = r.read()["processes"][0]
    assert (p["pid"], p["exe"], p["ended"], p["ppid"], p["started_ticks"]) == (5001, "/usr/bin/wget", None, 4000, 50)
    assert "began" not in p["unread"] and p["earlier"] == [{"exe": "/usr/bin/sh", "name": NAME, "unread": {}}]
    feed(r, fork(4000, 5001))                                # a fork between: a new process; the old one's end lost
    system.proc(5001, "/usr/bin/cp", 4100, 70)
    feed(r, exec_(5001))
    got = r.read()
    assert [(p["exe"], p["ppid"], p["earlier"]) for p in got["processes"]] == [("/usr/bin/cp", 4000, [])]
    assert [(e["pid"], e["started_ticks"], e["unread"]) for e in got["ends"]] == [
        (5001, 50, {"ended": procevents.NO_END})]


def test_e1_br1_threads_are_counted_apart_and_a_thread_is_not_a_process():
    system = System()
    r = started(system)
    feed(r, fork(4000, 5002, tgid=4000), exec_(5003, tgid=5001), exit_(5002, tgid=4000))
    assert r.read() == {"processes": [], "ends": [], "older": []} and system.asked == []
    c = r.counts()
    assert c["threads"] == 3 and c["events"] == {"fork": 1, "exec": 1, "exit": 1} and c["live"] == 0
    feed(r, fork(4001, 5004, ptgid=4000))                    # made by a thread of 4000: its parent is 4000
    assert r.read()["processes"][0]["ppid"] == 4000


def test_e1_br1_where_lost_is_not_0_a_record_says_its_count_of_threads_is_not_known():
    system = System()
    system.proc(5001, "/usr/bin/git", 4000, 9)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    assert "threads" not in r.read()["processes"][0]["unread"]
    feed(r, OSError(errno.ENOBUFS, "No buffer space available"), fork(4000, 5005))
    p = r.read()["processes"][0]
    loss = "ENOBUFS 1 time(s), at least 0 event(s) by the kernel's count"
    assert p["unread"]["threads"] == procevents.LOST_THREADS % loss and "count of threads is not known" in \
        p["unread"]["threads"]
    assert p["unread"]["exe"] == procevents.LOST_EXEC % loss and "made it" not in p["unread"]["exe"]


# --- E2 (BR-2): every program a process had --------------------------------------------------------------------
def test_e2_br2_two_execs_within_one_read_keep_the_first_program_in_earlier():
    system = System()
    system.proc(5001, "/usr/bin/dash", 4000, 8)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    system.links[5001] = "/usr/bin/curl"
    feed(r, exec_(5001))
    got = r.read()["processes"]
    assert [(p["exe"], p["earlier"]) for p in got] == [("/usr/bin/curl", [{"exe": "/usr/bin/dash", "name": NAME, "unread": {}}])]
    assert r.counts()["events"]["exec"] == 2 and r.counts()["given"] == 1


def test_e2_br2_a_second_exec_whose_reads_fail_never_replaces_what_the_first_read_gave():
    system = System()
    system.proc(5001, "/usr/bin/dash", 4000, 8)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    system.links[5001] = FileNotFoundError(errno.ENOENT, "gone")
    system.stats[5001] = PermissionError(errno.EACCES, "no")
    feed(r, exec_(5001))
    p = r.read()["processes"][0]
    assert p["exe"] is None and p["earlier"] == [{"exe": "/usr/bin/dash", "name": NAME, "unread": {}}]
    assert (p["ppid"], p["started_ticks"]) == (4000, 8)       # what the first read gave stands
    assert p["unread"]["exe"].startswith("not read at its exec (%s" % name(errno.ENOENT))
    assert p["unread"]["stat"].startswith("not read at its exec (%s" % name(errno.EACCES))


def test_e2_br2_a_second_exec_after_a_read_is_given_again_with_its_earlier():
    system = System()
    system.proc(5001, "/usr/bin/dash", 4000, 8)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    first = r.read()["processes"][0]
    assert first["earlier"] == []
    system.links[5001] = "/usr/bin/git"
    feed(r, exec_(5001), exit_(5001))
    again = r.read()
    assert [(p["pid"], p["exe"], p["earlier"], p["code"], p["began"]) for p in again["processes"]] == [
        (5001, "/usr/bin/git", [{"exe": "/usr/bin/dash", "name": NAME, "unread": {}}], 0, first["began"])]
    assert again["ends"] == [] and r.counts()["given"] == 2


# --- E3 (BR-3): the pid's holder -----------------------------------------------------------------------------------
@pytest.mark.parametrize("ticks, reused", [(500774, False), (500776, True)])
def test_e3_br3_a_start_later_than_the_exec_by_more_than_a_second_is_another_process(ticks, reused):
    """The exec at TS on the monotonic clock is (TS + BOOT_OFF) / 1e9 = 5006.75 s on the boot clock; stat's start at
    100 ticks a second: 500774 is 5007.74 s (inside the second), 500776 is 5007.76 s (past it)."""
    system = System()
    system.proc(5001, "/usr/bin/touch", 4000, ticks)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    p = r.read()["processes"][0]
    if reused:
        assert p["exe"] is None and p["started_ticks"] is None and p["ppid"] == 4000
        assert p["unread"] == {"exe": procevents.ANOTHER, "stat": procevents.ANOTHER, "name": procevents.ANOTHER}
        assert procevents.ANOTHER.startswith("another process held the pid") and r.counts()["reused"] == 1
    else:
        assert p["exe"] == "/usr/bin/touch" and p["started_ticks"] == ticks and p["unread"] == {}
        assert r.counts()["reused"] == 0


def test_e3_br3_a_start_other_than_the_processs_own_at_a_later_exec_is_another_process():
    system = System()
    system.proc(5001, "/usr/bin/dash", 4000, 8)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    system.proc(5001, "/usr/bin/cat", 1, 9)
    feed(r, exec_(5001))
    p = r.read()["processes"][0]
    assert p["exe"] is None and p["started_ticks"] == 8 and p["unread"]["exe"] == procevents.ANOTHER
    assert r.counts()["reused"] == 1


# --- E4 (BR-4): the last datagram, the words of a loss ----------------------------------------------------------
def test_e4_br4_counts_say_when_a_datagram_was_last_heard_and_a_loss_in_the_measured_words():
    clock = Clock()
    r = reader(System(), clock)
    assert r.counts()["last"] is None
    assert r.start() is None and r.counts()["last"] == text_of(WALL) == r.counts()["since"]   # the answer
    clock.step = 0
    clock.wall_s = WALL + 5                                  # BS-9: `last` moves with the wall clock, `since` not
    feed(r, OSError(errno.ENOBUFS, "No buffer space available"), fork(4000, 5001))
    c = r.counts()
    assert c["last"] == text_of(WALL + 5) != c["since"] == text_of(WALL)
    assert c["lost"] == {"count": 1, "events": 0,
                         "why": "the kernel's queue for this socket overflowed 1 time(s) (ENOBUFS): what the queue"
                                " held is given; what came while it was full is gone"}
    assert [p["pid"] for p in r.read()["processes"]] == [5001] and r.counts()["ended"] is None


# --- E5 (BR-5): a mark nobody can guess; no silent end ------------------------------------------------------------
def test_e5_br5_the_asks_mark_is_random_and_only_its_answer_is_the_readers():
    system = System()
    other = (PID + 1) & 0xFFFFFFFF                          # another's ask answered with an error, before the reader's
    system.before = [answer(errno.EINVAL, ack=other), answer(0, ack=PID + 1)]
    r = started(system)
    assert struct.unpack_from("=IIIIHH", system.socks[0].sent[0], 16)[3] == MARK
    assert r.counts()["unread"] == {"an answer to another listener's ask": 2} and r.refused is None
    assert "urandom" in SOURCE and "self._mark = int.from_bytes(self._urandom(4)" in SOURCE
    real = procevents.Reader(pid=PID)
    assert real._urandom is os.urandom and real._mark is None


def test_e5_br5_any_exception_that_ends_the_thread_before_the_stop_is_said():
    system = System()
    r = started(system)

    def boom():
        raise RuntimeError("a fault in the loop")
    r._once = boom
    r._run()
    assert r.counts()["ended"] == ("the reader's thread ended before the stop (RuntimeError: a fault in the loop):"
                                   " from then on nothing is heard")
    r2 = started(System())
    system2 = r2._sock.system
    system2.socks[0].inbox.append(OSError(errno.EBADF, "Bad file descriptor"))
    r2._run()
    assert r2.counts()["ended"] == ("the reader's thread ended before the stop (its receive failed: %s): from then"
                                    " on nothing is heard" % name(errno.EBADF))
    r3 = started(System())
    r3._clock = boom                                         # a clock that fails: the datagram is unread, not the end
    feed(r3, fork(4000, 5001))
    assert r3.counts()["unread"] == {"not read: RuntimeError": 1} and r3.counts()["ended"] is None


# --- E6 (BR-6): the words ---------------------------------------------------------------------------------------
REFUSALS = [
    ("platform", None, "this is not Linux (win32)"),
    ("socket", OSError(errno.EAFNOSUPPORT, "Address family not supported"),
     "the socket (AF_NETLINK, the connector) was refused (%s)" % name(errno.EAFNOSUPPORT)),
    ("bind", PermissionError(errno.EPERM, "Operation not permitted"),
     "the bind to the connector's group of process events was refused (%s); this kernel keeps its process events"
     " from this user (a kernel older than 6.8 may keep them for root), and no right is asked" % name(errno.EPERM)),
    ("send", OSError(errno.ECONNREFUSED, "refused"), "the ask to listen was refused (%s)" % name(errno.ECONNREFUSED)),
    ("answer", errno.EPERM, "the kernel answered the ask to listen with %s" % name(errno.EPERM)),
    ("silence", None, "the kernel did not answer the ask to listen within 2 s"),
    ("recv", OSError(errno.EBADF, "bad"), "the kernel's answer to the ask could not be read (%s)" % name(errno.EBADF)),
    ("setsockopt-and-bind", RuntimeError("odd"), "the reader failed while starting: RuntimeError: odd"),
]


@pytest.mark.parametrize("step, exc, words", REFUSALS, ids=[x[0] for x in REFUSALS])
def test_e6_a_refused_start_returns_its_reason_in_words_raises_nothing_and_has_no_since(step, exc, words):
    system = System()
    platform = "linux"
    if step == "platform":
        platform = "win32"
    elif step == "answer":
        system.answer = exc
    elif step in ("silence", "recv"):
        system.answer = None
    elif step == "setsockopt-and-bind":
        system.fail["setsockopt"] = OSError(errno.ENOPROTOOPT, "no")
        system.fail["bind"] = exc
    else:
        system.fail[step] = exc
    r = reader(system, platform=platform)
    if step == "recv":
        orig = system.socket

        def making(*a):
            s = orig(*a)
            s.inbox.append(exc)
            return s
        r._sockets = making
    why = r.start()
    assert why == r.refused and why.startswith(procevents.PREFIX) and words in why, why
    assert all(s.closed for s in system.socks) and r._sock is None and r._atexit.registered == []
    if step in ("answer", "silence", "recv"):      # the ask was sent: the stop of listening is asked too
        assert system.socks[0].sent == [asked(1), asked(2)]
    assert r.read() == {"processes": [], "ends": [], "older": []} and r.counts()["refused"] == why
    assert r.counts()["since"] is None
    assert r.stop() == [] and r.start() == procevents.PREFIX + "this reader was started once already (refused)"
    assert system.made == ([] if step == "platform" else [(16, socket.SOCK_DGRAM, 11)])


def test_e6_a_second_start_of_a_running_reader_says_running_not_a_refusal():
    r = started(System())
    assert r.start() == procevents.RUNNING == "running" and not procevents.RUNNING.startswith(procevents.PREFIX)
    assert r._state == "running" and r.refused is None and r.stop() == []


def test_e6_an_interrupt_in_the_start_closes_the_socket_and_goes_up():
    system = System()
    system.fail["bind"] = KeyboardInterrupt()
    r = reader(system)
    with pytest.raises(KeyboardInterrupt):
        r.start()
    assert system.socks[0].closed and r._atexit.registered == [] and r.stop() == [] and r.counts()["since"] is None


def test_e6_what_comes_before_the_answer_is_taken_and_the_receive_queue_kept_is_said():
    system = System()
    system.rcvbuf = 425984                                   # the system's maximum, doubled: less than asked
    system.proc(5001, "/usr/bin/git", 4000, 9)
    system.before = [fork(4000, 5001), OSError(errno.ENOBUFS, "No buffer space available"), exec_(5001)]
    r = started(system)
    assert [p["exe"] for p in r.read()["processes"]] == ["/usr/bin/git"]
    c = r.counts()
    assert c["lost"]["count"] == 1
    assert c["said"] == ["the socket's receive queue is reported as 425984 bytes, less than the 2097152 the kernel"
                         " reports for the 1048576 asked (twice the asked): the system's maximum"]
    s2 = System()
    s2.fail["setsockopt"] = OSError(errno.EPERM, "no")
    assert started(s2).counts()["said"] == ["the socket's receive queue is left at the system's size (%s)"
                                            % name(errno.EPERM)]
    assert started(System()).counts()["said"] == []


def test_e6_an_unread_program_is_said_with_every_cause_it_can_have():
    system = System()
    system.stats[5001] = stat_line(5001, 4000, 42)          # its stat is there, its exe link is not
    system.links[5002] = "/usr/bin/shred"
    system.stats[5002] = PermissionError(errno.EACCES, "Permission denied")
    system.links[5003] = PermissionError(errno.EPERM, "Operation not permitted")
    system.stats[5003] = b"5003 (cp) S"                        # a stat that cannot be read
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), fork(4000, 5002), exec_(5002), exec_(5003))
    a, b, c = r.read()["processes"]
    assert a["exe"] is None and a["started_ticks"] == 42
    assert a["unread"] == {"exe": "not read at its exec (%s: gone before the read, or hidden from this reader by the"
                                  " system)" % name(errno.ENOENT)}
    assert b["exe"] == "/usr/bin/shred" and b["unread"] == {k: "not read at its exec (%s: not readable by this user:"
                                                                " another user's process, or a program that made"
                                                                " itself so)" % name(errno.EACCES)
                                                             for k in ("stat", "name")}   # CC-2: read with the stat
    assert c["ppid"] is None and c["began"] is None and set(c["unread"]) == {"began", "exe", "stat", "name",
                                                                             "threads"}
    assert c["unread"]["stat"] == "not read at its exec (ValueError)" and c["unread"]["began"] == procevents.NO_FORK
    assert c["unread"]["threads"] == procevents.NO_FORK_THREADS
    assert r.counts()["missed"] == {"exe": 2, "stat": 2}     # reads, not processes: 5003 added one to each


def test_e6_a_fork_with_no_exec_runs_its_parents_program_unread_only_where_nothing_was_lost():
    system = System()
    r = started(system)
    feed(r, fork(4000, 5001))
    p = r.read()["processes"][0]
    assert (p["pid"], p["ppid"], p["exe"], p["began"], p["started_ticks"]) == (5001, 4000, None,
                                                                             text_of(WALL - 0.25), None)
    assert p["unread"] == {"exe": procevents.NO_EXEC_EXE, "stat": procevents.NO_EXEC_STAT} and system.asked == []
    assert "the program of the process that made it" in procevents.NO_EXEC_EXE


def test_e6_a_record_the_bound_refused_says_the_bound_not_no_fork_heard(monkeypatch):
    monkeypatch.setattr(procevents, "PROCESSES_MAX", 3)
    system = System()
    system.proc(5004, "/usr/bin/rm", 4000, 3)
    r = started(system)
    feed(r, *[fork(4000, 5000 + i) for i in range(5)])
    assert [p["pid"] for p in r.read()["processes"]] == [5000, 5001, 5002] and r.counts()["beyond"] == 2
    feed(r, exit_(5003), exit_(9000))
    older = r.read()["older"]
    assert [(o["pid"], o["unread"]["began"]) for o in older] == [(5003, procevents.BEYOND_BEGAN),
                                                                  (9000, procevents.NO_FORK)]
    assert "over the reader's life" in procevents.BEYOND_BEGAN and r.counts()["older"] == 2
    feed(r, exit_(5000), exit_(5001))                         # room again: a refused pid's exec says the bound
    feed(r, exec_(5004))
    p = r.read()["processes"][0]
    assert p["pid"] == 5004 and p["unread"]["began"] == procevents.BEYOND_BEGAN and p["exe"] == "/usr/bin/rm"
    feed(r, *[exit_(6000 + i) for i in range(4)])           # ends of processes never kept: held to the bound
    assert len(r.read()["older"]) == 3 and r.counts()["beyond"] == 3


def test_e6_read_gives_what_began_since_the_read_before_and_a_later_read_gives_its_end_with_its_beginning():
    system = System()
    system.proc(5001, "/usr/bin/nc", 4000, 5)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    first = r.read()["processes"]
    assert [(p["pid"], p["exe"], p["ended"], p["code"]) for p in first] == [(5001, "/usr/bin/nc", None, None)]
    assert r.read() == {"processes": [], "ends": [], "older": []}
    feed(r, exit_(5001, code=1 << 8))
    assert r.read() == {"processes": [], "older": [], "ends": [{"pid": 5001, "started_ticks": 5,
                                                                 "began": first[0]["began"],
                                                                 "ended": text_of(WALL - 0.25), "code": 1,
                                                                 "signal": None, "unread": {}}]}
    feed(r, fork(4000, 5005), exit_(5005, code=9))      # killed by SIGKILL; the parent's signal 17 is not kept
    p = r.read()["processes"][0]
    assert (p["code"], p["signal"]) == (None, 9)
    assert procevents.wait_status(0x89) == (None, 9) and procevents.wait_status(0x200) == (2, None)
    c = r.counts()
    assert set(c) == {"since", "last", "events", "given", "missed", "unread", "threads", "older", "reused", "lost",
                      "beyond", "live", "refused", "ended", "said"}
    assert c["given"] == 2 and c["since"] == text_of(WALL) and c["live"] == 0 and c["refused"] is None


def test_e6_an_exit_with_no_exec_heard_is_a_process_older_than_the_reader_said_in_older():
    system = System()
    r = started(system)
    feed(r, exit_(3000, code=3 << 8))
    assert r.read() == {"processes": [], "ends": [], "older": [
        {"pid": 3000, "started_ticks": None, "began": None, "ended": text_of(WALL - 0.25), "code": 3,
         "signal": None, "unread": {"began": procevents.NO_FORK, "threads": procevents.END_NOT_HELD}}]}
    assert r.counts()["older"] == 1 and r.read()["older"] == []


def test_e6_a_pid_reused_within_one_read_is_two_processes_and_a_lost_end_is_said():
    system = System()
    system.proc(5001, "/usr/bin/mv", 4000, 10)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), exit_(5001))
    system.proc(5001, "/usr/bin/getent", 4100, 20)
    feed(r, fork(4100, 5001), exec_(5001), exit_(5001, code=2 << 8))
    got = r.read()["processes"]
    assert [(p["pid"], p["ppid"], p["exe"], p["started_ticks"], p["code"]) for p in got] == [
        (5001, 4000, "/usr/bin/mv", 10, 0), (5001, 4100, "/usr/bin/getent", 20, 2)]
    system.proc(5002, "/usr/bin/sh", 4000, 30)
    feed(r, fork(4000, 5002), exec_(5002), fork(4000, 5002))
    a, b = r.read()["processes"]
    assert a["ended"] is None and a["unread"] == {"ended": procevents.NO_END} and b["unread"]["exe"]
    feed(r, fork(4000, 5003))
    r.read()
    feed(r, fork(4000, 5003))
    got = r.read()
    assert got["ends"] == [{"pid": 5003, "started_ticks": None, "began": text_of(WALL - 0.25), "ended": None,
                            "code": None, "signal": None, "unread": {"ended": procevents.NO_END}}]


def test_e6_the_times_are_the_kernels_stamps_on_the_wall_clock():
    system = System()
    r = started(system)
    feed(r, fork(1, 6000, ts=MONO - 1_500_000_000), exit_(6000, ts=MONO - 500_000))
    p = r.read()["processes"][0]
    assert p["began"] == text_of(WALL - 1.5) and p["ended"] == text_of(WALL - 0.0005)


def test_e6_at_an_exec_it_reads_the_exe_link_and_the_stat_and_nothing_else():
    system = System()
    system.proc(5001, "/usr/bin/wget", 3999, 777)
    r = started(system)
    feed(r, fork(4000, 5001))
    assert system.asked == []
    feed(r, exec_(5001), exit_(5001))
    assert system.asked == ["/proc/5001/exe", "/proc/5001/stat"]
    p = r.read()["processes"][0]
    assert p["ppid"] == 4000 and p["started_ticks"] == 777 and p["exe"] == "/usr/bin/wget"   # the fork's parent
    for word in ("/cmdline", "/environ", "/cwd", "/fd", "/maps", "/status", "/root", "/mem", "/io"):
        assert word not in SOURCE, word


# --- the stop, the exit, the context manager ------------------------------------------------------------------
def test_e6_stop_ends_the_thread_and_closes_the_socket_and_twice_does_nothing():
    system = System()
    system.wait = True
    r = reader(system, thread=threading.Thread)
    assert r.start() is None and r._thread.is_alive() and r._thread.daemon
    system.socks[0].inbox.append(fork(4000, 5001))
    end = time.monotonic() + 5
    while not r.counts()["events"]["fork"] and time.monotonic() < end:
        time.sleep(0.01)
    thread = r._thread
    assert r.stop() == [] and not thread.is_alive() and system.socks[0].closed
    assert r.stop() == [] and system.socks[0].sent == [asked(1), asked(2)] and r.counts()["ended"] is None
    assert [p["pid"] for p in r.read()["processes"]] == [5001]   # what was heard is still read after the stop


def test_e6_the_reader_is_a_context_manager_and_is_stopped_at_the_interpreters_exit():
    system = System()
    with pytest.raises(ValueError):
        with reader(system) as r:
            assert r._state == "running"
            raise ValueError("inside")
    assert r._state == "stopped" and system.socks[0].closed and r._atexit.registered == []
    s2 = System()
    r2 = started(s2)
    assert len(r2._atexit.registered) == 1
    r2._atexit.registered[0]()                      # what the interpreter runs at its exit
    assert r2._state == "stopped" and s2.socks[0].closed and r2._atexit.registered == []
    assert procevents.Reader(PID)._atexit is atexit


def test_e6_the_stops_problems_are_said():
    system = System()
    r = started(system)
    system.fail["send again"] = OSError(errno.ENOBUFS, "no")
    system.fail["close"] = OSError(errno.EIO, "io")
    assert r.stop() == ["the ask to stop listening failed (%s)" % name(errno.ENOBUFS),
                        "the socket could not be closed (OSError: [Errno %d] io)" % errno.EIO]
    assert r.stop() == [] and r._atexit.registered == []


def test_e6_past_processes_max_is_counted_beyond_and_the_bound_is_a_constant(monkeypatch):
    tree = ast.parse(SOURCE)
    consts = {t.id: n.value for n in tree.body if isinstance(n, ast.Assign) for t in n.targets
              if isinstance(t, ast.Name)}
    assert isinstance(consts["PROCESSES_MAX"], ast.Constant) and consts["PROCESSES_MAX"].value == 32768
    monkeypatch.setattr(procevents, "PROCESSES_MAX", 3)
    r = started(System())
    feed(r, *[fork(4000, 5000 + i) for i in range(5)])
    r.read()
    feed(r, fork(4000, 5100))                                 # over the reader's life: the three live are kept
    assert r.read()["processes"] == [] and r.counts()["beyond"] == 3 and r.counts()["live"] == 3


# --- everything of the system through arguments; the one real test -------------------------------------------
def test_e3_a_whole_run_touches_nothing_of_the_real_system(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the real system was touched: %r" % (a,))
    for owner, attr in ((socket, "socket"), (os, "readlink"), (builtins, "open"), (time, "time"),
                        (time, "monotonic_ns"), (time, "monotonic"), (atexit, "register"), (os, "urandom"),
                        (os, "sysconf")):
        monkeypatch.setattr(owner, attr, boom, raising=False)
    monkeypatch.setattr(time, "clock_gettime_ns", boom, raising=False)
    system = System()
    system.proc(5001, "/usr/bin/sh", 4000, 1)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), exit_(5001))
    assert r.read()["processes"][0]["exe"] == "/usr/bin/sh" and r.stop() == []


LINUX = sys.platform.startswith("linux")


@pytest.mark.skipif(not LINUX, reason="the kernel's process events are Linux's")
def test_e7_the_real_kernel_tells_each_child_of_its_own_and_its_program_or_why_not():
    """BR-7: each child is heard with its parent and its exit code; its program is asked of every one, and where it
    was not read in time (the sandbox misses some) the test says how many and why, and is not held to none."""
    true = os.path.realpath(shutil.which("true") or "/bin/true")
    r = procevents.Reader()
    why = r.start()
    if why:
        r.stop()
        pytest.skip("the kernel refused here: %s" % why)
    heard, children = {}, []
    try:
        time.sleep(0.2)                            # the reader's thread waits in its receive
        for _ in range(5):
            child = subprocess.Popen(["true"])
            child.wait()
            children.append(child.pid)
        end = time.monotonic() + 5
        while any(heard.get(pid, {}).get("ended") is None for pid in children) and time.monotonic() < end:
            got = r.read()                         # a process is given again at its exec, its end later in ends
            for p in got["processes"]:
                heard[p["pid"]] = p
            for e in got["ends"]:
                if e["pid"] in heard:
                    heard[e["pid"]].update(ended=e["ended"], code=e["code"], signal=e["signal"])
            time.sleep(0.02)
        c = r.counts()
    finally:
        assert r.stop() == []
    missed = []
    for pid in children:
        p = heard.get(pid)
        assert p is not None, ("a child was not heard", pid, c)
        assert p["code"] == 0 and p["signal"] is None and p["ppid"] == os.getpid() and p["ended"], p
        if p["exe"] != true:
            assert p["exe"] is None and p["unread"]["exe"].startswith("not read at its exec ("), p
            missed.append(p["unread"]["exe"])
    assert c["lost"]["count"] == 0 and c["beyond"] == 0 and c["ended"] is None and c["refused"] is None
    if missed:
        warnings.warn("the real kernel: %d of %d programs not read in time: %s" % (len(missed), len(children),
                                                                                  "; ".join(sorted(set(missed)))))


# --- E9: the standard library alone, AF_NETLINK alone, no program, no file, imported by nothing yet -------------
def _imports(source):
    tree = ast.parse(source)
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add(("." * n.level) + (n.module or ""))
    return tree, mods


def test_e9_the_standard_library_alone_no_program_and_no_file_written():
    tree, mods = _imports(SOURCE)
    assert mods == {"__future__", "atexit", "datetime", "errno", "json", "os", "queue", "signal", "socket", "struct",
                    "subprocess", "sys", "threading", "time", "raqib"}   # M17.2b (CI-1): raqib.own, in start alone
    (start,) = [f for c in tree.body if isinstance(c, ast.ClassDef) and c.name == "Helper" for f in c.body
                if isinstance(f, ast.FunctionDef) and f.name == "start"]
    ours = [n for n in ast.walk(tree) if (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "raqib")
            or (isinstance(n, ast.Import) and any(a.name.split(".")[0] == "raqib" for a in n.names))]
    assert [(n.module, [a.name for a in n.names]) for n in ours] == [("raqib", ["own"])]
    assert all(n in list(ast.walk(start)) for n in ours)
    assert mods - {"__future__", "raqib"} <= set(sys.stdlib_module_names)   # raqib.own: the standard library only
    # M14.1b REDO (BW-8): only the client starts a program (the helper): `subprocess` is named inside class Helper
    # alone, never in serve, main or the Reader
    (helper,) = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Helper"]
    inside = {id(n) for n in ast.walk(helper)}
    named = [n for n in ast.walk(tree) if (isinstance(n, ast.Name) and n.id == "subprocess") or (
        isinstance(n, ast.alias) and n.name == "subprocess")]
    assert named and all(id(n) in inside for n in named)
    calls = [ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)]
    for bad in ("os.system", "os.popen", "os.fork", "os.spawn", "os.exec", "os.posix_spawn", "os.write", "os.remove",
                "os.unlink", "os.mkdir", "os.rename", "os.replace", "os.kill"):
        assert not [c for c in calls if c.startswith(bad)], bad
    opens = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == "open"]
    assert len(opens) == 1 and ast.unparse(opens[0].args[1]) == "'rb'"
    families = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr.startswith("AF_")}
    families |= {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and
                 n.value.startswith("AF_")}
    assert families == {"AF_NETLINK"}


def test_e9_no_socket_but_af_netlink_is_opened(monkeypatch):
    families = []

    class Only:
        def __init__(self, family, type_, proto):
            families.append((family, type_, proto))
            if family != 16:
                raise AssertionError("a socket of another family: %r" % family)
            self.inner = System().socket(family, type_, proto)

        def __getattr__(self, attr):
            return getattr(self.inner, attr)
    monkeypatch.setattr(socket, "socket", Only)
    clock = Clock()
    r = procevents.Reader(pid=PID, clock=clock.wall, mono=clock.mono, boot=clock.boot, thread=NoThread,
                          at_exit=Registry(), platform="linux", urandom=lambda n: MARK_BYTES, ticks_per_second=HZ)
    assert r.start() is None and r.stop() == []
    assert families == [(16, socket.SOCK_DGRAM, 11)]


def test_e9_only_the_watch_imports_the_reader():
    users = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "raqib").rglob("*.py")
                   if p.name != "procevents.py" and "procevents" in p.read_text(encoding="utf-8"))
    # M14.1c (ADR-0007 BY-1): discover names the round's source of that kind and parses its text; it never imports
    # the reader (only the watch does). M17.2a (ADR-0007 CG-1): the entry (raqib/cli.py main) takes the helper's
    # word before anything else, and uses nothing of the module but word()
    assert users == ["raqib/cli.py", "raqib/discover.py", "raqib/host.py"]
    cli_tree = ast.parse((ROOT / "raqib" / "cli.py").read_text(encoding="utf-8"))
    used = {n.attr for n in ast.walk(cli_tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
            and n.value.id == "procevents"}
    assert used == {"word"}
    # the review's S1: and it reaches the module by one import alone, `from raqib import ... procevents ...`
    imports = [n for n in ast.walk(cli_tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert not [n for n in imports if isinstance(n, ast.ImportFrom) and (n.module or "").endswith("procevents")]
    assert not [a for n in imports if isinstance(n, ast.Import) for a in n.names if "procevents" in a.name]
    named = [(n.module, a.name, a.asname) for n in imports if isinstance(n, ast.ImportFrom) for a in n.names
             if a.name == "procevents"]
    assert named == [("raqib", "procevents", None)]
    tree = ast.parse((ROOT / "raqib" / "discover.py").read_text(encoding="utf-8"))
    names = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    names |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not [x for x in names if "procevents" in x]


# --- E6: the docs ---------------------------------------------------------------------------------------------
def flat(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def test_e6_the_spec_says_the_layout_what_is_read_every_count_and_what_was_measured_and_not():
    spec = flat("docs/specs/PROC-EVENTS.md")
    for sentence in (
            "a socket of AF_NETLINK, SOCK_DGRAM, protocol 11 (the connector), bound to the reader's pid and group 1",
            "Several messages may come in one datagram, each padded to 4 bytes.",
            "At an exec the reader reads at once the link /proc/PID/exe (the program) and /proc/PID/stat (the parent"
            ", the start in clock ticks and the name the kernel gave the process), and nothing else of the"
            " process.",   # M14.1d (CC-2): the name, from the same stat
            "No argument, no environment, no working directory and no open file of a process is ever read, and"
            " nothing is read at a fork or an exit.",
            "An ended record is taken up again by an exec of its pid, with no fork between, only where its start and"
            " the exec's read start are both known and equal",
            "A pid taken again within one second of the exec, before the read, is not told apart, and the newcomer's"
            " program and start are then given as the first process's.",
            "A record keeps its newest 7 earlier programs (EARLIER_MAX); the number of older ones not kept is said"
            " on the record",   # M14.1d (CC-1): 8 programs a process
            "runs the program of the process that made it",
            "what the queue held is given; what came while it was full is gone; how many: at least the count.",
            "A step seen while no ENOBUFS has come since the start is a loss the kernel did not tell",
            "An answer to any listener's ask takes the next number of its CPU's count",
            "After an overflow of the listener's queue (ENOBUFS) the events went on, for that listener alone and for"
            " a second one opened after it.",
            "When a thread that is not the leader called exec, the kernel sent an exit with pid equal to tgid (code"
            " 0), then the exec, then the process's real exit.",
            "When the leader thread ended and another thread lived on, the kernel sent an exit with pid equal to tgid"
            " (code 0) at once, and the process's own code came on the last thread's exit.",
            "At an overflow (a queue of 9216 bytes, 300 children made while nothing was read) the error (ENOBUFS)"
            " was read first; after it the events the queue had held were still given; the events made while it was"
            " full were never given; events made afterwards all came.",
            "The gaps in the kernel's count over the events read added up to 275, 589 and 626 where some 890 events"
            " were lost: a count from below, not the whole.",
            "the other order was not seen in 2400 runs. If it came, the reader would give the leader thread's exit as"
            " the end of a process that lives on, and its real end as an end of a process it did not hold.",
            "In the builder's sandbox (kernel 6.18, 2 CPUs, as root) the first build's rig run was MET once in nine"
            " runs; in the other eight, 1 to 3 of 14 programs were not read in time (ENOENT), each counted in"
            " `missed`",
            "The REDO's runs there: the real test missed 3 or 4 of 5 programs of `true` in three runs",
            "The second REDO's runs there:",
            "The bound counts over the reader's life: a process whose end was lost never leaves `live`, so after"
            " enough losses every new process is past the bound.",
            "The parent is the one the kernel names: a child made to be its maker's sibling is given its maker's"
            " parent, not its maker.",
            "A program can keep itself unread: by ending before the read, by making itself not readable by this user,"
            " or by being hidden from the reader by the system.",
            "`missed` counts reads, not processes: one process can add one to each of `exe` and `stat`.",
            "`beyond` counts events and records past the bound, not processes.",
            "Read in the kernel's source, not measured:",
            "Not measured: a kernel older than 6.8 (the connector may be root's there); whether a plain user hears"
            " another user's processes; a machine that starts thousands of processes a second; a process inside a"
            " container; a reader inside a time namespace; the times of events read after the machine slept."):
        assert sentence in spec, sentence
    for key in ("since", "last", "events", "given", "missed", "unread", "threads", "older", "reused", "lost",
                "beyond", "live", "refused", "ended", "said"):
        assert "- `%s`" % key in spec, key
    for gone in ("every measured event is 40 bytes", "name one holder of a pid", "within one clock tick",
                 "within the tick", "its parent's program", "what was in the queue is gone"):
        assert gone not in spec, gone
    measured = spec[spec.index("## What was measured"):spec.index("## Read in the kernel's source")]
    for source_only in ("whole group", "CLONE_PARENT", "not dumpable", "time namespace"):
        assert source_only not in measured, source_only


def test_e6_the_threat_model_says_what_an_agent_can_do_about_this_source_without_a_milestone_token():
    import re
    text = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    start = text.index("- **The kernel's process events on Linux")
    section = " ".join(text[start:text.index("\n- **", start + 5)].split())
    for sentence in (
            "an agent that starts more processes than the reader's bound (32768) has the rest counted `beyond`, not"
            " kept; the bound counts over the reader's life, and a process whose end was lost never leaves it",
            "a process that ends before its program is read, that is not readable by this user (a program can make"
            " itself so), or that the system hides from the reader is given without its program: the read is"
            " counted in `missed` and named in its `unread`",
            "a pid taken again within one second of the exec, before the read, is not told apart: the newcomer's"
            " program and start are then given as the first process's",
            "a burst the kernel cannot queue for the reader is counted in `lost` (ENOBUFS), never as nothing"
            " happened; what the queue held is given, what came while it was full is gone, and the kernel's own"
            " count on each CPU gives how many at least, a gap with no ENOBUFS included",
            "an end of a process the reader did not hold from its fork, or any end given after a loss, may be its"
            " leader thread's alone, and says so",
            "if a thread's exec ever came before its leader's exit (not seen in 2400 runs), the reader would give"
            " the end of a process that lives on",
            "a kernel that refuses (an older one, or a container's) is the hole, said in the reader's words as"
            " `refused`, and nothing else is tried",
            "a child made to be its maker's sibling is given the parent the kernel names, which is not its maker",
            "a process that changes its program again keeps the programs it had before in `earlier`, its newest 7"):
        assert sentence in section, sentence
    for gone in ("within one clock tick", "whatever shows it escapes it", "how many events the queue held"):
        assert gone not in section, gone
    assert not re.search(r"\bM\d+\.\d+", section)


def test_e9_ascii_outside_docs():
    for path in ("raqib/procevents.py", "tests/test_procevents.py"):
        assert (ROOT / path).read_bytes().isascii(), path


# --- REDO 2 (Amendment BS) ----------------------------------------------------------------------------------------
def ended_once(system, first_stat=None):
    """A process 5001 forked, exec'd and ended, its end read; the reader and that read."""
    system.links[5001] = "/usr/bin/sh"
    system.stats[5001] = first_stat if first_stat is not None else stat_line(5001, 4000, 50)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), exit_(5001))
    got = r.read()["processes"][0]
    assert got["ended"] is not None
    return r, got


@pytest.mark.parametrize("case", ["a different start", "the old start unknown", "the read failed",
                                  "the read another's"])
def test_e1_bs2_an_ended_record_is_taken_up_only_where_both_starts_are_known_and_equal(case):
    system = System()
    r, first = ended_once(system, PermissionError(errno.EACCES, "no") if case == "the old start unknown" else None)
    if case == "the read failed":
        system.links[5001], system.stats[5001] = "/usr/bin/cat", FileNotFoundError(errno.ENOENT, "gone")
    else:                                    # 600000 ticks: 6000 s, later than the exec on the boot clock
        system.proc(5001, "/usr/bin/cat", 4100, 600000 if case == "the read another's" else 60)
    feed(r, exec_(5001))
    got = r.read()
    p = got["processes"][0]
    assert p["unread"]["began"] == procevents.NO_FORK_AFTER_END and p["earlier"] == [] and p["ended"] is None
    assert "a thread of the same process called exec" in procevents.NO_FORK_AFTER_END and got["ends"] == []
    assert r._gone[5001].ended == first["ended"] and r._gone[5001].exe == "/usr/bin/sh"   # left ended
    if case == "the read another's":
        assert p["unread"]["exe"] == procevents.ANOTHER and r.counts()["reused"] == 1


def test_e2_bs3_an_end_says_its_threads_are_not_known_where_the_process_was_not_held_or_events_were_lost():
    system = System()
    system.proc(5001, "/usr/bin/sh", 1, 50)
    r = started(system)
    feed(r, exec_(5001))                                       # held from its exec, not its fork
    r.read()
    feed(r, exit_(5001))
    end = r.read()["ends"][0]
    assert end["unread"] == {"threads": procevents.END_NOT_HELD} and "leader thread's alone" in end["unread"]["threads"]
    system.proc(5002, "/usr/bin/cp", 4000, 51)
    feed(r, fork(4000, 5002), exec_(5002))
    r.read()
    feed(r, OSError(errno.ENOBUFS, "No buffer space available"), exit_(5002), exit_(3000))
    got = r.read()
    loss = "ENOBUFS 1 time(s), at least 0 event(s) by the kernel's count"
    assert got["ends"][0]["unread"] == {"threads": procevents.END_LOST % loss}
    assert got["older"][0]["unread"]["threads"] == procevents.END_LOST % loss


def test_e2_bs3_a_threads_end_after_an_end_of_a_process_not_held_is_its_later_end_with_its_code():
    system = System()
    r = started(system)
    feed(r, exit_(3000, code=0))                               # order (b) of a process not held: its leader's end
    first = r.read()["older"]
    assert [(o["pid"], o["code"]) for o in first] == [(3000, 0)]
    feed(r, exit_(3001, tgid=3000, code=5 << 8), exit_(3002, tgid=3000, code=7 << 8))   # its threads' ends
    later = r.read()["older"]
    assert [(o["pid"], o["code"], o["unread"]) for o in later] == [
        (3000, 7, {"began": procevents.NO_FORK, "ended": procevents.LATER_END, "threads": procevents.LATER_THREADS})]
    assert "one thread's" in procevents.LATER_THREADS and "leader" not in procevents.LATER_THREADS   # H3
    feed(r, exit_(3003, tgid=3000, code=9 << 8))               # after a read: another later end
    assert [(o["pid"], o["code"]) for o in r.read()["older"]] == [(3000, 9)]
    feed(r, exit_(3101, tgid=3100))                            # a thread of a pid it gave no end of: counted only
    assert r.read()["older"] == [] and r.counts()["older"] == 3


def test_e2_bs3_an_exec_after_an_end_of_a_process_not_held_is_a_new_record_not_no_fork_heard():
    system = System()
    system.proc(3000, "/usr/bin/node", 1, 40)
    r = started(system)
    feed(r, exit_(3000), exec_(3000))                          # order (a) of a process not held
    got = r.read()
    assert got["older"][0]["pid"] == 3000
    assert [(p["pid"], p["exe"], p["unread"]["began"]) for p in got["processes"]] == [
        (3000, "/usr/bin/node", procevents.NO_FORK_AFTER_END)]


def test_e2_bs3_a_record_taken_up_withdraws_its_unread_end_or_says_the_end_given_before_was_its_leaders():
    system = System()
    system.proc(5001, "/usr/bin/sh", 4000, 50)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    r.read()
    feed(r, exit_(5001), exec_(5001))                          # its end not read yet: withdrawn
    got = r.read()
    assert got["ends"] == [] and [(p["pid"], p["ended"], "ended" in p["unread"]) for p in got["processes"]] == [
        (5001, None, False)]
    feed(r, exit_(5001))
    assert [e["pid"] for e in r.read()["ends"]] == [5001]      # its end read
    feed(r, exec_(5001))
    p = r.read()["processes"][0]
    assert p["ended"] is None and p["unread"]["ended"] == procevents.ENDED_BEFORE
    assert "leader thread's" in procevents.ENDED_BEFORE


def test_h5_an_end_past_the_bound_was_never_given_and_is_not_called_the_end_given_before(monkeypatch):
    # the third review, H5: `ends` full at a record's end: the end is counted in `beyond` and never given; a record
    # taken up again after it must not say "the end given before"
    system = System()
    for pid in (5001, 5002):
        system.proc(pid, "/usr/bin/p", 4000, 50 + pid)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), fork(4000, 5002), exec_(5002))
    assert [p["pid"] for p in r.read()["processes"]] == [5001, 5002]
    monkeypatch.setattr(procevents, "PROCESSES_MAX", 1)
    feed(r, exit_(5001), exit_(5002))                          # the second end is past the bound of `ends`
    assert r.counts()["beyond"] == 1
    feed(r, exec_(5002))                                       # its own start: taken up again
    got = r.read()
    assert [e["pid"] for e in got["ends"]] == [5001]
    p = [p for p in got["processes"] if p["pid"] == 5002][0]
    assert p["ended"] is None and "ended" not in p["unread"]


def test_e3_bs4_a_record_keeps_its_newest_7_earlier_programs_and_counts_the_rest():
    system = System()
    system.proc(5001, "/usr/bin/p0", 4000, 50)
    r = started(system)
    feed(r, fork(4000, 5001))
    for i in range(40):
        system.links[5001] = "/usr/bin/p%d" % i
        feed(r, exec_(5001))
    p = r.read()["processes"][0]
    # M14.1d (CC-1): 8 programs a process at most, the one it has now among them
    assert procevents.PROGRAMS_MAX == 8 and procevents.EARLIER_MAX == 7 and len(p["earlier"]) == 7
    assert p["exe"] == "/usr/bin/p39" and [e["exe"] for e in p["earlier"]] == ["/usr/bin/p%d" % i for i in range(32, 39)]
    assert p["unread"]["earlier"] == "32 earlier program(s) not kept: a record keeps its newest 7 (EARLIER_MAX)"
    assert p["dropped"] == 32


# --- E4 (BS-5): the kernel's count of events on each CPU --------------------------------------------------------
def lost_after(*datagrams):
    r = started(System())
    feed(r, *datagrams)
    return r, r.counts()


def test_e4_bs5_no_gap_two_cpus_and_an_answer_between_are_no_loss():
    # the third review, H1 (measured on 6.8, 7.0 and 6.18): another listener's answer takes the next number of its
    # CPU, so the event after it steps by one from the answer, not from the event before it
    r, c = lost_after(fork(1, 6001, cpu=0, seq=10), fork(1, 6002, cpu=3, seq=500), fork(1, 6003, cpu=0, seq=11),
                      answer(0, ack=9, seq=12, cpu=0), fork(1, 6004, cpu=3, seq=501), exit_(6001, cpu=0, seq=13))
    assert c["lost"] == {"count": 0, "events": 0, "why": None} and c["said"] == []
    r, c = lost_after(fork(1, 6001, cpu=0, seq=10), answer(0, ack=9, seq=12, cpu=0), exit_(6001, cpu=0, seq=13))
    assert c["lost"]["events"] == 1                      # a number stepped over before the answer is still a loss


def test_e4_bs5_a_gap_after_enobufs_is_lost_events_at_least_in_the_measured_words():
    r, c = lost_after(fork(1, 6001, cpu=0, seq=10), OSError(errno.ENOBUFS, "No buffer space available"),
                      fork(1, 6002, cpu=0, seq=15))
    assert c["lost"] == {"count": 1, "events": 4, "why": (
        "the kernel's queue for this socket overflowed 1 time(s) (ENOBUFS): what the queue held is given; what came"
        " while it was full is gone; how many: at least 4 event(s) by the kernel's own count on each CPU (a count"
        " from below)")}
    p = r.read()["processes"][0]
    assert p["unread"]["threads"] == procevents.LOST_THREADS % "ENOBUFS 1 time(s), at least 4 event(s) by the" \
                                                               " kernel's count"


def test_e4_bs5_a_gap_with_no_enobufs_is_a_loss_the_kernel_did_not_tell():
    r, c = lost_after(fork(1, 6001, cpu=0, seq=10), message(COMM, bytes(24), cpu=0, seq=11),
                      fork(1, 6002, cpu=0, seq=14))
    assert c["lost"]["count"] == 0 and c["lost"]["events"] == 2
    assert c["lost"]["why"].endswith("2 of them came before any ENOBUFS: a loss the kernel did not tell")
    feed(r, OSError(errno.ENOBUFS, "No buffer space available"), fork(1, 6003, cpu=0, seq=20))
    assert r.counts()["lost"]["why"].endswith("2 of them came before any ENOBUFS: a loss the kernel did not tell")
    # the third review, H2 (the measured order: the ENOBUFS is read first, a CPU's gap shows at its next event,
    # which may come after a counts()): once an ENOBUFS came, a gap is never called untold
    feed(r, fork(1, 6004, cpu=0, seq=23))
    assert r.counts()["lost"]["events"] == 9 and "2 of them came before any ENOBUFS" in r.counts()["lost"]["why"]


def test_h2_a_gap_seen_after_counts_was_read_is_not_called_untold_once_an_enobufs_came():
    r, c = lost_after(fork(1, 6001, cpu=0, seq=10), fork(1, 6002, cpu=1, seq=40),
                      OSError(errno.ENOBUFS, "No buffer space available"), fork(1, 6003, cpu=0, seq=15))
    assert c["lost"]["events"] == 4 and "did not tell" not in c["lost"]["why"]
    feed(r, fork(1, 6004, cpu=1, seq=45))                # the idle CPU's gap shows later, after counts() was read
    c = r.counts()
    assert c["lost"]["events"] == 8 and "did not tell" not in c["lost"]["why"]


def test_e4_bs5_a_count_that_goes_back_is_not_counted_and_is_said_once():
    r, c = lost_after(fork(1, 6001, cpu=0, seq=10), fork(1, 6002, cpu=0, seq=8), fork(1, 6003, cpu=0, seq=8),
                      fork(1, 6004, cpu=0, seq=9))
    assert c["lost"]["events"] == 0 and c["said"] == [
        "the kernel's count of events on CPU 0 went from 10 to 8: a step that is not forward is not counted (said"
        " once)"]


# --- E6 (BS-7): said as it is ------------------------------------------------------------------------------------
def test_e6_bs7_a_boot_clock_that_fails_is_said_once_and_the_check_is_off():
    system = System()
    system.proc(5001, "/usr/bin/cat", 4000, 600000)          # would be another's with the check on
    clock = Clock()

    def no_boot():
        raise OSError(errno.EINVAL, "no such clock")
    clock.boot = no_boot
    r = started(system, clock)
    feed(r, fork(4000, 5001), exec_(5001))
    assert r.counts()["said"] == ["the boot clock cannot be read (%s): no read is held against its exec's time"
                                  % name(errno.EINVAL)]
    assert r.read()["processes"][0]["exe"] == "/usr/bin/cat" and r.counts()["reused"] == 0


@pytest.mark.parametrize("kept, said", [(2 * (1 << 20), False), (2 * (1 << 20) - 2, True), (1 << 20, True)])
def test_e6_bs7_the_queue_is_compared_as_the_kernel_reports_it(kept, said):
    system = System()
    system.rcvbuf = kept
    words = ("the socket's receive queue is reported as %d bytes, less than the 2097152 the kernel reports for the"
             " 1048576 asked (twice the asked): the system's maximum" % kept)
    assert started(system).counts()["said"] == ([words] if said else [])


def test_e6_bs7_a_start_with_no_answer_while_the_queue_overflowed_says_so():
    system = System()
    system.answer = None
    system.before = [OSError(errno.ENOBUFS, "No buffer space available")]
    why = reader(system).start()
    assert why.startswith(procevents.PREFIX + "the kernel did not answer the ask to listen within 2 s")
    assert why.endswith("; the kernel's queue for this socket overflowed (ENOBUFS) 1 time(s) while the answer was"
                        " awaited: the answer may be among what was lost")


# --- E8 (BS-9): each guard fails a test where it is removed -------------------------------------------------------
def test_e8_bs9_leader_ended_is_cleared_at_an_exec():
    system = System()
    system.proc(5001, "/usr/bin/sh", 4000, 50)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), fork(5001, 5002, tgid=5001), exit_(5001), exec_(5001),
         fork(5001, 5003, tgid=5001), exit_(5003, tgid=5001))
    assert r.counts()["live"] == 1 and r.read()["processes"][0]["ended"] is None   # a thread's end, not its end


def test_e8_bs9_the_threads_of_one_process_are_bounded(monkeypatch):
    monkeypatch.setattr(procevents, "PROCESSES_MAX", 3)
    r = started(System())
    feed(r, fork(4000, 5001), *[fork(5001, 5100 + i, tgid=5001) for i in range(5)])
    assert len(r._live[5001].threads) == 3 and r.counts()["beyond"] == 2


def test_e8_bs9_the_memories_of_ended_and_refused_pids_forget_their_oldest(monkeypatch):
    monkeypatch.setattr(procevents, "PROCESSES_MAX", 3)
    system = System()
    r = started(system)
    for pid in (5001, 5002, 5003, 5004):
        system.proc(pid, "/usr/bin/true", 4000, 50)
        feed(r, fork(4000, pid), exec_(pid), exit_(pid))
        r.read()
    assert sorted(r._gone) == [5002, 5003, 5004]
    feed(r, exec_(5001))                                       # forgotten: not taken up, and nothing says its end
    assert r.read()["processes"][0]["unread"]["began"] == procevents.NO_FORK
    feed(r, exit_(5001))
    r.read()
    feed(r, fork(4000, 5011), fork(4000, 5012), fork(4000, 5013))   # the bound is full
    feed(r, *[fork(4000, 6000 + i) for i in range(4)])        # refused; the memory keeps the newest 3
    feed(r, exit_(6000), exit_(6003))
    assert [(o["pid"], o["unread"]["began"]) for o in r.read()["older"]] == [
        (6000, procevents.NO_FORK), (6003, procevents.BEYOND_BEGAN)]


def test_e8_bs9_ticks_of_a_second_not_known_are_said(monkeypatch):
    def nothing(name):
        raise ValueError("unknown configuration name")
    monkeypatch.setattr(os, "sysconf", nothing, raising=False)
    system = System()
    clock = Clock()
    r = procevents.Reader(pid=PID, sockets=system.socket, readlink=system.readlink, read_bytes=system.read_bytes,
                          clock=clock.wall, mono=clock.mono, boot=clock.boot, thread=NoThread, at_exit=Registry(),
                          platform="linux", urandom=lambda n: MARK_BYTES)
    assert r.start() is None
    assert r.counts()["said"] == ["the clock ticks of a second are not known (ValueError): no read is held against"
                                  " its exec's time"]
