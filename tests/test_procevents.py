"""M14.1a (HANDOFF E1-E5, E7, E8; ADR-0007 Amendment BQ, BQ-1 and BQ-2): the reader of Linux's process events
alone, raqib/procevents.py. The system is a fake here (System): the socket's maker, the reads of /proc and the
clocks are its; the datagrams it hands the reader are laid out here by hand, as the Table measured them on kernels
6.8 and 7.0 (nlmsghdr =IHHII, cn_msg =IIIIHH, the event's header =IIQ, its data at 16), and not taken from the
module's structures, so the module's layouts are checked against a statement of them made apart. One test opens a
real netlink socket and hears a child of its own; it is skipped off Linux and where the kernel refuses. Pids,
paths and times are made up."""
import ast
import atexit
import builtins
import datetime
import errno
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
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


def text_of(seconds):
    return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- the messages, by hand ------------------------------------------------------------------------------------
def message(what, data, ts=TS, cpu=1, idx=1, val=1, seq=77, ack=0, nltype=3, cut=None, size=None):
    """One netlink message of the connector: nlmsghdr (16), cn_msg (20), the event (what, cpu, time; its data),
    padded to 4 bytes. The kernel's union is 24 bytes, so every event of the measured kernels is 40."""
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


def answer(err=0, ack=PID + 1, seq=15821):
    return message(0, struct.pack("=I", err) + bytes(20), ack=ack, seq=seq, cpu=0xFFFFFFFF)


def asked(op, pid=PID):
    """The ask as measured: nlmsghdr (40, type 3, flags 0, seq 0, the pid), cn_msg (idx 1, val 1, seq 0, ack: the
    reader's own nonce, its pid; len 4, flags 0), the u32 op (1 listen, 2 ignore)."""
    return struct.pack("=IHHII", 40, 3, 0, 0, pid) + struct.pack("=IIIIHH", 1, 1, 0, pid, 4, 0) + struct.pack("=I", op)


def stat_line(pid, ppid, ticks, comm="a) (b"):
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

    def wall(self):
        return WALL

    def mono(self):
        self.now += self.step
        return self.now - self.step


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
                             clock=clock.wall, mono=clock.mono, thread=thread, at_exit=Registry(), platform=platform)


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


# --- E1: the messages, as measured --------------------------------------------------------------------------------
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
    odd = message(COMM, struct.pack("=II", 5001, 5001) + b"curl\0\0\0\0\0\0\0\0\0\0\0\0\0")   # 77: padded to 80
    assert len(odd) % 4 == 0 and struct.unpack_from("=I", odd, 0)[0] == 77
    feed(r, fork(4000, 5001) + odd + exec_(5001) + exit_(5001, code=7 << 8))
    got = r.read()
    assert got == {"processes": [{"pid": 5001, "ppid": 4000, "exe": "/usr/bin/curl", "started_ticks": 123456,
                                  "began": text_of(WALL - 0.25), "ended": text_of(WALL - 0.25), "code": 7,
                                  "signal": None, "unread": {}}], "ends": [], "older": []}
    c = r.counts()
    assert c["events"] == {"fork": 1, "exec": 1, "exit": 1} and c["unread"] == {"comm": 1} and c["given"] == 1
    assert procevents.parse(fork(1, 2))[0] == ("fork", TS, (1, 1, 2, 2))
    assert procevents.parse(exit_(9, code=9))[0] == ("exit", TS, (9, 9, 9, 17))


def test_e1_a_thread_is_not_a_process_and_is_counted_apart():
    system = System()
    r = started(system)
    feed(r, fork(4000, 5002, tgid=4000), exec_(5003, tgid=5001), exit_(5002, tgid=4000))
    assert r.read() == {"processes": [], "ends": [], "older": []} and system.asked == []
    c = r.counts()
    assert c["threads"] == 3 and c["events"] == {"fork": 1, "exec": 1, "exit": 1} and c["live"] == 0
    # a fork from a thread of the parent: the child's parent is the parent's process (its tgid)
    feed(r, fork(4001, 5004, ptgid=4000))
    assert r.read()["processes"][0]["ppid"] == 4000


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
        "exec shorter than its shape": 1, "exit shorter than its shape": 1, "an event shorter than its header": 2,
        "a netlink message of type 2": 1, "a message of another connector (5, 1)": 1,
        "a connector message shorter than its header": 1,
        "a netlink message whose length is not in its datagram": 1,
        "a datagram's tail shorter than a netlink header": 1, "an empty datagram": 1,
        "an answer to another listener's ask": 1}
    assert r.counts()["events"] == {"fork": 0, "exec": 0, "exit": 0}


# --- E2: the Reader ---------------------------------------------------------------------------------------------------
REFUSALS = [
    ("platform", None, "this is not Linux (win32)"),
    ("socket", OSError(errno.EAFNOSUPPORT, "Address family not supported"), "the socket (AF_NETLINK, the connector)"
                                                                            " was refused (EAFNOSUPPORT)"),
    ("bind", PermissionError(errno.EPERM, "Operation not permitted"), "the bind to the connector's group of process"
                                                                      " events was refused (EPERM); this kernel keeps"
                                                                      " its process events from this user (a kernel"
                                                                      " older than 6.8 may keep them for root), and no"
                                                                      " right is asked"),
    ("send", OSError(errno.ECONNREFUSED, "refused"), "the ask to listen was refused (ECONNREFUSED)"),
    ("answer", errno.EPERM, "the kernel answered the ask to listen with EPERM"),
    ("silence", None, "the kernel did not answer the ask to listen within 2 s"),
    ("recv", OSError(errno.EBADF, "bad"), "the kernel's answer to the ask could not be read (EBADF)"),
    ("setsockopt-and-bind", RuntimeError("odd"), "the reader failed while starting: RuntimeError: odd"),
]


@pytest.mark.parametrize("step, exc, words", REFUSALS, ids=[x[0] for x in REFUSALS])
def test_e2_a_refused_start_returns_its_reason_in_words_and_raises_nothing(step, exc, words):
    system = System()
    platform = "linux"
    if step == "platform":
        platform = "win32"
    elif step == "answer":
        system.answer = exc
    elif step == "silence":
        system.answer = None
    elif step == "recv":
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
    assert r.stop() == [] and r.start().startswith("this reader was started once already")
    assert system.made == ([] if step == "platform" else [(16, socket.SOCK_DGRAM, 11)])


def test_e2_an_interrupt_in_the_start_closes_the_socket_and_goes_up():
    system = System()
    system.fail["bind"] = KeyboardInterrupt()
    r = reader(system)
    with pytest.raises(KeyboardInterrupt):
        r.start()
    assert system.socks[0].closed and r._atexit.registered == [] and r.stop() == []


def test_e2_what_comes_before_the_answer_is_taken_and_a_setsockopt_refused_is_said():
    system = System()
    system.fail["setsockopt"] = OSError(errno.EPERM, "no")
    system.proc(5001, "/usr/bin/git", 4000, 9)
    system.before = [fork(4000, 5001), OSError(errno.ENOBUFS, "No buffer space available"), exec_(5001)]
    r = started(system)
    assert [p["exe"] for p in r.read()["processes"]] == ["/usr/bin/git"]
    c = r.counts()
    assert c["lost"]["count"] == 1 and c["said"] == ["the socket's receive queue is left at the system's size (EPERM)"]


def test_e2_at_an_exec_it_reads_the_exe_link_and_the_stat_and_nothing_else_and_nothing_at_fork_or_exit():
    system = System()
    system.proc(5001, "/usr/bin/wget", 3999, 777)
    r = started(system)
    feed(r, fork(4000, 5001))
    assert system.asked == []
    feed(r, exec_(5001))
    assert system.asked == ["/proc/5001/exe", "/proc/5001/stat"]
    feed(r, exit_(5001))
    assert system.asked == ["/proc/5001/exe", "/proc/5001/stat"]
    p = r.read()["processes"][0]
    assert p["ppid"] == 4000 and p["started_ticks"] == 777 and p["exe"] == "/usr/bin/wget"   # the fork's parent
    for word in ("/cmdline", "/environ", "/cwd", "/fd", "/maps", "/status", "/root", "/mem", "/io"):
        assert word not in SOURCE, word


def test_e2_read_gives_what_began_since_the_read_before_and_a_later_read_gives_its_end():
    system = System()
    system.proc(5001, "/usr/bin/nc", 4000, 5)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    first = r.read()["processes"]
    assert [(p["pid"], p["exe"], p["ended"], p["code"]) for p in first] == [(5001, "/usr/bin/nc", None, None)]
    assert r.read() == {"processes": [], "ends": [], "older": []}
    feed(r, exit_(5001, code=1 << 8))
    assert r.read() == {"processes": [], "older": [], "ends": [{"pid": 5001, "started_ticks": 5,
                                                                 "ended": text_of(WALL - 0.25), "code": 1,
                                                                 "signal": None, "unread": {}}]}
    feed(r, fork(4000, 5005), exit_(5005, code=9))      # killed by SIGKILL; the parent's signal 17 is not kept
    p = r.read()["processes"][0]
    assert (p["code"], p["signal"]) == (None, 9)
    assert procevents.wait_status(0x89) == (None, 9) and procevents.wait_status(0x200) == (2, None)
    c = r.counts()
    assert set(c) == {"since", "events", "given", "missed", "unread", "threads", "older", "lost", "beyond", "live",
                      "refused", "ended", "said"}
    assert c["given"] == 2 and c["since"] == text_of(WALL) and c["live"] == 0 and c["refused"] is None


def test_e2_the_times_are_the_kernels_stamps_on_the_wall_clock():
    system = System()
    r = started(system)
    feed(r, fork(1, 6000, ts=MONO - 1_500_000_000), exit_(6000, ts=MONO - 500_000))
    p = r.read()["processes"][0]
    assert p["began"] == text_of(WALL - 1.5) and p["ended"] == text_of(WALL - 0.0005)


def test_e2_stop_ends_the_thread_and_closes_the_socket_and_twice_does_nothing():
    system = System()
    system.wait = True
    clock = Clock()
    r = procevents.Reader(pid=PID, sockets=system.socket, readlink=system.readlink, read_bytes=system.read_bytes,
                          clock=clock.wall, mono=clock.mono, at_exit=Registry(), platform="linux")
    assert r.start() is None and r._thread.is_alive() and r._thread.daemon
    system.socks[0].inbox.append(fork(4000, 5001))
    end = time.monotonic() + 5
    while not r.counts()["events"]["fork"] and time.monotonic() < end:
        time.sleep(0.01)
    thread = r._thread
    assert r.stop() == [] and not thread.is_alive() and system.socks[0].closed
    assert r.stop() == [] and system.socks[0].sent == [asked(1), asked(2)]
    assert [p["pid"] for p in r.read()["processes"]] == [5001]   # what was heard is still read after the stop


def test_e2_the_reader_is_a_context_manager_and_stops_on_an_exception():
    system = System()
    with pytest.raises(ValueError):
        with reader(system) as r:
            assert r._state == "running"
            raise ValueError("inside")
    assert r._state == "stopped" and system.socks[0].closed and r._atexit.registered == []


def test_e2_a_reader_started_and_never_stopped_is_stopped_at_the_interpreters_exit():
    system = System()
    r = started(system)
    assert len(r._atexit.registered) == 1
    r._atexit.registered[0]()                      # what the interpreter runs at its exit
    assert r._state == "stopped" and system.socks[0].closed and r._atexit.registered == []
    r2 = started(System())
    assert r2.stop() == [] and r2._atexit.registered == []
    assert procevents.Reader(PID)._atexit is atexit


def test_e2_a_thread_that_ends_before_the_stop_is_said_and_the_stops_problems_are_said():
    system = System()
    r = started(system)
    system.socks[0].inbox.append(OSError(errno.EBADF, "Bad file descriptor"))
    assert r._once() is False
    assert r.counts()["ended"] == ("the reader's thread ended before the stop (its receive failed: EBADF): from then"
                                   " on nothing is heard")
    system.fail["send again"] = OSError(errno.ENOBUFS, "no")
    system.fail["close"] = OSError(errno.EIO, "io")
    assert r.stop() == ["the ask to stop listening failed (ENOBUFS)", "the socket could not be closed (OSError: [Errno"
                        " %d] io)" % errno.EIO]
    assert r.stop() == [] and r._atexit.registered == []


# --- E3: everything of the system through arguments; the one real test --------------------------------------------
def test_e3_a_whole_run_touches_nothing_of_the_real_system(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the real system was touched: %r" % (a,))
    for owner, name in ((socket, "socket"), (os, "readlink"), (builtins, "open"), (time, "time"),
                        (time, "monotonic_ns"), (time, "monotonic"), (atexit, "register")):
        monkeypatch.setattr(owner, name, boom)
    system = System()
    system.proc(5001, "/usr/bin/sh", 4000, 1)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), exit_(5001))
    assert r.read()["processes"][0]["exe"] == "/usr/bin/sh" and r.stop() == []


LINUX = sys.platform.startswith("linux")


@pytest.mark.skipif(not LINUX, reason="the kernel's process events are Linux's")
def test_e3_the_real_kernel_tells_a_child_of_its_own_with_its_program_and_its_exit_code():
    true = os.path.realpath(shutil.which("true") or "/bin/true")
    r = procevents.Reader()
    why = r.start()
    if why:
        r.stop()
        pytest.skip("the kernel refused here: %s" % why)
    try:
        time.sleep(0.2)                            # the reader's thread waits in its receive
        heard, read = {}, []
        for _ in range(5):                         # the read of the program is a race with the child's end
            child = subprocess.Popen(["true"])
            child.wait()
            end = time.monotonic() + 5
            while heard.get(child.pid, {}).get("ended") is None and time.monotonic() < end:
                got = r.read()                     # a process is given again at its exec, its end later in ends
                for p in got["processes"]:
                    heard[p["pid"]] = p
                for e in got["ends"]:
                    if e["pid"] in heard:
                        heard[e["pid"]].update(ended=e["ended"], code=e["code"], signal=e["signal"])
                time.sleep(0.02)
            p = heard.get(child.pid)
            assert p is not None, ("the child was not heard", r.counts())
            assert p["code"] == 0 and p["signal"] is None and p["ppid"] == os.getpid(), p
            read.append(p)
            if p["exe"] == true:
                break
        assert read[-1]["exe"] == true, (read, r.counts())
        c = r.counts()
        assert c["lost"]["count"] == 0 and c["beyond"] == 0 and c["ended"] is None and c["refused"] is None
    finally:
        assert r.stop() == []


# --- E4: the standard library alone, AF_NETLINK alone, no program, no file, imported by nothing yet --------------
def _imports(source):
    tree = ast.parse(source)
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add(("." * n.level) + (n.module or ""))
    return tree, mods


def test_e4_the_standard_library_alone_no_program_and_no_file_written():
    tree, mods = _imports(SOURCE)
    assert mods == {"__future__", "atexit", "datetime", "errno", "os", "socket", "struct", "sys", "threading",
                    "time"}
    assert mods - {"__future__"} <= set(sys.stdlib_module_names)
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


def test_e4_no_socket_but_af_netlink_is_opened(monkeypatch):
    families = []

    class Only:
        def __init__(self, family, type_, proto):
            families.append((family, type_, proto))
            if family != 16:
                raise AssertionError("a socket of another family: %r" % family)
            self.inner = System().socket(family, type_, proto)

        def __getattr__(self, name):
            return getattr(self.inner, name)
    monkeypatch.setattr(socket, "socket", Only)
    clock = Clock()
    r = procevents.Reader(pid=PID, clock=clock.wall, mono=clock.mono, thread=NoThread, at_exit=Registry(),
                          platform="linux")
    assert r.start() is None and r.stop() == []
    assert families == [(16, socket.SOCK_DGRAM, 11)]


def test_e4_nothing_in_raqib_imports_the_reader_yet():
    users = [p.relative_to(ROOT).as_posix() for p in (ROOT / "raqib").rglob("*.py")
             if p.name != "procevents.py" and "procevents" in p.read_text(encoding="utf-8")]
    assert users == []


# --- E5: losses are said, never smoothed --------------------------------------------------------------------------
def test_e5_enobufs_between_two_datagrams_is_counted_lost_with_why_and_both_are_read():
    system = System()
    system.proc(5001, "/usr/bin/touch", 4000, 1)
    system.proc(5002, "/usr/bin/rm", 4000, 2)
    r = started(system)
    feed(r, fork(4000, 5001) + exec_(5001), OSError(errno.ENOBUFS, "No buffer space available"),
         fork(4000, 5002) + exec_(5002))
    assert [p["exe"] for p in r.read()["processes"]] == ["/usr/bin/touch", "/usr/bin/rm"]
    lost = r.counts()["lost"]
    assert lost["count"] == 1 and "ENOBUFS" in lost["why"] and "how many is not known" in lost["why"]
    assert r.counts()["ended"] is None


def test_e5_a_process_whose_reads_fail_is_given_with_what_was_read_and_unread_naming_the_rest():
    system = System()
    system.stats[5001] = stat_line(5001, 4000, 42)          # a zombie: its stat is there, its exe link is not
    system.links[5002] = "/usr/bin/shred"
    system.stats[5002] = PermissionError(errno.EACCES, "Permission denied")
    system.links[5003] = "/usr/bin/cp"
    system.stats[5003] = b"5003 (cp) S"                        # a stat that cannot be read
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), fork(4000, 5002), exec_(5002), exec_(5003))
    a, b, c = r.read()["processes"]
    assert a["exe"] is None and a["started_ticks"] == 42
    assert a["unread"] == {"exe": "not read at its exec (ENOENT: gone before the read)"}
    assert b["exe"] == "/usr/bin/shred" and b["unread"] == {"started_ticks": "not read at its exec (EACCES: not this"
                                                                              " user's to read)"}
    assert c["ppid"] is None and c["began"] is None and set(c["unread"]) == {"began", "started_ticks", "ppid"}
    assert c["unread"]["started_ticks"] == "not read at its exec (ValueError)"
    assert r.counts()["missed"] == {"exe": 1, "stat": 2}


def test_e5_an_exit_with_no_exec_heard_is_a_process_older_than_the_reader_said_in_older():
    system = System()
    r = started(system)
    feed(r, exit_(3000, code=3 << 8))
    assert r.read() == {"processes": [], "ends": [], "older": [
        {"pid": 3000, "started_ticks": None, "ended": text_of(WALL - 0.25), "code": 3, "signal": None,
         "unread": {"began": procevents.NO_FORK}}]}
    assert r.counts()["older"] == 1 and r.read()["older"] == []


def test_e5_a_second_exec_of_one_process_gives_the_program_it_became():
    system = System()
    system.proc(5001, "/usr/bin/dash", 4000, 8)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001))
    system.links[5001] = "/usr/bin/curl"
    feed(r, exec_(5001))
    got = r.read()["processes"]
    assert [(p["pid"], p["exe"]) for p in got] == [(5001, "/usr/bin/curl")]
    system.links[5001] = "/usr/bin/git"                      # given before, and it changes its program again
    feed(r, exec_(5001), exit_(5001))
    again = r.read()
    assert [(p["pid"], p["exe"], p["code"], p["began"]) for p in again["processes"]] == [
        (5001, "/usr/bin/git", 0, got[0]["began"])] and again["ends"] == []
    assert r.counts()["given"] == 2 and r.counts()["events"]["exec"] == 3


def test_e5_a_fork_with_no_exec_is_given_by_its_fork_with_its_parents_program_unread():
    system = System()
    r = started(system)
    feed(r, fork(4000, 5001))
    p = r.read()["processes"][0]
    assert (p["pid"], p["ppid"], p["exe"], p["began"], p["started_ticks"]) == (5001, 4000, None,
                                                                             text_of(WALL - 0.25), None)
    assert p["unread"] == {"exe": procevents.NO_EXEC_EXE, "started_ticks": procevents.NO_EXEC_STAT}
    assert "its parent's" in procevents.NO_EXEC_EXE and system.asked == []


def test_e5_a_pid_reused_within_one_read_is_two_processes_and_a_lost_end_is_said():
    system = System()
    system.proc(5001, "/usr/bin/mv", 4000, 10)
    r = started(system)
    feed(r, fork(4000, 5001), exec_(5001), exit_(5001))
    system.proc(5001, "/usr/bin/getent", 4100, 20)
    feed(r, fork(4100, 5001), exec_(5001), exit_(5001, code=2 << 8))
    got = r.read()["processes"]
    assert [(p["pid"], p["ppid"], p["exe"], p["started_ticks"], p["code"]) for p in got] == [
        (5001, 4000, "/usr/bin/mv", 10, 0), (5001, 4100, "/usr/bin/getent", 20, 2)]
    # its end lost: the pid begins again; the first holder is said with its end unread, in the read and in `ends`
    system.proc(5002, "/usr/bin/sh", 4000, 30)
    feed(r, fork(4000, 5002), exec_(5002), fork(4000, 5002))
    a, b = r.read()["processes"]
    assert a["ended"] is None and a["unread"] == {"ended": procevents.NO_END} and b["unread"]["exe"]
    feed(r, fork(4000, 5003))
    r.read()
    feed(r, fork(4000, 5003))
    got = r.read()
    assert got["ends"] == [{"pid": 5003, "started_ticks": None, "ended": None, "code": None, "signal": None,
                            "unread": {"ended": procevents.NO_END}}] and len(got["processes"]) == 1


def test_e5_past_processes_max_is_counted_beyond_not_kept(monkeypatch):
    monkeypatch.setattr(procevents, "PROCESSES_MAX", 3)
    system = System()
    r = started(system)
    feed(r, *[fork(4000, 5000 + i) for i in range(5)])
    assert [p["pid"] for p in r.read()["processes"]] == [5000, 5001, 5002] and r.counts()["beyond"] == 2
    feed(r, *[exit_(6000 + i) for i in range(4)])      # ends of processes never heard to begin: kept to the bound
    assert len(r.read()["older"]) == 3 and r.counts()["beyond"] == 3 and r.counts()["older"] == 4


def test_e5_the_bound_is_a_constant_of_the_module():
    tree = ast.parse(SOURCE)
    consts = {t.id: n.value for n in tree.body if isinstance(n, ast.Assign) for t in n.targets
              if isinstance(t, ast.Name)}
    assert isinstance(consts["PROCESSES_MAX"], ast.Constant) and consts["PROCESSES_MAX"].value == 32768


# --- E7 and E8: the docs, ASCII ---------------------------------------------------------------------------------------
def flat(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def test_e7_the_spec_says_the_layout_what_is_read_every_count_and_what_was_not_measured():
    spec = flat("docs/specs/PROC-EVENTS.md")
    for sentence in (
            "a socket of AF_NETLINK, SOCK_DGRAM, protocol 11 (the connector), bound to the reader's pid and group 1",
            "Several messages may come in one datagram, each padded to 4 bytes.",
            "A thread (its tgid not its pid) is not a process: it is counted in `threads` and nothing else.",
            "At an exec the reader reads at once the link /proc/PID/exe (the program) and /proc/PID/stat (the parent"
            " and the start in clock ticks), and nothing else of the process.",
            "No argument, no environment, no working directory and no open file of a process is ever read, and"
            " nothing is read at a fork or an exit.",
            "Not measured: a kernel older than 6.8 (the connector may be root's there); whether a plain user hears"
            " another user's processes; a machine that starts thousands of processes a second; a process inside a"
            " container."):
        assert sentence in spec, sentence
    for key in ("since", "events", "given", "missed", "unread", "threads", "older", "lost", "beyond", "live",
                "refused", "ended", "said"):
        assert "- `%s`" % key in spec, key
    assert str(procevents.PROCESSES_MAX) in spec


def test_e7_the_threat_model_says_what_an_agent_can_do_about_this_source_without_a_milestone_token():
    import re
    text = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    start = text.index("- **The kernel's process events on Linux")
    section = " ".join(text[start:text.index("\n- **", start + 5)].split())
    for sentence in (
            "an agent that starts more processes between two reads than the reader's bound (32768) has the rest"
            " counted `beyond`, not kept",
            "a process that ends before its program is read is given without it: the read is counted in `missed`"
            " and named in its `unread`",
            "a kernel that refuses (an older one, or a container's) is the hole, said in the reader's words as"
            " `refused`, and nothing else is tried",
            "a burst the kernel cannot queue for the reader is counted in `lost` (ENOBUFS), never as nothing"
            " happened"):
        assert sentence in section, sentence
    assert not re.search(r"\bM\d+\.\d+", section)


def test_e8_ascii_outside_docs():
    for path in ("raqib/procevents.py", "tests/test_procevents.py"):
        assert (ROOT / path).read_bytes().isascii(), path
