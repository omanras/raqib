"""Probe only (never merged): two questions the review of M14.1a asked of the kernel's process events.
A. After the listener's queue overflowed (ENOBUFS), do events still come - when this is the only listener?
B. What does the kernel send when a thread that is not the leader calls exec, and when the leader thread ends
   while another thread lives on?
Standard library only; run as a plain user. It prints what it heard and judges nothing."""
import os
import socket
import struct
import subprocess
import sys
import threading
import time

WHAT = {0x0: "answer", 0x1: "fork", 0x2: "exec", 0x4: "uid", 0x40: "gid", 0x80: "sid", 0x100: "ptrace",
        0x200: "comm", 0x40000000: "coredump", 0x80000000: "exit"}


def listen(rcvbuf=None):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 11)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.bind((0, 1))
    body = struct.pack("=IIIIHH", 1, 1, 0, 0, 4, 0) + struct.pack("=I", 1)
    s.send(struct.pack("=IHHII", 16 + len(body), 3, 0, 0, os.getpid()) + body)
    return s


def drain(s, seconds):
    """Read for `seconds`: (events as (what, pid, tgid, extra), the number of ENOBUFS)."""
    out, lost = [], 0
    end = time.monotonic() + seconds
    s.settimeout(0.2)
    while time.monotonic() < end:
        try:
            data = s.recv(65536)
        except socket.timeout:
            continue
        except OSError as exc:
            lost += 1
            out.append(("ERROR %s" % type(exc).__name__, getattr(exc, "errno", None), 0, None))
            continue
        at = 0
        while at + 16 <= len(data):
            length = struct.unpack_from("=I", data, at)[0]
            if length < 16:
                break
            ev = data[at + 36:at + length]
            at += (length + 3) & ~3
            if len(ev) < 24:
                continue
            what = struct.unpack_from("=I", ev, 0)[0]
            a, b = struct.unpack_from("=II", ev, 16)
            extra = struct.unpack_from("=II", ev, 24) if len(ev) >= 32 else None
            out.append((WHAT.get(what, hex(what)), a, b, extra))
    return out, lost


def part_a():
    print("=== A. after an overflow, alone", flush=True)
    s = listen(rcvbuf=2304)
    print("queue asked 2304, got %d" % s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), flush=True)
    time.sleep(0.5)
    got, lost = drain(s, 1.0)
    print("before: %d event(s), %d error(s)" % (len(got), lost), flush=True)
    for _ in range(400):   # not reading: the queue fills
        subprocess.run(["true"])
    got, lost = drain(s, 2.0)
    errors = [g for g in got if g[0].startswith("ERROR")]
    print("after 400 children unread: %d event(s) read, errors %s" % (len(got) - len(errors), errors[:3]), flush=True)
    marks = []
    for _ in range(5):
        marks.append(subprocess.Popen(["true"]).pid)
        subprocess.run(["sleep", "0.2"])
    got, lost = drain(s, 2.0)
    heard = sorted({g[1] for g in got if g[0] in ("exec", "exit")} & set(marks))
    print("then 5 marked children: heard %d of 5 (events %d, errors %d)" % (len(heard), len(got), lost), flush=True)
    time.sleep(1.5)
    pid = subprocess.Popen(["true"]).pid
    got, lost = drain(s, 2.0)
    print("and one more, later: heard %s" % (pid in {g[1] for g in got if g[0] in ("exec", "exit")}), flush=True)
    s2 = listen()
    time.sleep(0.3)
    pid = subprocess.Popen(["true"]).pid
    got2, _ = drain(s2, 1.5)
    got1, _ = drain(s, 0.5)
    print("a second listener, opened after: it heard the next child: %s; the first heard it: %s" % (
        pid in {g[1] for g in got2 if g[0] in ("exec", "exit")}, pid in {g[1] for g in got1 if g[0] in ("exec", "exit")}),
        flush=True)
    s.close()
    s2.close()


CHILD_THREAD_EXEC = r'''
import os, threading, time
print("CHILD thread-exec pid", os.getpid(), flush=True)
def go():
    time.sleep(0.3)
    os.execv("/bin/true", ["true"])
threading.Thread(target=go).start()
time.sleep(5)
'''
CHILD_LEADER_ENDS = r'''
import ctypes, os, threading, time
print("CHILD leader-ends pid", os.getpid(), flush=True)
def stay():
    time.sleep(1.5)
    os._exit(7)
threading.Thread(target=stay).start()
time.sleep(0.3)
ctypes.CDLL(None).pthread_exit(None)
'''


def part_b():
    print("=== B. threads", flush=True)
    for name, code in (("a thread that is not the leader calls exec", CHILD_THREAD_EXEC),
                       ("the leader thread ends, another thread lives on and ends the process with 7", CHILD_LEADER_ENDS)):
        s = listen()
        time.sleep(0.3)
        child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
        pid = child.pid
        got, _ = drain(s, 4.0)
        try:
            child.wait(5)
        except subprocess.TimeoutExpired:
            child.kill()
        print("--- %s: child pid %d, its return code %s" % (name, pid, child.returncode), flush=True)
        for what, a, b, extra in got:
            if b == pid or a == pid or (what == "fork" and extra and pid in extra):
                print("    %-6s pid %d tgid %d %s%s" % (what, a, b, "" if extra is None else "more %s" % (extra,),
                                                          "   <- a thread" if a != b and what != "fork" else ""), flush=True)
        s.close()


if __name__ == "__main__":
    print("kernel %s uid %d" % (os.uname().release, os.geteuid()), flush=True)
    part_a()
    part_b()
