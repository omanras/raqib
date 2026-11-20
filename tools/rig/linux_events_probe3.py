"""Probe only (never merged): three questions the second review of M14.1a asked of the kernel's process events.
C. In a quiet run, is the count the kernel puts on each event (its `seq`, one per CPU) without gaps?
D. When the listener's queue overflows: which events come before the error and after it (the ones queued first,
   or none), which are missing, and do the gaps in `seq` add up to what is missing?
E. When a thread that is not the leader calls exec, with every CPU busy: does the exit with pid equal to tgid
   always come before the exec, as it did once on a quiet machine?
Standard library only; run as a plain user. It prints what it heard and judges nothing."""
import collections
import os
import socket
import struct
import subprocess
import sys
import time

WHAT = {0x0: "answer", 0x1: "fork", 0x2: "exec", 0x80000000: "exit"}


def listen(rcvbuf=None):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 11)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.bind((0, 1))
    body = struct.pack("=IIIIHH", 1, 1, 0, 0, 4, 0) + struct.pack("=I", 1)
    s.send(struct.pack("=IHHII", 16 + len(body), 3, 0, 0, os.getpid()) + body)
    return s


def drain(s, quiet=1.0, limit=30.0):
    """Read until nothing came for `quiet` seconds: a list of ("ev", what, cpu, seq, a, b, extra) and
    ("error", errno) in the order they were read."""
    out = []
    s.settimeout(quiet)
    end = time.monotonic() + limit
    while time.monotonic() < end:
        try:
            data = s.recv(65536)
        except socket.timeout:
            break
        except OSError as exc:
            out.append(("error", exc.errno))
            continue
        at = 0
        while at + 16 <= len(data):
            length = struct.unpack_from("=I", data, at)[0]
            if length < 36:
                break
            seq = struct.unpack_from("=I", data, at + 16 + 8)[0]
            ev = data[at + 36:at + length]
            at += (length + 3) & ~3
            if len(ev) < 24:
                continue
            what, cpu = struct.unpack_from("=II", ev, 0)
            a, b = struct.unpack_from("=II", ev, 16)
            extra = struct.unpack_from("=II", ev, 24) if len(ev) >= 32 else None
            out.append(("ev", WHAT.get(what, hex(what)), cpu, seq, a, b, extra))
    return out


def gaps(items):
    """Per CPU: (events, the sum of the gaps in seq, how many times seq went back)."""
    last, total, back, n = {}, 0, 0, collections.Counter()
    for it in items:
        if it[0] != "ev" or it[1] == "answer":
            continue
        cpu, seq = it[2], it[3]
        n[cpu] += 1
        if cpu in last:
            step = seq - last[cpu]
            if step > 1:
                total += step - 1
            elif step < 1:
                back += 1
        last[cpu] = seq
    return dict(n), total, back


def part_c():
    print("=== C. a quiet run: is seq without gaps?", flush=True)
    s = listen(rcvbuf=1 << 20)
    time.sleep(0.3)
    drain(s, 0.3)
    for _ in range(300):
        subprocess.run(["true"])
    got = drain(s, 1.0)
    n, total, back = gaps(got)
    errors = [g for g in got if g[0] == "error"]
    print("events per CPU %s; sum of gaps in seq %d; seq went back %d time(s); errors %d" % (
        n, total, back, len(errors)), flush=True)
    s.close()


def part_d():
    print("=== D. an overflow: what comes before the error, what after, what is missing", flush=True)
    s = listen(rcvbuf=4608)
    print("queue got %d" % s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), flush=True)
    time.sleep(0.3)
    drain(s, 0.3)
    me = os.getpid()
    order = []
    for _ in range(300):   # not reading: the queue fills
        p = subprocess.Popen(["true"])
        order.append(p.pid)
        p.wait()
    got = drain(s, 1.0)
    number = {pid: i for i, pid in enumerate(order)}
    first_error = next((i for i, g in enumerate(got) if g[0] == "error"), None)
    before = got[:first_error] if first_error is not None else got
    after = got[first_error + 1:] if first_error is not None else []

    def children(items):
        return sorted({number[g[6][0]] for g in items if g[0] == "ev" and g[1] == "fork" and g[4] == me
                       and g[6] and g[6][0] in number})

    def spans(nums):
        out, start, prev = [], None, None
        for x in nums:
            if start is None:
                start = prev = x
            elif x == prev + 1:
                prev = x
            else:
                out.append((start, prev))
                start = prev = x
        if start is not None:
            out.append((start, prev))
        return out

    errors = [g for g in got if g[0] == "error"]
    print("read %d event(s) and %d error(s) %s; the first error came after %s event(s)" % (
        len([g for g in got if g[0] == "ev"]), len(errors), sorted({g[1] for g in errors}),
        first_error if first_error is not None else "no error at all:"), flush=True)
    b, a = children(before), children(after)
    print("of the 300 numbered children (0 the first made): forks read before the error %d, spans %s" % (
        len(b), spans(b)[:8]), flush=True)
    print("forks read after the error %d, spans %s" % (len(a), spans(a)[:8]), flush=True)
    heard = set(b) | set(a)
    print("children whose fork was never read: %d" % (300 - len(heard)), flush=True)
    n, total, back = gaps(got)
    print("events read per CPU %s; sum of gaps in seq %d; went back %d" % (n, total, back), flush=True)
    time.sleep(0.5)
    order2, got2 = [], []
    for _ in range(20):   # read after each one: the queue does not fill
        p = subprocess.Popen(["true"])
        order2.append(p.pid)
        p.wait()
        got2 += drain(s, 0.05, limit=2.0)
    got2 += drain(s, 0.5)
    forks2 = {g[6][0] for g in got2 if g[0] == "ev" and g[1] == "fork" and g[6]}
    print("then 20 more, read one by one: forks heard %d of 20, errors %d" % (
        len(forks2 & set(order2)), len([g for g in got2 if g[0] == "error"])), flush=True)
    n, total, back = gaps(got + got2)
    seen = len([g for g in got + got2 if g[0] == "ev" and g[1] != "answer"])
    print("over both reads: events read %d; sum of gaps in seq %d (the events the kernel counted and this"
          " listener never read); went back %d" % (seen, total, back), flush=True)
    s.close()


CHILD = "import os,threading,time\nthreading.Thread(target=lambda: os.execv('/bin/true',['true'])).start()\ntime.sleep(3)\n"
BUSY = "while True:\n    pass\n"


def part_e(runs=600, wide=8):
    print("=== E. a thread's exec with every CPU busy: which comes first", flush=True)
    cpus = os.cpu_count() or 1
    busy = [subprocess.Popen([sys.executable, "-S", "-c", BUSY]) for _ in range(cpus)]
    s = listen(rcvbuf=1 << 21)
    time.sleep(0.3)
    drain(s, 0.3)
    shapes = collections.Counter()
    lost = 0
    try:
        done = 0
        while done < runs:
            batch = [subprocess.Popen([sys.executable, "-S", "-c", CHILD]) for _ in range(wide)]
            pids = {p.pid for p in batch}
            for p in batch:
                try:
                    p.wait(20)
                except subprocess.TimeoutExpired:
                    p.kill()
            got = drain(s, 0.15, limit=5.0)
            lost += len([g for g in got if g[0] == "error"])
            per = collections.defaultdict(list)
            for g in got:
                if g[0] != "ev":
                    continue
                what, a, b, extra = g[1], g[4], g[5], g[6]
                if what == "fork" and extra and extra[1] in pids:      # a child's or a thread's fork: child tgid
                    per[extra[1]].append("F" if extra[0] == extra[1] else "t")
                elif what in ("exec", "exit") and b in pids:
                    letter = "X" if what == "exec" else "E"
                    code = extra[0] if (what == "exit" and extra) else None
                    per[b].append(letter if a == b else letter.lower())
                    if what == "exit" and a == b and code is not None:
                        per[b][-1] += "(%d)" % code
            for pid in pids:
                shapes[" ".join(per.get(pid, ["nothing"]))] += 1
            done += wide
    finally:
        for b in busy:
            b.kill()
    print("CPUs %d, runs %d, errors while reading %d" % (cpus, sum(shapes.values()), lost), flush=True)
    print("letters: F the process's fork, X an exec with pid = tgid, t a thread's fork, E(code) an exit with"
          " pid = tgid, e an exit of a thread, x an exec with pid != tgid", flush=True)
    for shape, n in shapes.most_common(12):
        print("  %5d  %s" % (n, shape), flush=True)
    s.close()


if __name__ == "__main__":
    print("kernel %s uid %d" % (os.uname().release, os.geteuid()), flush=True)
    part_c()
    part_d()
    part_e()
