"""Probe only (never merged): what Linux itself tells of what happens between two samples, read with the standard
library alone, as root: (1) the kernel's process events (the netlink connector: fork, exec, exit), (2) the
kernel's word at the end of every TCP socket (sock_diag's destroy group). While it listens it starts the acts an
agent's short children make (files, curl, wget, a name lookup, nc, Python's own client, shred, git), and then
says, for each, what was heard. `--listen N` only listens for N seconds and counts (for a run under a unit's
limits). It judges nothing; it prints."""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

NETLINK_CONNECTOR, NETLINK_SOCK_DIAG = 11, 4
CN_IDX_PROC, CN_VAL_PROC, PROC_CN_MCAST_LISTEN = 1, 1, 1
WHAT = {0x1: "fork", 0x2: "exec", 0x4: "uid", 0x40: "gid", 0x80: "sid", 0x100: "ptrace", 0x200: "comm",
        0x40000000: "coredump", 0x80000000: "exit"}
EVENTS, SOCKS, ERRORS = [], [], []
STOP = threading.Event()


def proc_listener():
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        s.bind((os.getpid(), CN_IDX_PROC))
        body = struct.pack("=IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, 4, 0) + struct.pack("=I", PROC_CN_MCAST_LISTEN)
        s.send(struct.pack("=IHHII", 16 + len(body), 3, 0, 0, os.getpid()) + body)
        s.settimeout(0.5)
    except OSError as exc:
        ERRORS.append("the process connector: %s: %s" % (type(exc).__name__, exc))
        return
    while not STOP.is_set():
        try:
            data = s.recv(65536)
        except socket.timeout:
            continue
        except OSError as exc:
            ERRORS.append("the process connector, reading: %s: %s" % (type(exc).__name__, exc))
            continue
        now = time.monotonic()
        at = 0
        while at + 16 <= len(data):
            length, kind, _, _, _ = struct.unpack_from("=IHHII", data, at)
            if length < 16:
                break
            ev = data[at + 16 + 20:at + length]
            at += (length + 3) & ~3
            if len(ev) < 24:
                continue
            what, _, _ = struct.unpack_from("=IIQ", ev, 0)
            name = WHAT.get(what, hex(what))
            rec = {"t": now, "what": name}
            if what == 0x1 and len(ev) >= 32:
                rec["ppid"], _, rec["pid"], rec["tgid"] = struct.unpack_from("=IIII", ev, 16)
            elif len(ev) >= 24:
                rec["pid"], rec["tgid"] = struct.unpack_from("=II", ev, 16)
            if what == 0x2:   # the program, read at once: is the process still there to be read?
                try:
                    rec["exe"] = os.readlink("/proc/%d/exe" % rec["pid"])
                except OSError as exc:
                    rec["exe_error"] = type(exc).__name__
                try:
                    with open("/proc/%d/stat" % rec["pid"], "rb") as f:
                        rec["ppid_read"] = int(f.read().rsplit(b")", 1)[1].split()[1])
                except (OSError, ValueError, IndexError) as exc:
                    rec["stat_error"] = type(exc).__name__
                rec["read_ms"] = round((time.monotonic() - now) * 1000, 2)
            if what == 0x80000000 and len(ev) >= 32:
                rec["code"], rec["signal"] = struct.unpack_from("=II", ev, 24)
            EVENTS.append(rec)


def sock_listener():
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
        s.bind((0, 1 | 4))   # the destroy groups of TCP over IPv4 (1) and IPv6 (3)
        s.settimeout(0.5)
    except OSError as exc:
        ERRORS.append("sock_diag's destroy groups: %s: %s" % (type(exc).__name__, exc))
        return
    while not STOP.is_set():
        try:
            data = s.recv(65536)
        except socket.timeout:
            continue
        except OSError as exc:
            ERRORS.append("sock_diag, reading: %s: %s" % (type(exc).__name__, exc))
            continue
        now = time.monotonic()
        at = 0
        while at + 16 <= len(data):
            length, kind, _, _, _ = struct.unpack_from("=IHHII", data, at)
            if length < 16:
                break
            msg = data[at + 16:at + length]
            at += (length + 3) & ~3
            if len(msg) < 72:
                continue
            family, state = msg[0], msg[1]
            sport, dport = struct.unpack_from("!HH", msg, 4)
            uid, inode = struct.unpack_from("=II", msg, 64)
            rec = {"t": now, "kind": kind, "family": family, "state": state, "sport": sport, "dport": dport,
                   "uid": uid, "inode": inode, "attrs": {}}
            pos = 72
            while pos + 4 <= len(msg):
                alen, atype = struct.unpack_from("=HH", msg, pos)
                if alen < 4:
                    break
                rec["attrs"][atype] = alen - 4
                if atype == 2 and alen - 4 >= 136:   # INET_DIAG_INFO: struct tcp_info; its two byte counts
                    info = msg[pos + 4:pos + alen]
                    rec["bytes_acked"], rec["bytes_received"] = struct.unpack_from("=QQ", info, 120)
                pos += (alen + 3) & ~3
            SOCKS.append(rec)


def run(argv, timeout=30):
    t0 = time.monotonic()
    try:
        child = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return {"argv": argv[0], "error": type(exc).__name__}
    try:
        child.wait(timeout)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
    return {"argv": argv[0], "pid": child.pid, "t0": t0, "t1": time.monotonic(), "rc": child.returncode}


def main():
    if "--listen" in sys.argv:
        seconds = float(sys.argv[sys.argv.index("--listen") + 1])
        threads = [threading.Thread(target=proc_listener, daemon=True), threading.Thread(target=sock_listener, daemon=True)]
        for t in threads:
            t.start()
        time.sleep(1)
        subprocess.run(["true"])
        time.sleep(seconds)
        STOP.set()
        print("LISTEN %g s as uid %d: %d process event(s), %d socket end(s); errors: %s" % (
            seconds, os.geteuid(), len(EVENTS), len(SOCKS), ERRORS or "none"), flush=True)
        return 0
    print("uid %d, kernel %s" % (os.geteuid(), os.uname().release), flush=True)
    threads = [threading.Thread(target=proc_listener, daemon=True), threading.Thread(target=sock_listener, daemon=True)]
    for t in threads:
        t.start()
    time.sleep(1)
    print("errors at the start: %s" % (ERRORS or "none"), flush=True)
    idle0, n0, s0 = time.monotonic(), len(EVENTS), len(SOCKS)
    time.sleep(10)
    idle = time.monotonic() - idle0
    print("idle: %.1f process event(s) a second, %.2f socket end(s) a second (over %.0f s)" % (
        (len(EVENTS) - n0) / idle, (len(SOCKS) - s0) / idle, idle), flush=True)
    work = tempfile.mkdtemp(prefix="raqib-probe-")
    a, b, c, d = (os.path.join(work, n) for n in ("a.txt", "b.txt", "c.txt", "d.txt"))
    w0 = time.monotonic()
    acts = [run(["touch", a]), run(["mv", a, b]), run(["cp", b, c]), run(["rm", b, c]),
            run(["curl", "-s", "-o", "/dev/null", "--max-time", "8", "https://example.com/"]),
            run(["curl", "-s", "-o", "/dev/null", "--max-time", "8", "https://www.python.org/"]),
            run(["curl", "-s", "-o", "/dev/null", "--max-time", "8", "https://github.com/"]),
            run(["wget", "-q", "-O", "/dev/null", "--timeout=8", "https://example.com/"]),
            run(["getent", "hosts", "example.org"]),
            run(["nc", "-z", "-w", "3", "example.com", "443"]),
            run([sys.executable, "-c",
                 "import urllib.request; urllib.request.urlopen('https://example.com/', timeout=8).read()"]),
            run(["sh", "-c", "echo x > '%s'" % d]), run(["shred", "-u", d]),
            run(["git", "ls-remote", "https://github.com/omanras/raqib", "HEAD"])]
    w1 = time.monotonic()
    time.sleep(3)
    STOP.set()
    time.sleep(1)
    print("the acts took %.1f s; heard %d process event(s) and %d socket end(s) in all; errors: %s" % (
        w1 - w0, len(EVENTS), len(SOCKS), ERRORS or "none"), flush=True)
    by_pid = {}
    for e in EVENTS:
        by_pid.setdefault(e.get("pid"), []).append(e)
    children = {}
    for e in EVENTS:
        if e["what"] == "fork":
            children.setdefault(e["ppid"], []).append(e["pid"])
    me = os.getpid()
    for act in acts:
        if "pid" not in act:
            print("ACT %-8s not run (%s)" % (act["argv"], act["error"]))
            continue
        evs = by_pid.get(act["pid"], [])
        execs = [e for e in evs if e["what"] == "exec"]
        exits = [e for e in evs if e["what"] == "exit"]
        forked = any(e["what"] == "fork" and e["pid"] == act["pid"] and e["ppid"] == me for e in EVENTS)
        first = execs[0] if execs else {}
        kids = children.get(act["pid"], [])
        kid_exes = [os.path.basename(x.get("exe", "?" + x.get("exe_error", ""))) for k in kids
                    for x in by_pid.get(k, []) if x["what"] == "exec"]
        ends = [s for s in SOCKS if act["t0"] - 0.05 <= s["t"] <= act["t1"] + 0.5]
        print("ACT %-8s pid %-6d lived %6.0f ms rc %s | fork heard: %s | exec heard: %d, program read: %s (%s ms), "
              "parent read: %s | exit heard: %s | its children's programs: %s | socket ends in its time: %s" % (
                  act["argv"], act["pid"], (act["t1"] - act["t0"]) * 1000, act["rc"], forked, len(execs),
                  os.path.basename(first["exe"]) if "exe" in first else first.get("exe_error", "-"),
                  first.get("read_ms", "-"), first.get("ppid_read", first.get("stat_error", "-")) == me,
                  ("code %s" % exits[0].get("code")) if exits else "no", kid_exes or "none",
                  [(s["dport"], "uid %d" % s["uid"], "inode %d" % s["inode"], "bytes %s/%s" % (s.get("bytes_acked"), s.get("bytes_received")))
                   for s in ends] or "none"))
    kinds = {}
    for e in EVENTS:
        kinds[e["what"]] = kinds.get(e["what"], 0) + 1
    print("process events by kind: %s" % kinds)
    missed = sum(1 for e in EVENTS if e["what"] == "exec" and "exe" not in e)
    print("exec events whose program could not be read in time: %d of %d" % (missed, kinds.get("exec", 0)))
    slow = sorted(e.get("read_ms", 0) for e in EVENTS if e["what"] == "exec")
    if slow:
        print("the read after an exec took: median %.2f ms, max %.2f ms" % (slow[len(slow) // 2], slow[-1]))
    attrs = {}
    for s in SOCKS:
        for k, v in s["attrs"].items():
            attrs[k] = max(attrs.get(k, 0), v)
    print("a socket end's attributes (type: longest length): %s; states seen: %s; message kinds: %s" % (
        attrs, sorted({s["state"] for s in SOCKS}), sorted({s["kind"] for s in SOCKS})))
    return 0


if __name__ == "__main__":
    sys.exit(main())
