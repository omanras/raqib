"""Probe only (never merged): what the journal takes from a user's process by its native protocol."""
import json
import os
import socket
import struct
import subprocess
import sys
import time

PATH = "/run/systemd/journal/socket"
TAG = "raqib-probe-%d" % os.getpid()


def field(key, value):
    value = value if isinstance(value, bytes) else value.encode("utf-8")
    if b"\n" in value:
        return key.encode() + b"\n" + struct.pack("<Q", len(value)) + value + b"\n"
    return key.encode() + b"=" + value + b"\n"


def entry(message, n):
    return b"".join([field("MESSAGE", message), field("PRIORITY", "6"), field("SYSLOG_IDENTIFIER", TAG),
                     field("RAQIB_N", "%d" % n)])


def by_memfd(sock, data):
    fd = os.memfd_create("raqib-probe", os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, data)
        import fcntl
        fcntl.fcntl(fd, 1033, 0x0001 | 0x0002 | 0x0004 | 0x0008)   # F_ADD_SEALS: seal, shrink, grow, write
        import array
        sock.sendmsg([b""], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))], 0, PATH)
    finally:
        os.close(fd)


sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
print("sndbuf", sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
sizes = [20, 200000, 205000, 212000, 250000, 600000, 5000000]
for n, size in enumerate(sizes):
    data = entry("x" * size, n)
    try:
        sock.sendto(data, PATH)
        print("datagram", size, "sent")
    except OSError as exc:
        print("datagram", size, "refused", exc.errno, exc)
        try:
            by_memfd(sock, data)
            print("memfd", size, "sent")
        except OSError as exc2:
            print("memfd", size, "refused", exc2.errno, exc2)
sock.sendto(entry("two\nlines", 100), PATH)
sock.sendto(entry("{\"id\":\"r:1\",\"kind\":\"note\"}", 101), PATH)
# a burst: how many of 12000 the journal keeps
for i in range(40000):
    sock.sendto(entry("burst %d" % i, 1000 + i), PATH)
print("burst sent")
time.sleep(3)
subprocess.run(["journalctl", "--sync"], check=False)
for cmd in (["journalctl", "-t", TAG, "-o", "json", "--no-pager", "--all"],
            ["sudo", "journalctl", "-t", TAG, "-o", "json", "--no-pager", "--all"]):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rows = [json.loads(x) for x in p.stdout.decode("utf-8", "replace").splitlines() if x.startswith("{")]
    ns = [int(r["RAQIB_N"]) for r in rows if "RAQIB_N" in r]
    print(" ".join(cmd[:2]), "rows", len(rows), "first", ns[:10], "burst kept", len([n for n in ns if n >= 1000]),
          "in order", ns == sorted(ns), "err", p.stderr.decode()[:200])
    for r in rows:
        if r.get("RAQIB_N") in ("0", "100", "101"):
            print("  ", {k: (v if not isinstance(v, (str, list)) or len(v) < 80 else "len %d" % len(v))
                         for k, v in r.items() if k in ("MESSAGE", "PRIORITY", "SYSLOG_IDENTIFIER", "_PID", "_UID",
                                                        "_TRANSPORT", "_COMM", "RAQIB_N")})
    big = {r["RAQIB_N"]: (len(r["MESSAGE"]) if isinstance(r.get("MESSAGE"), (str, list)) else None) for r in rows
           if r.get("RAQIB_N") in tuple("%d" % i for i in range(len(sizes)))}
    print("  sizes kept", big)
p = subprocess.run(["sudo", "journalctl", "--no-pager", "-n", "400", "-o", "cat", "-u", "systemd-journald"],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print("journald says:", [x for x in p.stdout.decode("utf-8", "replace").splitlines() if "uppress" in x or "rate" in x.lower()][-5:])
p = subprocess.run(["systemd-analyze", "cat-config", "systemd/journald.conf"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print("conf:", [x for x in p.stdout.decode().splitlines() if x.strip() and not x.startswith("#")][:20])
