"""Probe only (never merged): the third review of M14.1a, H1. Does the kernel's answer to a listener's ask take a
number of the per-CPU count that events carry? One listener reads everything; children run; a second listener
asks to listen and to stop, three times; children run again. Printed: every answer as read (its cpu and seq), and
the per-CPU gaps counted two ways: answers left out of the count, and answers taken as part of it.
Standard library only; a plain user; it judges nothing."""
import os
import socket
import struct
import subprocess
import time


def listen(op=1, sock=None):
    s = sock or socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 11)
    if sock is None:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        s.bind((0, 1))
    body = struct.pack("=IIIIHH", 1, 1, 0, 0, 4, 0) + struct.pack("=I", op)
    s.send(struct.pack("=IHHII", 16 + len(body), 3, 0, 0, os.getpid()) + body)
    return s


def drain(s, quiet=0.5):
    out = []
    s.settimeout(quiet)
    while True:
        try:
            data = s.recv(65536)
        except socket.timeout:
            return out
        except OSError as exc:
            out.append(("error", exc.errno, 0, 0))
            continue
        at = 0
        while at + 16 <= len(data):
            length = struct.unpack_from("=I", data, at)[0]
            if length < 36:
                break
            seq, ack = struct.unpack_from("=II", data, at + 24)
            ev = data[at + 36:at + length]
            at += (length + 3) & ~3
            if len(ev) >= 8:
                what, cpu = struct.unpack_from("=II", ev, 0)
                out.append(("answer" if what == 0 else "event", cpu, seq, ack))


def gaps(items, with_answers):
    last, total = {}, 0
    for kind, cpu, seq, _ in items:
        if kind == "error" or (kind == "answer" and not with_answers):
            continue
        if cpu in last and seq - last[cpu] > 1:
            total += seq - last[cpu] - 1
        last[cpu] = seq
    return total


if __name__ == "__main__":
    print("kernel %s, CPUs %d" % (os.uname().release, os.cpu_count() or 0), flush=True)
    a = listen()
    time.sleep(0.3)
    got = drain(a, 0.3)
    print("the first listener's own answer: %s" % [g for g in got if g[0] == "answer"], flush=True)
    got = []
    for _ in range(40):
        subprocess.run(["true"])
    got += drain(a, 0.3)
    for turn in range(3):
        b = listen()
        time.sleep(0.1)
        listen(op=2, sock=b)      # the second listener stops listening
        time.sleep(0.1)
        b.close()
        for _ in range(10):
            subprocess.run(["true"])
        got += drain(a, 0.3)
    answers = [g for g in got if g[0] == "answer"]
    print("answers the first listener read while a second asked and stopped three times: %d" % len(answers), flush=True)
    for g in answers:
        print("   answer cpu %s seq %s ack %s" % (g[1], g[2], g[3]), flush=True)
    print("events read %d, errors %d" % (len([g for g in got if g[0] == "event"]), len([g for g in got if g[0] == "error"])),
          flush=True)
    print("sum of gaps per CPU, answers left out of the count: %d" % gaps(got, False), flush=True)
    print("sum of gaps per CPU, answers taken as part of it:   %d" % gaps(got, True), flush=True)
