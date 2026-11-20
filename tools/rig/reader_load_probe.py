"""Probe only (never merged): how many programs the reader of M14.1a misses when the interpreter it shares is busy
(ADR-0007 BR-9), and whether a process of its own closes that. Four ways, each with the same 200 short children
(`true`, back to back): the reader's thread beside an idle main thread; beside a thread that never yields; beside
a thread busy half a second in every two; and the reader in a process of its own while this one is busy.
A plain user; the standard library and raqib.procevents; it prints counts and judges nothing."""
import json
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from raqib import procevents  # noqa: E402

N = 200
OWN = r'''
import json, sys, time
sys.path.insert(0, %r)
from raqib import procevents
r = procevents.Reader()
why = r.start()
print(json.dumps({"ready": why}), flush=True)
got = {}
sys.stdin.readline()
end = time.monotonic() + 3.0
while time.monotonic() < end:
    for p in r.read()["processes"]:
        got[p["pid"]] = p["exe"]
    time.sleep(0.1)
r.stop()
print(json.dumps({"got": got, "counts": r.counts()}), flush=True)
''' % ROOT


def spin(stop, duty=None):
    while not stop.is_set():
        if duty is None:
            x = 0
            for i in range(20000):
                x += i
        else:
            end = time.monotonic() + duty[0]
            while time.monotonic() < end:
                x = sum(range(2000))
            stop.wait(duty[1])


def children():
    pids = []
    for _ in range(N):
        p = subprocess.Popen(["true"])
        pids.append(p.pid)
        p.wait()
    return pids


def score(name, pids, got, counts):
    have = [pid for pid in pids if got.get(str(pid), got.get(pid))]
    seen = [pid for pid in pids if str(pid) in got or pid in got]
    print("%-46s heard %3d of %d, program read %3d, missed.exe %s, lost %s" % (
        name, len(seen), N, len(have), (counts.get("missed") or {}).get("exe"), (counts.get("lost") or {}).get("count")),
        flush=True)


def in_process(name, duty="idle"):
    r = procevents.Reader()
    why = r.start()
    if why is not None:
        print("%s: start refused: %s" % (name, why), flush=True)
        return
    stop = threading.Event()
    t = None
    if duty != "idle":
        t = threading.Thread(target=spin, args=(stop, duty), daemon=True)
        t.start()
    time.sleep(0.2)
    pids = children()
    got = {}
    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        for p in r.read()["processes"]:
            got[p["pid"]] = p["exe"]
        time.sleep(0.1)
    stop.set()
    r.stop()
    score(name, pids, got, r.counts())


def own_process(name):
    child = subprocess.Popen([sys.executable, "-c", OWN], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    ready = json.loads(child.stdout.readline())
    if ready.get("ready") is not None:
        print("%s: start refused: %s" % (name, ready["ready"]), flush=True)
        child.kill()
        return
    stop = threading.Event()
    t = threading.Thread(target=spin, args=(stop, None), daemon=True)
    t.start()
    time.sleep(0.2)
    pids = children()
    child.stdin.write("go\n")
    child.stdin.flush()
    out = json.loads(child.stdout.readline())
    stop.set()
    child.wait(10)
    score(name, pids, out["got"], out["counts"])


if __name__ == "__main__":
    print("kernel %s, CPUs %d, switch interval %s s" % (os.uname().release, os.cpu_count() or 0, sys.getswitchinterval()),
          flush=True)
    for turn in (1, 2, 3):
        print("--- turn %d" % turn, flush=True)
        in_process("reader's thread, main thread idle")
        in_process("reader's thread beside a thread that never yields", None)
        in_process("reader's thread beside a thread busy 0.5 s in 2 s", (0.5, 1.5))
        own_process("reader in a process of its own, this one busy")
