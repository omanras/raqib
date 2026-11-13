"""Probe only (ADR-0007 BH-3, the shape that needs no evasion primitive): a talker started BESIDE the watch, as
another child of the watch's launcher. This program (python) starts `raqib watch --host` as its child, so it is
one of the watch's launchers; it also starts an agent-like talker (tools/rig/orphans.py --orphan) as another
child of its own, beside the watch. A watch that took for its own whatever stands under its launcher would list
neither; BH-3 lists the talker and keeps the watch's own tree to the watch's pid and its launchers.
The other BH-3 shape - a process that names the watch as its parent when it is created - is held by M7.27's unit
tests as process rows (test data), not by a working tool here: Raqib does not ship a parent-spoofing primitive.
Usage: python tools/rig/beside.py URL OUT WATCH_OUT   (writes "launcher/raqib/beside PID" lines to OUT)"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def main(argv):
    url, out, watch_out = argv[1], argv[2], argv[3]
    talker = [sys.executable, os.path.join(HERE, "orphans.py"), "--orphan", url]
    with open(watch_out, "w", encoding="utf-8") as w:
        watch = subprocess.Popen(["raqib", "watch", "--host", "--rounds", "10", "--every", "5", "--no-open"],
                                 stdout=w, stderr=subprocess.STDOUT)
        beside = subprocess.Popen(talker, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        with open(out, "w", encoding="ascii") as f:
            f.write("launcher %d\nraqib %d\nbeside %d\n" % (os.getpid(), watch.pid, beside.pid))
        try:
            watch.wait(timeout=180)
        finally:
            beside.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
