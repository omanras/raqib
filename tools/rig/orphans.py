"""Probe only (ADR-0007 BE-4): make orphans whose dead parents' pids are free again, so that the watch started
next is likely given one of them. Each orphan behaves as an agent does (it talks, then starts a child, again and
again) so that a watch that sees it lists it as a candidate.
Usage: python tools/rig/orphans.py N URL OUT      (writes "dead_parent_pid orphan_pid" lines to OUT)
       python tools/rig/orphans.py --mid URL OUT  (starts one orphan, writes the pair, ends at once)
       python tools/rig/orphans.py --orphan URL   (talks to URL and starts a child every 5 s for 100 s)"""
import os
import subprocess
import sys
import time
import urllib.request


def orphan(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    end = time.monotonic() + 100
    while time.monotonic() < end:
        try:
            with opener.open(urllib.request.Request(url, headers={"Connection": "close"}), timeout=5) as r:
                r.read()
        except OSError:
            pass
        subprocess.run(["cmd", "/c", "ver"] if os.name == "nt" else ["true"], capture_output=True)
        time.sleep(5)
    return 0


def mid(url, out):
    flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0   # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    child = subprocess.Popen([sys.executable, os.path.abspath(__file__), "--orphan", url], creationflags=flags,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(out, "a", encoding="ascii") as f:
        f.write("%d %d\n" % (os.getpid(), child.pid))
    return 0


def main(argv):
    if argv[1] == "--orphan":
        return orphan(argv[2])
    if argv[1] == "--mid":
        return mid(argv[2], argv[3])
    n, url, out = int(argv[1]), argv[2], argv[3]
    open(out, "w", encoding="ascii").close()
    for _ in range(n):
        subprocess.run([sys.executable, os.path.abspath(__file__), "--mid", url, out])
    print("orphans: %d made" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
