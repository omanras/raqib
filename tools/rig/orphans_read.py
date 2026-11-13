"""Probe only (ADR-0007 BE-4): was the watch given a dead parent's pid, and did it still see that parent's orphan?
Usage: python tools/rig/orphans_read.py PAIRS   (PAIRS: orphans.py's OUT; reads ~/.raqib/host/inventory.json)"""
import json
import os
import sys


def main(argv):
    pairs = [tuple(int(x) for x in line.split()) for line in open(argv[1], encoding="ascii") if line.strip()]
    inv = json.load(open(os.path.join(os.path.expanduser("~"), ".raqib", "host", "inventory.json"), encoding="utf-8"))
    own = set(inv.get("self") or ())
    seen = {c.get("pid") for c in inv.get("candidates") or ()}
    sampled = {p.get("pid") for p in inv.get("processes") or ()}
    orphans = {o for _, o in pairs}
    under_watch = [(d, o) for d, o in pairs if d in own]
    print("orphans made %d; alive in the sample %d; listed as candidates %d; the watch's own pids %s" % (
        len(pairs), len(orphans & sampled), len(orphans & seen), sorted(own)))
    if not under_watch:
        print("HIT: no - the watch was given no dead parent's pid this time (the run proves nothing of BE)")
    for d, o in under_watch:
        print("HIT: yes - the watch holds pid %d, the dead parent of orphan %d; that orphan is %s" % (
            d, o, "LISTED as a candidate" if o in seen else "NOT listed (alive in the sample: %s)" % (o in sampled)))
    alive_unseen = sorted((orphans & sampled) - seen)
    print("orphans alive and not listed: %s" % (alive_unseen[:20] or "none"))
    for h in inv.get("holes") or ():
        if "parent link" in str(h):
            print("hole: %s" % str(h)[:700])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
