"""Probe only (ADR-0007 BH-3): did the watch list the talker started beside it, and keep its own tree to the
reader and its launchers? Usage: python tools/rig/beside_read.py OUT  (OUT: beside.py's; reads rounds.jsonl,
inventory.json under ~/.raqib/host)."""
import json
import os
import sys


def walk(x, out):
    if isinstance(x, dict):
        if x.get("tool") == "HostTree" and isinstance(x.get("input_meta"), dict):
            out.append(x["input_meta"])
        for v in x.values():
            walk(v, out)
    elif isinstance(x, list):
        for v in x:
            walk(v, out)


def main(argv):
    base = os.path.join(os.path.expanduser("~"), ".raqib", "host")
    said = dict(line.split(" ", 1) for line in open(argv[1], encoding="ascii").read().splitlines() if " " in line)
    print("beside.py said: %s" % said)
    trees = []
    for raw in open(os.path.join(base, "rounds.jsonl"), encoding="utf-8", errors="replace"):
        try:
            walk(json.loads(raw), trees)
        except ValueError:
            pass
    try:
        pid = int(said.get("beside", ""))
    except ValueError:
        print("BESIDE: not started"); return 0
    mine = [m for m in trees if m.get("pid") == pid]
    print("BESIDE pid %d: %s" % (pid, ("LISTED in round(s) %s, class %s" % (
        sorted({m.get("round") for m in mine}), sorted({str(m.get("class")) for m in mine}))) if mine
        else "NOT LISTED in any round"))
    try:
        inv = json.load(open(os.path.join(base, "inventory.json"), encoding="utf-8"))
        print("the watch's own pids: %s" % inv.get("self"))
        for h in inv.get("holes") or ():
            if "did not start" in str(h) or "no record" in str(h) or "the watch started" in str(h):
                print("hole: %s" % str(h)[:500])
    except (OSError, ValueError) as exc:
        print("inventory not read: %s" % exc)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
