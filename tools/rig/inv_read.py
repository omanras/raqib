"""Probe only: what the latest inventory and the first rounds of the record say of the reader itself - the
sources read (name, error, how much), what was incomplete, how many processes and connections, the candidates.
Reads ~/.raqib/host/inventory.json and rounds.jsonl. Usage: python tools/rig/inv_read.py"""
import json
import os
import sys


def brief(x, n=160):
    s = json.dumps(x, sort_keys=True, default=str)
    return s if len(s) <= n else s[:n] + "..."


def say(inv, label):
    if not isinstance(inv, dict):
        print("%s: not an object: %s" % (label, brief(inv)))
        return
    print("%s: keys %s" % (label, sorted(inv)))
    for k in ("platform", "window", "result", "summary", "self", "channel"):
        if k in inv:
            print("  %s: %s" % (k, brief(inv[k], 300)))
    for k in ("incomplete", "holes", "notes"):
        for item in inv.get(k) or ():
            print("  %s: %s" % (k, brief(item, 260)))
    for s in inv.get("sources") or ():
        print("  source: %s" % brief(s, 300))
    for k in ("processes", "connections", "candidates", "act_roots", "footprints", "trees"):
        v = inv.get(k)
        if isinstance(v, list):
            print("  %s: %d" % (k, len(v)))
            for item in v[:3] if k in ("candidates", "act_roots", "connections") else ():
                print("    %s" % brief(item, 260))


def main():
    base = os.path.join(os.path.expanduser("~"), ".raqib", "host")
    try:
        say(json.load(open(os.path.join(base, "inventory.json"), encoding="utf-8")), "inventory.json")
    except (OSError, ValueError) as exc:
        print("inventory.json: %s" % exc)
    rows = []
    try:
        for raw in open(os.path.join(base, "rounds.jsonl"), encoding="utf-8", errors="replace"):
            try:
                rows.append(json.loads(raw))
            except ValueError:
                pass
    except OSError as exc:
        print("rounds.jsonl: %s" % exc)
    print("rounds.jsonl: %d line(s)" % len(rows))
    tools = {}
    for r in rows:
        if isinstance(r, dict):
            tools[r.get("tool")] = tools.get(r.get("tool"), 0) + 1
    print("  tools: %s" % brief(tools, 400))
    shown = 0
    for r in rows:
        if isinstance(r, dict) and r.get("tool") in ("HostRound", "Round", "HostInventory") and shown < 2:
            shown += 1
            print("  first %s: %s" % (r.get("tool"), brief(r, 1500)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
