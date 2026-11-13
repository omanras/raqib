"""Probe only (ADR-0007 BE-4): the reader's own pids and the holes about parent links in the latest inventory.
Reads ~/.raqib/host/inventory.json. Prints one line. Usage: python tools/rig/link_holes.py"""
import json
import os
import sys


def main():
    path = os.path.join(os.path.expanduser("~"), ".raqib", "host", "inventory.json")
    try:
        inv = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("inventory not read: %s" % exc.__class__.__name__)
        return 0
    holes = [str(h) for h in inv.get("holes") or () if "parent link" in str(h)]
    print("self %s; candidates %d; processes %d; link holes: %s" % (
        inv.get("self"), len(inv.get("candidates") or ()), len(inv.get("processes") or ()),
        " || ".join(h[:260] for h in holes) or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
