"""Probe only (ADR-0007 BC-7): for every source file of the host watch, how many of its lines carry
input_meta.under_root, by the root's pid, and how many process lines it holds in all.
Reads ~/.raqib/host/sources/*.jsonl. Usage: python tools/rig/marks_read.py"""
import glob
import json
import os
import sys


def main():
    base = os.path.join(os.path.expanduser("~"), ".raqib", "host", "sources")
    for path in sorted(glob.glob(os.path.join(base, "*.jsonl"))):
        lines = marked = procs = marked_procs = 0
        roots = {}
        for raw in open(path, encoding="utf-8", errors="replace"):
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("phase") != "pre":
                continue
            lines += 1
            meta = rec.get("input_meta") if isinstance(rec.get("input_meta"), dict) else {}
            is_proc = rec.get("tool") == "process"
            procs += is_proc
            if "under_root" in meta:
                marked += 1
                marked_procs += is_proc
                roots[meta["under_root"]] = roots.get(meta["under_root"], 0) + 1
        print("%s: %d event(s), %d process; marked %d (%d process) by root %s" % (
            os.path.basename(path), lines, procs, marked, marked_procs, dict(sorted(roots.items(), key=str))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
