"""Probe only: the connection lines of the newest run (round, change, pid, remote, bytes), from ~/.raqib."""
import glob
import json
import os

rows = []
for path in glob.glob(os.path.join(os.path.expanduser("~"), ".raqib", "**", "*.jsonl"), recursive=True):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if '"HostConnection"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                m = d.get("input_meta") or {}
                rows.append((os.path.getmtime(path), path, m.get("round"), m.get("change"), m.get("pid"),
                             m.get("remote"), m.get("bytes")))
    except OSError:
        pass
newest = sorted({(t, p) for t, p, *_ in rows})[-3:]
for t, p in newest:
    print("file", os.path.basename(os.path.dirname(p)), os.path.basename(p))
    for _, q, rnd, change, pid, remote, b in rows:
        if q == p:
            print("  round %s %s pid %s %s bytes %s" % (rnd, change, pid, remote, json.dumps(b, sort_keys=True)))
