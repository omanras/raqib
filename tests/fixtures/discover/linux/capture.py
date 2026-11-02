"""Capture the REAL Linux fixtures of M5.0 with raqib's own live readers.

Run from the checkout on a Linux host, from inside the agent's shell (so
the tree has a child):
    python3 tests/fixtures/discover/linux/capture.py [--drop PID]...
It writes proc.txt, proc-net.txt, ss.txt and footprints.txt next to itself,
all from one moment. Identifiers are replaced by fixed placeholders (B-9):
the value after --session, any session token, any /tmp/claude-* path (the
builder's scratchpad and temp files) and the basename of a Claude Code
shell-snapshots/snapshot-* file (D-6). Environment NAMES stay; values are
read and dropped at once, never stored. A dropped pid (e.g. a process whose
argv holds a whole script) is named in the snapshot note, with any socket
it held.
"""
import argparse
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(HERE)))))
from raqib import discover  # noqa: E402

SESSION = "cse_REDACTED"
SCRATCH = "/tmp/SCRATCHPAD"
SNAPSHOT = "shell-snapshots/snapshot-REDACTED.sh"
TOKEN = re.compile(r"\b(?:cse|session)_[A-Za-z0-9]{12,}\b")
SCRATCH_PATH = re.compile(r"/tmp/claude-[^\s\"']*")
SHELL_SNAPSHOT = re.compile(r"shell-snapshots/snapshot-[^/\s\"']+")


def redact(argv):
    out = []
    for i, arg in enumerate(argv or []):
        if i and argv[i - 1] == "--session":
            arg = SESSION
        arg = SHELL_SNAPSHOT.sub(SNAPSHOT, SCRATCH_PATH.sub(SCRATCH, TOKEN.sub(SESSION, arg)))
        out.append(arg)
    return out if argv is not None else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--drop", type=int, action="append", default=[], help="pid to leave out")
    args = ap.parse_args()
    at = discover.iso(datetime.datetime.now(datetime.timezone.utc))
    proc_text = discover.snapshot_proc("/proc", at, os.getpid())
    net_text, net_error = discover.read_proc_net("/proc", at)
    if net_text is None:
        sys.exit("cannot capture /proc/net/tcp: %s" % net_error)
    ss_path = discover.find_ss()
    ss_text, ss_error = discover.run_ss(ss_path, ("-tnp",), at) if ss_path else (None, "no ss")
    if ss_text is None:
        sys.exit("cannot capture ss -tnp: %s" % ss_error)
    footprints = discover.scan_footprints(discover.default_homes("linux"), discover.load_catalog())

    lines = proc_text.splitlines()
    meta, procs = json.loads(lines[0]), [json.loads(x) for x in lines[1:]]
    dropped = [p for p in procs if p["pid"] in args.drop]
    kept = [dict(p, argv=redact(p["argv"]), cwd=SCRATCH_PATH.sub(SCRATCH, p["cwd"]) if p["cwd"] else p["cwd"])
            for p in procs if p["pid"] not in args.drop]
    held = sorted(i for p in dropped for i in p["sockets"] or [])
    meta["note"] = ("M5.0 fixture: %d of %d processes kept; dropped pids %s (sockets held: %s);"
                    " identifiers redacted: --session value -> %s, scratchpad paths -> %s,"
                    " shell snapshots -> %s"
                    % (len(kept), len(procs), ", ".join(str(p["pid"]) for p in dropped) or "none",
                       ", ".join(map(str, held)) or "none", SESSION, SCRATCH, SNAPSHOT))
    meta["processes"] = len(kept)
    head = "# M5.0 fixture, %s: tests/fixtures/discover/linux/capture.py in the builder's container (Claude Code on Linux), %s.\n"
    with open(os.path.join(HERE, "proc.txt"), "w", encoding="ascii", newline="\n") as f:
        f.write(head % ("REAL, identifiers redacted", at))
        f.write("# environ: variable NAMES only; values are never read into this text.\n")
        for x in [meta] + kept:
            f.write(json.dumps(x, sort_keys=True, ensure_ascii=True) + "\n")
    for name, text in (("proc-net.txt", net_text), ("ss.txt", ss_text), ("footprints.txt", footprints)):
        with open(os.path.join(HERE, name), "w", encoding="ascii", newline="\n") as f:
            f.write(head % ("REAL (not synthetic)", at))
            f.write(text)
    print("self %d; kept %s; dropped %s; sockets of dropped %s"
          % (os.getpid(), [p["pid"] for p in kept], [p["pid"] for p in dropped], held))


if __name__ == "__main__":
    main()
