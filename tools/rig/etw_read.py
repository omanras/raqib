"""The field check of the tracing reader (ADR-0007 Amendments BK, BL; M7.21a): on Windows, run as an
administrator, it stops the leftovers of killed watches (sessions raqib-net-<n> whose n is no live pid, the live
pids read by raqib/hostwin.py's process snapshot), starts raqib/etwnet.py's Reader for SECONDS, and prints what
it read:

    python tools/rig/etw_read.py SECONDS

one line per connection: pid=, local=ADDR:PORT (this host's side), remote=ADDR:PORT, sent=, received=, last=
(the time of the connection's last event); a line `said: ...` for each problem (a leftover not stopped, the
consumer ended early, a loss not known, the unread events by their reason); and a last line `since=... unread=N
lost=events:N,buffers:N leftovers=NAMES`; or, where the system refused the session, a last line `refused:
<the reason>; leftovers stopped: NAMES`. Exit 0 read, 3 refused or not Windows, 2 its own usage. Stdlib and
raqib only; nothing on any network; it asks for no elevation (BL-3).
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
from raqib import etwnet  # noqa: E402

USAGE = "usage: python tools/rig/etw_read.py SECONDS"


def live_pids():
    """(the live pids of one process snapshot, None) or (None, why): a list that may be partial is not used,
    so no live watch's session is ever taken for a leftover."""
    try:
        from raqib import hostwin
        rows, error = hostwin.read_processes(hostwin.Api())
    except Exception as exc:
        return None, "the live pids were not read (%s: %s)" % (type(exc).__name__, exc)
    if error:
        return None, "the live pids were not all read (%s)" % error
    return {pid for pid, _, _ in rows}, None


def endpoint(addr, port):
    return ("[%s]:%d" if ":" in addr else "%s:%d") % (addr, port)


def names(stopped):
    return ",".join(stopped) or "none"


def main(argv=None, platform=None, api=None, alive=None, wait=None, out=None, pid=None):
    argv = sys.argv[1:] if argv is None else argv
    out = out or sys.stdout
    platform = sys.platform if platform is None else platform
    try:
        seconds = float(argv[0]) if len(argv) == 1 else -1.0
    except ValueError:
        seconds = -1.0
    if not seconds >= 0:
        sys.stderr.write(USAGE + "\n")
        return 2
    if platform != "win32":
        out.write("not Windows (%s): the kernel's tracing is read on Windows only; nothing was read\n" % platform)
        return 3
    if api is None:
        try:
            api = etwnet.Api()
        except (OSError, AttributeError) as exc:
            out.write("refused: the tracing API cannot be loaded (%s: %s); leftovers stopped: none\n"
                      % (type(exc).__name__, exc))
            return 3
    problems = []
    if alive is None:
        alive, why = live_pids()
        if why:
            problems.append(why)
    stopped = etwnet.leftovers(alive, api, problems)
    reader = etwnet.Reader(os.getpid() if pid is None else pid, api)
    with reader:
        if reader.refused:
            for p in problems:
                out.write("said: %s\n" % p)
            out.write("refused: %s; leftovers stopped: %s\n" % (reader.refused, names(stopped)))
            return 3
        (wait or time.sleep)(seconds)
        got = reader.counts()
    problems += reader.stop_problems
    for key in sorted(got["connections"]):
        pid_, laddr, lport, raddr, rport = key
        c = got["connections"][key]
        out.write("pid=%d local=%s remote=%s sent=%d received=%d last=%s\n"
                  % (pid_, endpoint(laddr, lport), endpoint(raddr, rport), c["sent"], c["received"], c["last"]))
    lost = got["lost"]
    if lost["why"]:
        problems.append("lost: %s" % lost["why"])
    if got["ended"]:
        problems.append(got["ended"])
    for why, n in sorted(got["unread_why"].items()):
        problems.append("unread: %d event(s): %s" % (n, why))
    if got["other"]:
        problems.append("%d event(s) of another provider (the trace's own header among them)" % got["other"])
    for p in problems:
        out.write("said: %s\n" % p)
    shown = "unknown" if lost["why"] else "events:%d,buffers:%d" % (lost["events"], lost["buffers"])
    out.write("since=%s unread=%d lost=%s leftovers=%s\n" % (got["since"], got["unread"], shown, names(stopped)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
