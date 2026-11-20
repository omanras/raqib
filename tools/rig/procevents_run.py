"""The rig's run of the reader of Linux's process events (ADR-0007 Amendment BQ, BQ-2): on Linux, as the user that
runs it (the watch's own: no right is asked, nothing is run as root), it starts raqib.procevents.Reader, runs the
short acts the Table's probe ran - touch, mv, cp, rm, three curls, wget, getent, nc, Python's own client, sh, shred,
git (and its child) - against this machine alone (a stand-in HTTP server on loopback, a name lookup of localhost),
and writes what read() gave for each as JSON for tools/rig/check.py, which states X31. It judges nothing itself.

    python tools/rig/procevents_run.py --out FACTS.json

An act whose program is not installed is said as not run. Off Linux nothing is run, and the reason is the fact; a
start the kernel refuses is the fact, in the reader's words. For every act that ran: its pid, its exit code as the
run saw it (subprocess's own: negative for a signal), the program it is (the real path of the program the run
started) and the process read() gave for its pid, with the end a later read gave in `ends`; the programs of its
children as read() gave them. The reader's counts and its stop's problems are kept too. The run's own thread does
nothing between two acts, as the probe's did (the reader's thread shares the interpreter with it); read() is asked
after the last act until every act's end is heard or READ_S passed.

It never raises: an error is a fact; it writes its facts and exits 0 whatever happened (2 only for its own usage).
The standard library and raqib.procevents only. A test hands in its own reader, runner, `which`, server and clock.
"""
import argparse
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from raqib import procevents  # noqa: E402

ACT_TIMEOUT_S = 30
READ_S = 5.0          # after the last act: how long the reader is asked again for the acts' ends
POLL_S = 0.1
PROXIES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


class Quiet(http.server.BaseHTTPRequestHandler):
    """The stand-in server: "ok" at /, 404 elsewhere; it logs nothing."""

    def do_GET(self):
        body = b"ok\n"
        self.send_response(200 if self.path == "/" else 404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def serve():
    """A stand-in HTTP server on loopback, on a thread: (port, close)."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def close():
        server.shutdown()
        server.server_close()
    return server.server_address[1], close


def acts(work, port, python):
    """(name, argv) of every act, as the probe ran them, against this machine alone."""
    a, b, c, d = (os.path.join(work, n) for n in ("a.txt", "b.txt", "c.txt", "d.txt"))
    url = "http://127.0.0.1:%d/" % port
    curl = ["curl", "-s", "-o", os.devnull, "--max-time", "8", url]
    return [("touch", ["touch", a]), ("mv", ["mv", a, b]), ("cp", ["cp", b, c]), ("rm", ["rm", b, c]),
            ("curl", curl), ("curl", curl), ("curl", curl),
            ("wget", ["wget", "-q", "-O", os.devnull, "--timeout=8", url]),
            ("getent", ["getent", "hosts", "localhost"]),
            ("nc", ["nc", "-z", "-w", "3", "127.0.0.1", str(port)]),
            ("python", [python, "-c", "import urllib.request; urllib.request.urlopen(%r, timeout=8).read()" % url]),
            ("sh", ["sh", "-c", "echo x > '%s'" % d]), ("shred", ["shred", "-u", d]),
            ("git", ["git", "ls-remote", url + "none.git", "HEAD"])]


def run_act(argv, env, cwd):
    """Starts one act and waits for it: {"pid", "rc", "ms"}, or {"not_run": why}."""
    t0 = time.monotonic()
    try:
        child = subprocess.Popen(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
    except OSError as exc:
        return {"not_run": "cannot start (%s)" % type(exc).__name__}
    try:
        child.wait(ACT_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
    return {"pid": child.pid, "rc": child.returncode, "ms": round((time.monotonic() - t0) * 1000, 1)}


class Heard:
    """What read() gave, put together: the last record of each pid, with the end a later read gave."""

    def __init__(self):
        self.by_pid = {}

    def take(self, got):
        for p in got.get("processes", []):
            self.by_pid[p["pid"]] = dict(p)
        for e in got.get("ends", []):
            p = self.by_pid.get(e["pid"])
            if p is not None and e.get("started_ticks") in (None, p.get("started_ticks")):
                p.update(ended=e["ended"], code=e["code"], signal=e["signal"])

    def of(self, pid):
        return self.by_pid.get(pid)


def collect(reader=None, run=None, which=None, server=None, platform=None, work=None, sleep=None, clock=None):
    platform = sys.platform if platform is None else platform
    run, which, server = run or run_act, which or shutil.which, server or serve
    sleep, clock = sleep or time.sleep, clock or time.monotonic
    facts = {"platform": platform, "uid": os.geteuid() if hasattr(os, "geteuid") else None, "acts": [],
             "children": [], "counts": None, "refused": None, "stop_problems": None, "error": None}
    if not str(platform).startswith("linux"):
        facts["not_run"] = "not Linux (%s): the process events are the Linux kernel's" % platform
        return facts
    r = None
    try:
        r = (reader or procevents.Reader)()
        why = r.start()
        if why:
            facts["refused"], facts["counts"] = why, r.counts()
            return facts
        heard = Heard()
        own = work is None
        work = tempfile.mkdtemp(prefix="raqib-x31-") if own else work
        env = {k: v for k, v in os.environ.items() if k not in PROXIES}
        env.update(NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost", GIT_TERMINAL_PROMPT="0")
        port, close = server()
        try:
            for name, argv in acts(work, port, sys.executable):
                program = which(argv[0], path=env.get("PATH"))
                entry = {"act": name, "argv0": os.path.basename(argv[0])}
                if program is None:
                    entry["not_run"] = "not installed"
                else:
                    entry["expect"] = os.path.realpath(program)
                    entry.update(run(argv, env, work))
                facts["acts"].append(entry)
            ran = [e["pid"] for e in facts["acts"] if e.get("pid") is not None]
            end = clock() + READ_S
            while True:
                heard.take(r.read())
                if all((heard.of(p) or {}).get("ended") for p in ran) or clock() >= end:
                    break
                sleep(POLL_S)
        finally:
            close()
            if own:
                shutil.rmtree(work, ignore_errors=True)
        facts["stop_problems"] = r.stop()
        heard.take(r.read())
        facts["counts"] = r.counts()
        pids = {}
        for e in facts["acts"]:
            if e.get("pid") is not None:
                e["given"] = heard.of(e["pid"])
                pids[e["pid"]] = e["act"]
        facts["children"] = [{"act": pids[p["ppid"]], "pid": p["pid"], "exe": p["exe"]}
                             for p in heard.by_pid.values() if p.get("ppid") in pids]
    except Exception as exc:
        facts["error"] = "%s: %s" % (type(exc).__name__, " ".join(str(exc).split()))
        if r is not None:
            try:
                facts["stop_problems"] = r.stop()
                facts["counts"] = r.counts()
            except Exception:
                pass
    return facts


def main(argv=None, **hand):
    p = argparse.ArgumentParser(prog="tools/rig/procevents_run.py")
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    facts = collect(**hand)
    try:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(facts, f, indent=1, sort_keys=True)
    except OSError as exc:
        print("procevents_run: the facts could not be written (%s)" % type(exc).__name__)
        return 0
    ran = [e for e in facts["acts"] if e.get("pid") is not None]
    print("procevents_run: %s; %d act(s) ran, %d not run; refused: %s; error: %s" % (
        facts["platform"], len(ran), len(facts["acts"]) - len(ran), facts["refused"] or facts.get("not_run") or
        "no", facts["error"] or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
