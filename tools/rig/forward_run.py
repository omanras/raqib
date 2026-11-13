"""The rig's forwarder run (ADR-0011 J-14, L-10): `raqib forward` against the stand-in collector
(tools/rig/collector.py, loopback only, the hec shape, a made-up token), over the events file the rig's watch
wrote. It writes what it saw as JSON for tools/rig/check.py, which states X19 to X22; it judges nothing itself.

    python tools/rig/forward_run.py --events FILE --out FACTS.json [--home DIR]

X19 the whole file, --once. X20 the collector down from the start (its port bound by it, nothing listening),
then up: the state says failing, and nothing is lost. X21 a forwarder killed while the collector holds its
second request (by the collector's count of requests, not a window of time), then started again (--once): the
lines taken before the kill must not come again. X22 every output, state and error of every run here, every
argument list, and the argument list of a running forwarder as the system's own process list says it, for both
made-up tokens (the right one and the refused one). The forwarders run with HOME (and USERPROFILE) set to
--home (default: a new directory), so their states are the rig's own.

It never raises (L-10): each case is its own, an error in one is a fact of that case, and a missing events file
is a fact; it writes its facts and exits 0 whatever happened (2 only for its own usage). Stdlib only.
"""
import argparse
import binascii
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import collector  # noqa: E402  (the stand-in beside this file)

PATH = "/services/collector/event"
FORWARD = [sys.executable, "-m", "raqib", "forward"]   # the forwarder (a test names one that cannot start)
CASES = ("x19", "x20", "x21", "x22")


class Run:
    def __init__(self, events, home):
        self.events, self.home = events, home
        self.forward = os.path.join(home, ".raqib", "forward")
        self.env = dict(os.environ, HOME=home, USERPROFILE=home,
                        PYTHONPATH=os.pathsep.join([ROOT] + [p for p in [os.environ.get("PYTHONPATH")] if p]))
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            self.env.pop(key, None)
        self.token_file = self.secret("token", "rig-made-up-token-" + binascii.hexlify(os.urandom(8)).decode())
        self.wrong_file = self.secret("wrong", "rig-made-up-wrong-" + binascii.hexlify(os.urandom(8)).decode())
        self.texts, self.argvs, self.listed = [], [], []

    def secret(self, name, value):
        path = os.path.join(self.home, name + ".txt")
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value + "\n")
        return path

    def argv(self, name, port, *more, token=None):
        return FORWARD + [self.events, "--to", "http://127.0.0.1:%d%s" % (port, PATH), "--name", name, "--shape",
                          "hec", "--token-file", token or self.token_file, "--beat", "1"] + list(more)

    def say(self, where, text):
        self.texts.append({"where": where, "text": text})

    def run(self, where, argv, timeout=120):
        self.argvs.append(argv)
        try:
            p = subprocess.run(argv, env=self.env, cwd=self.home, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout)
            out, err, code = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as exc:
            out, err, code = exc.stdout or b"", exc.stderr or b"", None
        except OSError as exc:   # the forwarder cannot start: a fact
            self.say(where + " start", "cannot start: %s" % type(exc).__name__)
            return None
        self.say(where + " stdout", out.decode("utf-8", "replace"))
        self.say(where + " stderr", err.decode("utf-8", "replace"))
        return code

    def start(self, where, argv):
        self.argvs.append(argv)
        out = open(os.path.join(self.home, where + ".out"), "wb")
        try:
            return subprocess.Popen(argv, env=self.env, cwd=self.home, stdout=out, stderr=subprocess.STDOUT), out
        except OSError:
            out.close()
            raise

    def end(self, where, proc, out, kill=False):
        if proc.poll() is None:
            if kill:
                proc.kill()
            else:
                proc.terminate()
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(15)
        out.close()
        with open(out.name, "rb") as f:
            self.say(where + " output", f.read().decode("utf-8", "replace"))
        return proc.returncode

    def list_process(self, where, pid):
        """L-10: the argument list of a running process as the system lists it (not as the rig built it)."""
        how, text = None, ""
        try:
            if sys.platform.startswith("linux") and os.path.exists("/proc/%d/cmdline" % pid):
                how = "/proc/%d/cmdline" % pid
                with open(how, "rb") as f:
                    text = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
            elif sys.platform == "win32":
                how = "Win32_Process CommandLine"
                text = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                       "(Get-CimInstance Win32_Process -Filter 'ProcessId=%d').CommandLine" % pid],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      timeout=60).stdout.decode("utf-8", "replace")
            else:
                how = "ps"
                text = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(pid)], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, timeout=60).stdout.decode("utf-8", "replace")
        except (OSError, subprocess.SubprocessError) as exc:
            text = ""
            how = "%s (%s)" % (how, type(exc).__name__)
        self.listed.append({"where": where, "pid": pid, "how": how, "text": text.strip()})

    def state(self, name):
        try:
            with open(os.path.join(self.forward, name + ".json"), "rb") as f:
                return json.loads(f.read().decode("ascii"))
        except (OSError, ValueError):
            return None

    def until(self, test, seconds, proc=None):
        """Polls `test` (the collector's or the state's own facts) until it holds, the process ended, or
        `seconds` passed."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            got = test()
            if got:
                return got
            if proc is not None and proc.poll() is not None:
                return test()
            time.sleep(0.05)
        return None

    def states(self):
        out = []
        for name in sorted(os.listdir(self.forward)) if os.path.isdir(self.forward) else []:
            try:
                with open(os.path.join(self.forward, name), "rb") as f:
                    out.append({"where": "state " + name, "text": f.read().decode("utf-8", "replace")})
            except OSError:
                pass
        return out


def count_lines(path):
    with open(path, "rb") as f:
        return f.read().count(b"\n")


def x19(r):
    c = collector.Collector(r.token_file)
    port = c.start()
    try:
        code = r.run("x19", r.argv("rig-x19", port, "--once"))
    finally:
        c.stop()
    r.run("x19 status", FORWARD + ["--status", "rig-x19"])
    return {"exit": code, "events": list(c.events), "requests": len(c.requests)}


def x20(r):
    c = collector.Collector(r.token_file, down=True)
    port = c.start()   # bound by the collector, nothing listening: down, and no one else's port
    proc = out = None
    try:
        proc, out = r.start("x20", r.argv("rig-x20", port))
        failing = r.until(lambda: (r.state("rig-x20") or {}).get("failing"), 30, proc)
        if proc.poll() is None:
            r.list_process("x20 running", proc.pid)
        c.up()
        final = r.until(lambda: (lambda s: s if s and not s.get("failing") and s.get("behind") == 0 and
                                 s.get("last_ok") else None)(r.state("rig-x20")), 60, proc)
    finally:
        if proc is not None:
            r.end("x20", proc, out)
        c.stop()
    return {"failing": failing, "final": final, "events": list(c.events)}


def x21(r):
    lines = count_lines(r.events)
    batch = max(1, min(5, lines // 4))
    c = collector.Collector(r.token_file, hold=1)   # the second request is held: the kill comes then
    port = c.start()
    proc = out = None
    try:
        proc, out = r.start("x21", r.argv("rig-x21", port, "--batch", str(batch)))
        held = bool(r.until(c.held.is_set, 60, proc))
        killed = r.state("rig-x21")
        before, at_kill = len(c.events), c.arrived
        r.end("x21", proc, out, kill=True)
        proc = None
        c.release.set()   # the held request is dropped, never taken
        code = r.run("x21 again", r.argv("rig-x21", port, "--once"))
    finally:
        if proc is not None:
            r.end("x21", proc, out, kill=True)
        c.stop()
    return {"batch": batch, "held": held, "killed": (killed or {}).get("cursor"), "before": before,
            "requests_at_kill": at_kill, "size": os.path.getsize(r.events), "exit": code, "events": list(c.events)}


def x22(r):
    c = collector.Collector(r.token_file)
    port = c.start()
    try:
        r.run("x22 wrong token", r.argv("rig-x22-wrong", port, "--once", token=r.wrong_file))
        c.fail = 1000
        r.run("x22 failing", r.argv("rig-x22-fail", port, "--once"))
    finally:
        c.stop()
    r.run("x22 status", FORWARD + ["--status"])
    return {}


def main(argv=None):
    p = argparse.ArgumentParser(prog="tools/rig/forward_run.py")
    p.add_argument("--events", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--home")
    a = p.parse_args(argv)
    facts = {}
    try:
        home = os.path.abspath(a.home or tempfile.mkdtemp(prefix="raqib-forward-rig-"))
        os.makedirs(home, exist_ok=True)
        r = Run(os.path.abspath(a.events), home)
        facts.update(events=r.events, token_file=r.token_file, wrong_file=r.wrong_file)
        if not os.path.isfile(r.events):
            facts["events_missing"] = True   # the watch wrote none: X16 says it; nothing is forwarded
        else:
            for name, case in zip(CASES, (x19, x20, x21, x22)):
                try:
                    facts[name] = case(r)
                except Exception as exc:   # one case's error is that case's fact
                    facts[name] = {"error": "%s: %s" % (type(exc).__name__, exc)}
        facts.setdefault("x22", {}).update(texts=r.texts + r.states(), argv=r.argvs, listed=r.listed)
    except Exception as exc:
        facts["error"] = "%s: %s" % (type(exc).__name__, exc)
    try:
        with open(a.out, "w", encoding="ascii") as f:
            json.dump(facts, f, indent=1, ensure_ascii=True)
        print("forward_run: facts in %s" % a.out)
    except OSError as exc:
        print("forward_run: the facts cannot be written to %s (%s)" % (a.out, type(exc).__name__))
    return 0


if __name__ == "__main__":
    sys.exit(main())
