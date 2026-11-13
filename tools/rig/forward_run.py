"""The rig's forwarder run (ADR-0011 J-14): `raqib forward` against the stand-in collector (tools/rig/collector.py,
loopback only, the hec shape, a made-up token), over the events file the rig's watch wrote. It writes what it saw
as JSON for tools/rig/check.py, which states X19 to X22; it judges nothing itself.

    python tools/rig/forward_run.py --events FILE --out FACTS.json [--home DIR]

X19 the whole file, --once. X20 the collector down from the start, then up: the state says failing, and nothing
is lost. X21 a forwarder killed between two batches, then started again (--once). X22 every output, state and
error of every run here, and every argument list, for the made-up token. The forwarders run with HOME (and
USERPROFILE) set to --home (default: a new directory), so their states are the rig's own. Stdlib only; exit 0
(it reports; it does not fail), 2 usage.
"""
import argparse
import binascii
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import collector  # noqa: E402  (the stand-in beside this file)

PATH = "/services/collector/event"


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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
        self.texts, self.argvs = [], []

    def secret(self, name, value):
        path = os.path.join(self.home, name + ".txt")
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value + "\n")
        return path

    def argv(self, name, port, *more, token=None):
        return [sys.executable, "-m", "raqib", "forward", self.events, "--to", "http://127.0.0.1:%d%s" % (port, PATH),
                "--name", name, "--shape", "hec", "--token-file", token or self.token_file, "--beat", "1"] + list(more)

    def run(self, where, argv, timeout=120):
        self.argvs.append(argv)
        try:
            p = subprocess.run(argv, env=self.env, cwd=self.home, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout)
            out, err, code = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as exc:
            out, err, code = exc.stdout or b"", exc.stderr or b"", None
        self.texts += [{"where": where + " stdout", "text": out.decode("utf-8", "replace")},
                       {"where": where + " stderr", "text": err.decode("utf-8", "replace")}]
        return code

    def start(self, where, argv):
        self.argvs.append(argv)
        out = open(os.path.join(self.home, where + ".out"), "wb")
        return subprocess.Popen(argv, env=self.env, cwd=self.home, stdout=out, stderr=subprocess.STDOUT), out

    def end(self, where, proc, out, kill=False):
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
            self.texts.append({"where": where + " output", "text": f.read().decode("utf-8", "replace")})
        return proc.returncode

    def state(self, name):
        try:
            with open(os.path.join(self.forward, name + ".json"), "rb") as f:
                return json.loads(f.read().decode("ascii"))
        except (OSError, ValueError):
            return None

    def until(self, test, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            got = test()
            if got:
                return got
            time.sleep(0.05)
        return None

    def states(self):
        out = []
        for name in sorted(os.listdir(self.forward)) if os.path.isdir(self.forward) else []:
            with open(os.path.join(self.forward, name), "rb") as f:
                out.append({"where": "state " + name, "text": f.read().decode("utf-8", "replace")})
        return out


def count_lines(path):
    with open(path, "rb") as f:
        return f.read().count(b"\n")


def main(argv=None):
    p = argparse.ArgumentParser(prog="tools/rig/forward_run.py")
    p.add_argument("--events", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--home")
    a = p.parse_args(argv)
    home = os.path.abspath(a.home or tempfile.mkdtemp(prefix="raqib-forward-rig-"))
    os.makedirs(home, exist_ok=True)
    r = Run(os.path.abspath(a.events), home)
    facts = {"events": r.events, "token_file": r.token_file}

    # X19: the whole file, once.
    c = collector.Collector(r.token_file)
    port = c.start()
    try:
        code = r.run("x19", r.argv("rig-x19", port, "--once"))
    finally:
        c.stop()
    facts["x19"] = {"exit": code, "events": list(c.events), "requests": len(c.requests)}
    r.run("x19 status", [sys.executable, "-m", "raqib", "forward", "--status", "rig-x19"])

    # X20: the collector down from the start, then up.
    port = free_port()
    proc, out = r.start("x20", r.argv("rig-x20", port))
    failing = r.until(lambda: (r.state("rig-x20") or {}).get("failing"), 30)
    c = collector.Collector(r.token_file, port=port)
    c.start()
    try:
        final = r.until(lambda: (lambda s: s if s and not s.get("failing") and s.get("behind") == 0 and
                                 s.get("last_ok") else None)(r.state("rig-x20")), 60)
    finally:
        r.end("x20", proc, out)
        c.stop()
    facts["x20"] = {"failing": failing, "final": final, "events": list(c.events)}

    # X21: killed between two batches, started again.
    lines = count_lines(r.events)
    batch = str(max(1, min(5, lines // 4)))
    c = collector.Collector(r.token_file, late=0.3)
    port = c.start()
    try:
        proc, out = r.start("x21", r.argv("rig-x21", port, "--batch", batch))
        at = r.until(lambda: (lambda s: s if s and s["cursor"]["offset"] > 0 else None)(r.state("rig-x21")), 60)
        r.end("x21", proc, out, kill=True)
        killed = r.state("rig-x21")
        code = r.run("x21 again", r.argv("rig-x21", port, "--once"))
    finally:
        c.stop()
    size = os.path.getsize(r.events)
    facts["x21"] = {"batch": int(batch), "seen": (at or {}).get("cursor"), "killed": (killed or {}).get("cursor"),
                    "size": size, "exit": code, "events": list(c.events)}

    # X22: a refused token and a failing collector say their errors too.
    c = collector.Collector(r.token_file)
    port = c.start()
    try:
        r.run("x22 wrong token", r.argv("rig-x22-wrong", port, "--once", token=r.wrong_file))
        c.fail = 1000
        r.run("x22 failing", r.argv("rig-x22-fail", port, "--once"))
    finally:
        c.stop()
    r.run("x22 status", [sys.executable, "-m", "raqib", "forward", "--status"])
    facts["x22"] = {"texts": r.texts + r.states(), "argv": r.argvs}
    with open(a.out, "w", encoding="ascii") as f:
        json.dump(facts, f, indent=1, ensure_ascii=True)
    print("forward_run: facts in %s (home %s)" % (a.out, home))
    return 0


if __name__ == "__main__":
    sys.exit(main())
