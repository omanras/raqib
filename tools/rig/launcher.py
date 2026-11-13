"""Probe only (ADR-0007 BC-7): an unknown program that starts an agent and then talks by itself, so that the
watch holds two trees, one under the other: the agent's (found first) and this one's (found when it talks).
Usage: python tools/rig/launcher.py DELAY URL   (the agent's command line in the environment: RIG_CMD)
It runs RIG_CMD through the shell, waits DELAY seconds, then GETs URL every 5 s on a new connection each time
until the command ends (or 110 s), and ends with the command's exit code."""
import os
import subprocess
import sys
import time
import urllib.request


def main(argv):
    delay, url = float(argv[1]), argv[2]
    child = subprocess.Popen(os.environ["RIG_CMD"], shell=True)
    begin = time.monotonic()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    talks = 0
    while child.poll() is None and time.monotonic() - begin < 110:
        if time.monotonic() - begin >= delay:
            try:
                with opener.open(urllib.request.Request(url, headers={"Connection": "close"}), timeout=5) as r:
                    r.read()
                talks += 1
            except OSError as exc:
                print("launcher: no answer: %s" % exc.__class__.__name__)
            time.sleep(5)
        else:
            time.sleep(0.5)
    if child.poll() is None:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(child.pid)] if os.name == "nt" else
                       ["kill", str(child.pid)], capture_output=True)
        print("launcher: the agent was stopped at its time")
    print("launcher: pid %d talked %d time(s); the agent's shell was pid %d" % (os.getpid(), talks, child.pid))
    return child.poll() or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
