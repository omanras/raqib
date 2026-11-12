"""The rig's stand-in agent (ADR-0012): a process that keeps a connection to a public host open and starts the
children an agent starts. What it prints is the ground truth the watch's report is read against (tools/rig/check.py).
It runs in CI only, on a machine made for the job; it is never imported by raqib and is no part of the capture path."""
import os
import socket
import subprocess
import sys
import tempfile
import time


def say(what):
    print("WORKLOAD %s %s" % (time.strftime("%H:%M:%S", time.gmtime()), what), flush=True)


def run(argv, wait=True, timeout=60):
    say("start %s" % argv[0])
    child = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if wait:
        try:
            child.wait(timeout)
        except subprocess.TimeoutExpired:
            child.kill()
        say("end %s rc=%s" % (argv[0], child.returncode))
    return child


def main():
    windows = os.name == "nt"
    nul = "NUL" if windows else "/dev/null"
    say("pid %d" % os.getpid())
    talk = socket.create_connection(("example.com", 443), timeout=15)   # the tree talks to a remote host
    say("talking")
    time.sleep(8)
    # a child that lives across rounds and talks: about 20 s
    long_curl = run(["curl", "-s", "--limit-rate", "2000", "--max-time", "20", "-o", nul,
                     "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"], wait=False)
    time.sleep(12)
    run(["curl", "-s", "--max-time", "10", "-o", nul, "https://example.com/"])          # a short child
    if windows:
        run(["powershell", "-NoProfile", "-Command", "Set-Clipboard -Value 'raqib-rig'"])   # writes the clipboard
        run(["cmd", "/c", "whoami"])
    path = os.path.join(tempfile.gettempdir(), "raqib-rig-file.txt")
    with open(path, "w") as f:                                                           # a file made by its own code
        f.write("rig")
    say("wrote raqib-rig-file.txt")
    os.remove(path)
    say("deleted raqib-rig-file.txt")
    long_curl.wait(30)
    say("end long curl rc=%s" % long_curl.returncode)
    time.sleep(12)                                                                       # quiet, still talking
    talk.close()
    say("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
