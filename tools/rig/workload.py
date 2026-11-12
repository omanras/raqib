"""The rig's stand-in agent (probe only, never merged): a process that keeps a connection to a public host and
starts the children an agent starts. What it does is the ground truth the watch's report is read against."""
import os
import socket
import subprocess
import sys
import tempfile
import time

LOG = []


def say(what):
    LOG.append("%s %s" % (time.strftime("%H:%M:%S", time.gmtime()), what))
    print("WORKLOAD %s" % LOG[-1], flush=True)


def run(argv, wait=True, timeout=60):
    say("start %s" % " ".join(argv))
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if wait:
        try:
            p.wait(timeout)
        except subprocess.TimeoutExpired:
            p.kill()
        say("end %s rc=%s" % (argv[0], p.returncode))
    return p


def main():
    nul = "NUL" if os.name == "nt" else "/dev/null"
    say("pid %d" % os.getpid())
    talk = socket.create_connection(("example.com", 443), timeout=15)   # the tree talks to a remote host
    say("talking to %s:%d" % talk.getpeername()[:2])
    time.sleep(8)
    # a child that lives across rounds and talks: about 20 s
    long_curl = run(["curl", "-s", "--limit-rate", "2000", "--max-time", "20", "-o", nul,
                     "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"], wait=False)
    time.sleep(12)
    run(["curl", "-s", "--max-time", "10", "-o", nul, "https://example.com/"])          # a short child
    if os.name == "nt":
        run(["powershell", "-NoProfile", "-Command", "Set-Clipboard -Value 'rig-probe'"])   # the clipboard
        run(["cmd", "/c", "whoami"])
    path = os.path.join(tempfile.gettempdir(), "rig-probe-file.txt")
    with open(path, "w") as f:                                                           # a file made by its own code
        f.write("rig")
    say("wrote %s" % path)
    with open(os.path.join(os.environ.get("SystemRoot", "/etc"), "win.ini" if os.name == "nt" else "hostname")) as f:
        f.read()                                                                         # a file read by its own code
    say("read a system file")
    os.remove(path)
    say("deleted %s" % path)
    long_curl.wait(30)
    say("end long curl rc=%s" % long_curl.returncode)
    time.sleep(12)                                                                       # quiet, still talking
    talk.close()
    say("done")


if __name__ == "__main__":
    sys.exit(main())
