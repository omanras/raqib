"""The rig's stand-in agent (ADR-0012): a process that keeps a connection to a public host open and starts the
children an agent starts. What it prints is the ground truth the watch's report is read against (tools/rig/check.py).
It runs in CI only, on a machine made for the job; it is never imported by raqib and is no part of the capture path."""
import os
import shutil
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


RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "RaqibRigValue"
HARMLESS = "cmd /c rem raqib rig"


def own_address():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))   # no packet is sent: the route's own address is asked for
        return probe.getsockname()[0]
    finally:
        probe.close()


def behaviour(startup):
    """ADR-0014 (Windows): three harmless acts, each undone by undo(): a file in the user's Startup folder that
    holds a remark, a connection to port 22 of this machine's own address (its own sshd answers), and a value under
    the user's Run key that would run a remark. What each did is said, for tools/rig/check.py (X32 to X34)."""
    run(["powershell", "-NoProfile", "-Command", "Set-Content -LiteralPath '%s' -Value 'rem raqib rig'" % startup])
    say("startup file %s" % ("written" if os.path.exists(startup) else "not written"))
    try:
        address = own_address()
    except OSError as exc:
        say("port 22 not asked (%s)" % type(exc).__name__)
    else:
        child = run(["powershell", "-NoProfile", "-Command",
                     "$c = New-Object Net.Sockets.TcpClient('%s', 22); Start-Sleep 2; $c.Close()" % address])
        say("port 22 of this machine's own address %s" % ("reached" if child.returncode == 0 else "not reached"))
    child = run(["reg", "add", RUN_KEY, "/v", RUN_VALUE, "/t", "REG_SZ", "/d", HARMLESS, "/f"])
    say("autostart value %s" % ("set" if child.returncode == 0 else "not set"))


def undo(startup):
    try:
        os.remove(startup)
        say("undone: the startup file")
    except OSError as exc:
        say("the startup file was not there to undo (%s)" % type(exc).__name__)
    run(["reg", "delete", RUN_KEY, "/v", RUN_VALUE, "/f"])


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
    if sys.platform.startswith("linux"):   # ADR-0007 BY-7 (X36): a network tool that lives under a second
        if shutil.which("wget"):
            run(["wget", "-q", "-O", "/dev/null", "--timeout=5", "https://example.com/"])
        else:
            say("wget not installed")
    if windows:
        run(["powershell", "-NoProfile", "-Command", "Set-Clipboard -Value 'raqib-rig'"])   # writes the clipboard
        run(["cmd", "/c", "whoami"])
    path = os.path.join(tempfile.gettempdir(), "raqib-rig-file.txt")
    with open(path, "w") as f:                                                           # a file made by its own code
        f.write("rig")
    say("wrote raqib-rig-file.txt")
    os.remove(path)
    say("deleted raqib-rig-file.txt")
    startup = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
                           "raqib-rig-startup.cmd")
    try:
        if windows:
            behaviour(startup)
        long_curl.wait(30)
        say("end long curl rc=%s" % long_curl.returncode)
        time.sleep(12)                                                                   # quiet, still talking
    finally:
        if windows:
            undo(startup)
    talk.close()
    say("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
