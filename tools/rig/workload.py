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
SERVICE = "RaqibRigService"
SERVICE_BIN = "cmd.exe /c echo"   # ADR-0014 AG-4: a service that would only echo, made and never started


def own_address():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))   # no packet is sent: the route's own address is asked for
        return probe.getsockname()[0]
    finally:
        probe.close()


def behaviour(startup):
    """ADR-0014 (Windows): four harmless acts, each undone by undo(): a file in the user's Startup folder that
    holds a remark, a connection to port 22 of this machine's own address (its own sshd answers), a value under
    the user's Run key that would run a remark, and a service that would echo, made to start on demand and never
    started (AG-4). What each did is said, for tools/rig/check.py (X32 to X34, and X37 where
    tools/rig/autostart_run.py runs it)."""
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
    child = run(["sc.exe", "create", SERVICE, "binPath=", SERVICE_BIN, "start=", "demand"])
    say("service %s" % ("made, never started" if child.returncode == 0 else "not made"))


def undo(startup):
    try:
        os.remove(startup)
        say("undone: the startup file")
    except FileNotFoundError:
        say("the startup file was not there to undo")
    except OSError as exc:   # ADR-0014 AI-10: a delete that failed beside the reads is said (X37)
        say("the startup file's delete failed (%s)" % type(exc).__name__)
    run(["reg", "delete", RUN_KEY, "/v", RUN_VALUE, "/f"])
    child = run(["sc.exe", "delete", SERVICE])
    say("undone: the service" if child.returncode == 0 else "the service was not there to undo (rc=%s)" %
        child.returncode)


FETCH = "wget -q -O /dev/null --tries=1 --timeout=5 https://example.com/"   # a fetch thrown away


def later_programs():
    """ADR-0007 CC-7 (Linux; each harmless, each said): X43, a `bash -c` whose first step sleeps longer than a round
    and whose last command, a fetch, bash runs in its own pid; X44, `nc -z` to the same public name where nc is
    installed; X45, a bash that outlives the sh that started it, then runs a fetch in its own pid."""
    if not shutil.which("wget") or not shutil.which("bash"):
        say("bash-exec not run: wget or bash not installed")
    else:
        say("start bash")
        child = subprocess.Popen(["bash", "-c", "sleep 7; " + FETCH], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        say("bash-exec pid %d" % child.pid)
        try:
            child.wait(30)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(5)
        say("end bash rc=%s" % child.returncode)
    if shutil.which("nc"):
        run(["nc", "-z", "-w", "2", "example.com", "443"])
    else:
        say("nc not installed")
    if not shutil.which("wget") or not shutil.which("bash") or not shutil.which("sh"):
        say("outliving not run: wget, bash or sh not installed")
        return
    say("start sh")
    got = subprocess.run(["sh", "-c", 'bash -c "sleep 7; %s" >/dev/null 2>&1 & echo $!' % FETCH],
                         capture_output=True, text=True, timeout=30)
    say("outliving pid %s (sh rc=%s)" % (got.stdout.strip() or "?", got.returncode))
    time.sleep(10)   # the outliving bash sleeps 7 s, then fetches in its own pid
    say("outliving waited")
    sudo_fetch()


def sudo_fetch():
    """ADR-0007 CE-3 (X46, Linux): the same harmless fetch, thrown away, run through `sudo -n` where the machine
    allows it without a password (a throwaway CI machine): a process whose file a plain reader cannot read. Said
    n/a where `sudo -n true` fails; never asks for a password."""
    ok = False
    if shutil.which("wget") and shutil.which("sudo"):
        try:
            ok = subprocess.run(["sudo", "-n", "true"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
    if not ok:
        say("sudo-fetch not run: sudo -n is not allowed here (or wget or sudo not installed)")
        return
    say("start sudo")
    child = subprocess.Popen(["sudo", "-n"] + FETCH.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    say("sudo-fetch pid %d" % child.pid)
    try:
        child.wait(30)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(5)
    say("end sudo rc=%s" % child.returncode)


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
            run(["wget", "-q", "-O", "/dev/null", "--timeout=5", "--tries=1", "https://example.com/"])   # BZ-10
        else:
            say("wget not installed")
        later_programs()
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
