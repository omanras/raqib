"""Probe only (never merged): the rig's stand-in agent doing the acts of the field test of 2026-11-20, each of them
harmless and each undone at the end, to measure what they leave for a watch to read (Windows only):
  1. a file written under TEMP by a powershell under a cmd;
  2. an autostart entry of the user's that would run `cmd /c echo`: a value under HKCU ...\\CurrentVersion\\Run made
     once by reg.exe and once by PowerShell, a file holding `rem` in the user's Startup folder, and a scheduled
     task of that command;
  3. a TCP connection to port 22 of this machine's own address, once from PowerShell and once by ssh.
With --listen it is the other end of 3 instead: it accepts on port 22, says a banner and ends.
It runs in CI only, on a machine made for the job and thrown away after it; it is never imported by raqib."""
import os
import socket
import subprocess
import sys
import tempfile
import time

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
OTHERS = []   # (key, name, more arguments) of the values made by reg.exe beyond the first two, to undo
HARMLESS = "cmd /c echo benign-persistence-test"
TASK = "RaqibRigTest"


def say(what):
    print("WORKLOAD %s %s" % (time.strftime("%H:%M:%S", time.gmtime()), what), flush=True)


def run(argv, timeout=60):
    say("start %s" % " ".join(argv[:3]))
    child = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        child.wait(timeout)
    except subprocess.TimeoutExpired:
        child.kill()
    say("end %s pid %d rc=%s" % (argv[0], child.pid, child.returncode))
    return child


def own_address():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))   # no packet is sent: the route's own address is asked for
        return probe.getsockname()[0]
    finally:
        probe.close()


def listen():
    try:
        server = socket.create_server(("0.0.0.0", 22))
    except OSError as exc:
        print("LISTEN cannot listen on 22 (%s): something else may hold it" % exc, flush=True)
        return 0
    server.settimeout(5)
    end, taken = time.monotonic() + 170, 0
    while time.monotonic() < end and taken < 4:
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        taken += 1
        print("LISTEN accepted connection %d" % taken, flush=True)
        try:
            conn.sendall(b"SSH-2.0-rig\r\n")
            time.sleep(2)
        except OSError:
            pass
        conn.close()
    server.close()
    return 0


def run_values():
    import winreg
    out = {}
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY)
    except OSError as exc:   # seen on a fresh runner: the user's Run key is not there until something makes it
        say("the user's Run key is not there (%s)" % type(exc).__name__)
        return out
    with key:
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            out[name] = value
            i += 1
    return out


def undo(startup_file, temp_file):
    import winreg
    for name in ("RaqibRigTestA", "RaqibRigTestB"):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
            say("undone: the value %s" % name)
        except OSError as exc:
            say("the value %s was not there to undo (%s)" % (name, type(exc).__name__))
    for key, name, more in OTHERS:
        run(["reg", "delete", key, "/v", name, "/f"] + more)
    for path in (startup_file, temp_file):
        try:
            os.remove(path)
            say("undone: %s" % os.path.basename(path))
        except OSError as exc:
            say("%s was not there to undo (%s)" % (os.path.basename(path), type(exc).__name__))
    run(["schtasks", "/delete", "/tn", TASK, "/f"])


def main():
    if "--listen" in sys.argv:
        return listen()
    if os.name != "nt":
        say("not Windows: nothing is done")
        return 0
    address = own_address()
    temp_file = os.path.join(tempfile.gettempdir(), "raqib-effect-1.txt")
    startup_file = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup",
                                "raqib-rig-test.cmd")
    say("pid %d" % os.getpid())
    say("the user's autostart values before: %s" % sorted(run_values()))
    talk = socket.create_connection(("example.com", 443), timeout=15)   # the tree talks to a remote host
    say("talking")
    try:
        time.sleep(8)
        run(["curl", "-s", "--max-time", "10", "-o", "NUL", "https://example.com/"])
        # 1. a file under TEMP by a powershell under a cmd
        run(["cmd", "/c", "powershell", "-NoProfile", "-Command",
             "Set-Content -LiteralPath '%s' -Value rig" % temp_file])
        say("act 1 done: %s exists: %s" % (os.path.basename(temp_file), os.path.exists(temp_file)))
        time.sleep(6)
        # 2. autostart entries that would run a harmless command
        run(["cmd", "/c", "reg", "add", "HKCU\\" + RUN_KEY, "/v", "RaqibRigTestA", "/t", "REG_SZ", "/d", HARMLESS,
             "/f"])
        run(["powershell", "-NoProfile", "-Command",
             "New-ItemProperty -Path 'HKCU:\\%s' -Name RaqibRigTestB -Value '%s' -PropertyType String -Force"
             " | Out-Null" % (RUN_KEY, HARMLESS)])
        run(["powershell", "-NoProfile", "-Command",
             "Set-Content -LiteralPath '%s' -Value 'rem raqib rig test'" % startup_file])
        # the other forms of the same key (M15.2, measured before ruling): RunOnce, the machine's hive, the 32-bit view
        for key, name, more in (("HKCU\\" + RUN_KEY + "Once", "RaqibRigTestC", []),
                                ("HKLM\\" + RUN_KEY, "RaqibRigTestD", []),
                                ("HKLM\\" + RUN_KEY, "RaqibRigTestE", ["/reg:32"])):
            run(["reg", "add", key, "/v", name, "/t", "REG_SZ", "/d", HARMLESS, "/f"] + more)
            OTHERS.append((key, name, more))
        # a value whose name holds a backslash (the review of M15.2, F5): what does Sysmon write for it?
        run(["reg", "add", "HKCU\\" + RUN_KEY, "/v", "RaqibRig\\Slash", "/t", "REG_SZ", "/d", HARMLESS, "/f"])
        OTHERS.append(("HKCU\\" + RUN_KEY, "RaqibRig\\Slash", []))
        run(["schtasks", "/create", "/tn", TASK, "/tr", HARMLESS, "/sc", "onlogon", "/f"])
        values = run_values()
        say("act 2 done: the user's autostart values now: %s; the Startup file exists: %s" % (
            sorted(n for n in values if n.startswith("RaqibRigTest")), os.path.exists(startup_file)))
        time.sleep(6)
        # 3. a connection to port 22 of this machine's own address
        run(["powershell", "-NoProfile", "-Command",
             "$c = New-Object Net.Sockets.TcpClient('%s', 22); Start-Sleep 3; $c.Close()" % address])
        run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL",
             "-o", "ConnectTimeout=5", "rig@%s" % address, "exit"], timeout=20)
        say("act 3 done")
        # 40 values, each by a fresh reg.exe at a moment of its own (the review of M15.2, F1): how many become lines?
        import random
        for i in range(40):
            name = "RaqibRigMany%02d" % i
            run(["reg", "add", "HKCU\\" + RUN_KEY, "/v", name, "/t", "REG_SZ", "/d", HARMLESS, "/f"])
            OTHERS.append(("HKCU\\" + RUN_KEY, name, []))
            time.sleep(random.uniform(0.2, 1.8))
        say("the 40 values set")
        time.sleep(14)
    finally:
        undo(startup_file, temp_file)
        talk.close()
    say("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
