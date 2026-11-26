"""Probe only (never merged): what Raqib costs on a machine when it is packed with its own runtime (one folder,
no Python needed on the machine), beside the same commands run by the machine's Python. It says the folder's size
and files, how long `--version` takes cold and warm, and for a short host watch its time, its peak memory and what
its report says could not be seen (a packed program is not `python -m`: what the watch starts by that road may not
start). It changes nothing outside the runner's temp folder. usage: packed_probe.py PACKED_EXE"""
import os
import subprocess
import sys
import threading
import time


def tree_size(folder):
    total = files = 0
    for root, _, names in os.walk(folder):
        for n in names:
            try:
                total += os.path.getsize(os.path.join(root, n))
                files += 1
            except OSError:
                pass
    return total, files


def peak_of(pid, stop, out):
    """The peak resident memory of pid and of its children, sampled (KiB), by what the system has."""
    peak = 0
    while not stop.is_set():
        try:
            if sys.platform == "win32":
                got = subprocess.run(["powershell", "-NoProfile", "-Command",
                                      "$p = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq %d -or "
                                      "$_.ParentProcessId -eq %d }; ($p | Measure-Object WorkingSetSize -Sum).Sum"
                                      % (pid, pid)], capture_output=True, text=True, timeout=20).stdout.strip()
                now = int(got or 0) // 1024
            else:
                got = subprocess.run(["ps", "-axo", "pid=,ppid=,rss="], capture_output=True, text=True,
                                     timeout=20).stdout
                now = 0
                for line in got.splitlines():
                    f = line.split()
                    if len(f) == 3 and (f[0] == str(pid) or f[1] == str(pid)):
                        now += int(f[2])
            peak = max(peak, now)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        stop.wait(1.0)
    out.append(peak)


def timed(argv, label, env=None, watch=False):
    t0 = time.monotonic()
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    stop, peak = threading.Event(), []
    t = threading.Thread(target=peak_of, args=(p.pid, stop, peak))
    if watch:
        t.start()
    try:
        text, _ = p.communicate(timeout=240)
    except subprocess.TimeoutExpired:
        p.kill()
        text, _ = p.communicate()
        text += "\n(killed after 240 s)"
    took = time.monotonic() - t0
    stop.set()
    if watch:
        t.join()
    print("%s: exit %s in %.2f s%s" % (label, p.returncode, took, "; peak memory with its children %d MiB"
                                       % (peak[0] // 1024) if watch and peak else ""))
    return text


def said(text, label):
    keep = [l for l in text.splitlines() if any(w in l for w in (
        "RESULT", "HOLES", "PROCESS EVENTS", "rounds asked", "raqib ", "could not", "not read", "refused", "helper",
        "CHANNEL", "Traceback", "Error", "error", "No module", "not supported", "platform"))]
    print("  what %s said (%d line(s) of %d):" % (label, len(keep), len(text.splitlines())))
    for l in keep[:24]:
        print("    " + l[:230])


def main(exe):
    folder = os.path.dirname(os.path.abspath(exe))
    size, files = tree_size(folder)
    print("PLATFORM %s; python %s" % (sys.platform, sys.version.split()[0]))
    print("PACKED: %s: %.1f MiB in %d file(s)" % (os.path.basename(folder), size / 1048576.0, files))
    home = os.path.join(os.environ.get("RUNNER_TEMP") or os.getcwd(), "packed-home")
    env = dict(os.environ, HOME=home, USERPROFILE=home)
    os.makedirs(home, exist_ok=True)
    for label, argv in (("packed", [exe]), ("python", [sys.executable, "-m", "raqib"])):
        print(timed(argv + ["--version"], "%s --version, the first time" % label, env).strip()[:80])
        timed(argv + ["--version"], "%s --version, again" % label, env)
        text = timed(argv + ["watch", "--host", "--rounds", "5", "--every", "4", "--no-open", "--no-page"],
                     "%s watch --host, five rounds every 4 s" % label, env, watch=True)
        said(text, label)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
