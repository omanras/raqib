"""Probe only (never merged): what Raqib could read of Windows' autostart places by itself, with the standard
library and no right asked, before ADR-0014's S3 is ruled (M15.3). It measures, on a machine made for the job:
  A. each place read once: how many entries, how long, what it refuses (run keys of the user's hive, the
     machine's and every loaded hive, both views; the Startup folders; the scheduler's tree in the registry and
     its folder of files; the services' key; Winlogon's two values);
  B. a quiet minute and a half: what changes in those places with nothing done;
  C. four acts, each harmless (the command is `cmd /c echo`) and each undone: a Run value, a file in the Startup
     folder, a scheduled task, a service that is never started; how long until a read shows each, what the read
     shows, and that the undoing shows too;
  D. with --reads alone it does A and writes it to a file: run under a token of fewer rights, to see what a
     plain user's watch could read.
It is never imported by raqib."""
import hashlib
import json
import os
import subprocess
import sys
import time
import winreg

HARMLESS = "cmd /c echo benign-persistence-test"
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUNONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
WINLOGON = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
TREE = r"Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
TASKS = r"Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
SERVICES = r"System\CurrentControlSet\Services"
VIEWS = (("64", winreg.KEY_WOW64_64KEY), ("32", winreg.KEY_WOW64_32KEY))


def digest(value):
    data = value if isinstance(value, bytes) else repr(value).encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()[:12]


def values(root, path, view, names=None):
    """{name: digest of its data} of one key; an OSError is raised to the caller."""
    out = {}
    with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
        i = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            if names is None or name in names:
                out[name] = digest(data)
    return out


def subkeys(root, path, view=0):
    with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
        i, out = 0, []
        while True:
            try:
                out.append(winreg.EnumKey(key, i))
            except OSError:
                return out
            i += 1


def place(name, read, out):
    began = time.perf_counter()
    try:
        got, refused = read()
        err = None
    except OSError as exc:
        got, refused, err = {}, 0, "%s: %s" % (type(exc).__name__, exc)
    out["places"][name] = {"entries": got, "refused": refused, "error": err,
                           "seconds": round(time.perf_counter() - began, 4)}


def run_keys():
    got, refused = {}, 0
    roots = [("HKCU", winreg.HKEY_CURRENT_USER, ""), ("HKLM", winreg.HKEY_LOCAL_MACHINE, "")]
    try:
        for sid in subkeys(winreg.HKEY_USERS, ""):
            if not sid.endswith("_Classes"):
                roots.append(("HKU/" + ("S-..." + sid[-4:] if sid.startswith("S-1-5-21") else sid),
                              winreg.HKEY_USERS, sid + "\\"))
    except OSError:
        refused += 1
    for label, root, prefix in roots:
        for key in (RUN, RUNONCE):
            for vname, view in VIEWS:
                try:
                    for name, d in values(root, prefix + key, view).items():
                        got["%s %s %s %s" % (label, key.rsplit("\\", 1)[1], vname, name)] = d
                except FileNotFoundError:
                    pass
                except OSError:
                    refused += 1
    return got, refused


def startup_folders():
    got, refused = {}, 0
    for label, base in (("user", os.environ.get("APPDATA")), ("all", os.environ.get("ProgramData"))):
        folder = os.path.join(base or "", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        try:
            for entry in os.scandir(folder):
                st = entry.stat()
                got["%s %s" % (label, entry.name)] = "%d %d" % (st.st_size, st.st_mtime_ns)
        except FileNotFoundError:
            pass
        except OSError:
            refused += 1
    return got, refused


def task_tree():
    """The scheduler's tree in the registry: {task path: digest of its Id and of its Actions and Triggers}."""
    got, refused, todo = {}, 0, [""]
    while todo:
        at = todo.pop()
        try:
            kids = subkeys(winreg.HKEY_LOCAL_MACHINE, TREE + ("\\" + at if at else ""))
        except OSError:
            refused += 1
            continue
        for kid in kids:
            todo.append(at + "\\" + kid if at else kid)
        if not at:
            continue
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TREE + "\\" + at) as key:
                task_id = winreg.QueryValueEx(key, "Id")[0]
        except FileNotFoundError:
            continue   # a folder of tasks, not a task
        except OSError:
            refused += 1
            continue
        try:
            body = values(winreg.HKEY_LOCAL_MACHINE, TASKS + "\\" + task_id, 0, names=("Actions", "Triggers", "Path"))
            got[at] = "%s %s" % (body.get("Actions", "-"), body.get("Triggers", "-"))
        except OSError:
            refused += 1
            got[at] = "id only"
    return got, refused


def task_files():
    got, refused = {}, 0
    folder = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")

    def bad(_exc):
        nonlocal refused
        refused += 1
    for base, _dirs, files in os.walk(folder, onerror=bad):
        for name in files:
            path = os.path.join(base, name)
            try:
                st = os.stat(path)
                got[os.path.relpath(path, folder)] = "%d %d" % (st.st_size, st.st_mtime_ns)
            except OSError:
                refused += 1
    return got, refused


def services():
    got, refused = {}, 0
    for name in subkeys(winreg.HKEY_LOCAL_MACHINE, SERVICES):
        try:
            body = values(winreg.HKEY_LOCAL_MACHINE, SERVICES + "\\" + name, 0, names=("ImagePath", "Start", "Type"))
        except OSError:
            refused += 1
            continue
        if "ImagePath" in body:
            got[name] = "%s %s %s" % (body["ImagePath"], body.get("Start", "-"), body.get("Type", "-"))
    return got, refused


def winlogon():
    return values(winreg.HKEY_LOCAL_MACHINE, WINLOGON, winreg.KEY_WOW64_64KEY, names=("Shell", "Userinit")), 0


PLACES = (("run keys", run_keys), ("startup folders", startup_folders), ("task tree (registry)", task_tree),
          ("task files", task_files), ("services", services), ("winlogon", winlogon))


def schtasks_query():
    """What the scheduler's own tool tells a caller of any rights: how many tasks, how long (a helper process)."""
    began = time.perf_counter()
    try:
        done = subprocess.run(["schtasks", "/query", "/fo", "csv", "/nh"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": "%s" % exc, "seconds": round(time.perf_counter() - began, 3)}
    rows = [x for x in done.stdout.decode("utf-8", "replace").splitlines() if x.startswith('"')]
    names = {x.split('","')[0].strip('"') for x in rows}
    return {"exit": done.returncode, "rows": len(rows), "tasks": len(names),
            "ours": sum(1 for n in names if "RaqibRig" in n), "stderr": len(done.stderr),
            "seconds": round(time.perf_counter() - began, 3)}


def read_all():
    out = {"places": {}}
    began = time.perf_counter()
    for name, read in PLACES:
        place(name, read, out)
    out["seconds"] = round(time.perf_counter() - began, 4)
    return out


def flat(snap):
    return {(p, k): v for p, body in snap["places"].items() for k, v in body["entries"].items()}


def changes(before, after):
    a, b = flat(before), flat(after)
    return (sorted(k for k in b if k not in a), sorted(k for k in a if k not in b),
            sorted(k for k in b if k in a and a[k] != b[k]))


def say_read(snap, label):
    print("READ %s: all places in %.3f s" % (label, snap["seconds"]))
    for name, body in snap["places"].items():
        print("  %-22s %5d entries, %d refused, %.4f s%s" % (name, len(body["entries"]), body["refused"],
                                                           body["seconds"],
                                                           "" if body["error"] is None else "; " + body["error"]))


def quiet(seconds, every):
    first = last = read_all()
    costs, moved, end = [], {}, time.monotonic() + seconds
    while time.monotonic() < end:
        time.sleep(every)
        now = read_all()
        costs.append(now["seconds"])
        added, gone, changed = changes(last, now)
        for kind, keys in (("added", added), ("gone", gone), ("changed", changed)):
            for key in keys:
                moved.setdefault((kind,) + key, 0)
                moved[(kind,) + key] += 1
        last = now
    print("QUIET %d s, a read every %d s: %d reads, slowest %.3f s, mean %.3f s" % (
        seconds, every, len(costs), max(costs), sum(costs) / len(costs)))
    if not moved:
        print("  nothing changed in any place")
    for key, times in sorted(moved.items()):
        print("  %s in %s: %s (%d time(s))" % (key[0], key[1], key[2], times))
    added, gone, changed = changes(first, last)
    print("  first read against last: %d added, %d gone, %d changed" % (len(added), len(gone), len(changed)))


def call(argv):
    done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    return done.returncode, done.stdout.decode("utf-8", "replace").strip().replace("\r\n", " | ")[:200]


def shown(base, want, within=10.0):
    """Reads until a change of the kind `want` (0 added, 1 gone) is there: (seconds waited, the changes)."""
    began = time.monotonic()
    while True:
        got = changes(base, read_all())
        if got[want] or time.monotonic() - began > within:
            return round(time.monotonic() - began, 2), got
        time.sleep(0.2)


def act(name, do, undo):
    base = read_all()
    code, said = do()
    print("ACT %s: exit %s%s" % (name, code, "" if not said else "; " + said))
    waited, (added, gone, changed) = shown(base, 0)
    print("  shown after %.2f s: added %s; changed %s; gone %s" % (waited, added, changed, gone))
    mid = read_all()
    code, said = undo()
    print("  undone: exit %s%s" % (code, "" if not said else "; " + said))
    waited, (added, gone, changed) = shown(mid, 1)
    print("  the undoing shown after %.2f s: gone %s; added %s; changed %s" % (waited, gone, added, changed))
    left = changes(base, read_all())
    print("  left against before the act: %s" % ("nothing" if left == ([], [], []) else (left,)))


def acts():
    def run_value():
        return call(["reg", "add", "HKCU\\" + RUN, "/v", "RaqibRigProbe", "/t", "REG_SZ", "/d", HARMLESS, "/f"])

    def run_value_undo():
        return call(["reg", "delete", "HKCU\\" + RUN, "/v", "RaqibRigProbe", "/f"])
    startup = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
                           "raqib-rig-probe.cmd")

    def startup_file():
        os.makedirs(os.path.dirname(startup), exist_ok=True)
        with open(startup, "w", encoding="ascii") as f:
            f.write("rem benign-persistence-test\n")
        return 0, ""

    def startup_undo():
        os.remove(startup)
        return 0, ""

    def task():
        return call(["schtasks", "/create", "/tn", "RaqibRigProbe", "/tr", HARMLESS, "/sc", "once", "/st", "23:59",
                     "/f"])

    def task_undo():
        return call(["schtasks", "/delete", "/tn", "RaqibRigProbe", "/f"])

    def service():
        return call(["sc", "create", "RaqibRigProbe", "binPath=", r"C:\Windows\System32\cmd.exe /c echo",
                     "start=", "demand"])

    def service_undo():
        return call(["sc", "delete", "RaqibRigProbe"])
    act("a Run value (reg.exe)", run_value, run_value_undo)
    act("a file in the Startup folder", startup_file, startup_undo)
    act("a scheduled task (schtasks.exe)", task, task_undo)
    act("a service never started (sc.exe)", service, service_undo)


def main(argv):
    if "--reads" in argv:
        snap = read_all()
        with open(argv[argv.index("--reads") + 1], "w", encoding="utf-8") as f:
            json.dump({"seconds": snap["seconds"],
                       "places": {k: {"entries": len(v["entries"]), "refused": v["refused"], "error": v["error"],
                                      "seconds": v["seconds"]} for k, v in snap["places"].items()},
                       "schtasks": [schtasks_query(), schtasks_query()]}, f)
        return 0
    first = read_all()
    say_read(first, "first (this process's own rights)")
    say_read(read_all(), "second")
    names = sorted(first["places"]["run keys"]["entries"]) + sorted(first["places"]["startup folders"]["entries"])
    print("RUN KEYS AND STARTUP, by name: %s" % names)
    print("SCHTASKS /query, twice: %s" % json.dumps([schtasks_query(), schtasks_query()]))
    call(["schtasks", "/create", "/tn", "RaqibRigSeen", "/tr", HARMLESS, "/sc", "once", "/st", "23:59", "/f"])
    print("SCHTASKS /query with a task of this user's made: %s" % json.dumps(schtasks_query()))
    quiet(int(os.environ.get("QUIET_SECONDS", "90")), 5)
    acts()
    return 0


def cleanup():
    call(["schtasks", "/delete", "/tn", "RaqibRigSeen", "/f"])


if __name__ == "__main__":
    if "--cleanup" in sys.argv:
        cleanup()
        sys.exit(0)
    sys.exit(main(sys.argv[1:]))
