"""Probe only (never merged): what a program packed with its own runtime reads of its environment when it starts,
and what it hands to a program it starts (ADR-0007 Amendment CH-3, for M17.2b). The instrument is
packed_env_entry.py, run three ways under the same variables: packed; by the machine's Python with -I (the road
of the plain helper); by the machine's Python with no flag (the control: there the planted things must be taken,
or the probe proves nothing). The planted modules only set a name and append a word to a file in the runner's
temp folder; the folders named in the packer's and the loader's variables are empty. Nothing outside the
runner's temp folder is written.

usage: packed_env_probe.py PACKED_ENTRY [--raqib PACKED_RAQIB]"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENTRY = os.path.join(HERE, "packed_env_entry.py")
WATCHED = ("_PYI", "_MEI", "PYI", "LD_", "DYLD_", "PYTHON", "TCL", "TK_", "SSL_", "GCONV", "LOCPATH")
PLANT = "PLANTED = True\nimport os\nwith open(os.environ['RAQIB_PROBE_MARK'], 'a') as f:\n    f.write(%r + '\\n')\n"


def hashed(v):
    import hashlib
    return "#" + hashlib.sha256(v.encode("utf-8", "replace")).hexdigest()[:10]


def told(k):
    return k.upper().startswith(WATCHED) or k.upper() == "PATH"


def env_diff(handed, seen):
    """What differs between the environment handed and the one seen: (added, removed, changed) as text."""
    fold = (lambda k: k.upper()) if sys.platform == "win32" else (lambda k: k)
    h = dict((fold(k), v) for k, v in handed.items())
    s = dict((fold(k), v) for k, v in seen.items())
    out = []
    for k in sorted(set(s) - set(h)):
        out.append("+%s=%s" % (k, s[k][:200] if told(k) else "(a value)"))
    for k in sorted(set(h) - set(s)):
        out.append("-%s" % k)
    for k in sorted(set(h) & set(s)):
        was = h[k] if told(k) else hashed(h[k])
        if was != s[k]:
            if k == "PATH":
                a, b = h[k].split(os.pathsep), s[k].split(os.pathsep)
                out.append("~PATH: added %s; removed %s" % ([x for x in b if x not in a][:6],
                                                           [x for x in a if x not in b][:6]))
            else:
                out.append("~%s: %s -> %s" % (k, was[:120], s[k][:120]) if told(k) else "~%s (its value)" % k)
    return out


def run(argv, env):
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=120, errors="replace")
        code, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as exc:
        code, out, err = "none (killed after 120 s)", exc.stdout or "", exc.stderr or ""
        out = out if isinstance(out, str) else out.decode("utf-8", "replace")
        err = err if isinstance(err, str) else err.decode("utf-8", "replace")
    got = None
    for line in out.splitlines():
        if line.startswith("PROBE_JSON "):
            got = json.loads(line[len("PROBE_JSON "):])
    return code, got, err, time.monotonic() - t0


def say(label, way, code, got, err, env, mark, base):
    marked = open(mark).read().split() if os.path.exists(mark) else []
    imports = sum(1 for l in err.splitlines() if l.startswith("import ") or l.startswith("# "))
    print("  [%s] exit %s; planted modules that ran: %s; lines of the interpreter's own on stderr: %d"
          % (way, code, marked or "none", imports))
    if got is None:
        first = [l for l in err.splitlines() if l.strip() and not l.startswith(("import ", "# "))][:3]
        print("      it said nothing of itself. stderr: %s" % (" | ".join(x[:200] for x in first) or "(empty)"))
        return
    flags = dict((k, v) for k, v in got["flags"].items() if base is None or base["flags"].get(k) != v)
    print("      flags%s: %s" % (" (all)" if base is None else " that differ from its plain run", flags or "none"))
    print("      took: %s; site: %s; warnoptions: %s; hash('a') %s"
          % (got["taken"], got["site"] or "none", got["warnoptions"] or "none",
             "as its plain run" if base is not None and base["hash_a"] == got["hash_a"] else got["hash_a"]))
    if base is None or base["home"] != got["home"] or base["prefix"] != got["prefix"]:
        print("      home: %s; prefix: %s" % (got["home"], got["prefix"]))
    if base is None or base["path"] != got["path"]:
        print("      search path: %s" % got["path"])
    print("      its environment beside the one handed: %s" % (env_diff(env, got["env"]) or "the same"))
    if "dll_directory" in got:
        print("      the folder Windows searches first for it: %r" % got["dll_directory"])
    if "reset" in got:
        print("      the folder put back to none at its start: %s; then %r" % (got["reset"], got.get("after_reset")))
    bad = dict((k, v) for k, v in got.get("late", {}).items() if v != "ok" and "No module named" not in v)
    print("      modules with a library of their own, loaded late: %d ok (%s were loaded already), failed: %s; "
          "ssl %s; sqlite %s" % (sum(1 for v in got.get("late", {}).values() if v == "ok"),
                                 got.get("loaded_before") or "none", bad or "none", got.get("ssl"), got.get("sqlite")))
    me = got.get("self_cleaned")
    if me is not None:
        if "env" in me:
            whole = me["flags"] == got["flags"] and me["home"] == got["home"] and not [
                v for k, v in me["late"].items() if got["late"].get(k) != v]
            print("      itself, started with the cleaned environment: %s; its environment beside the one handed "
                  "to its parent: %s%s" % ("whole (the same flags, home and late modules)" if whole else
                                           "NOT as its parent: %s" % me["flags"], env_diff(env, me["env"]) or "the same",
                                           "; the folder Windows searches first for it: %r" % me["dll_directory"]
                                           if "dll_directory" in me else ""))
        else:
            print("      itself, started with the cleaned environment: did not run: %s" % me)
    for child in ("child_inherited", "child_handed", "child_cleaned"):
        c = got.get(child)
        if c is None:
            continue
        if "env" not in c:
            print("      %s: did not run: %s" % (child, c))
            continue
        print("      %s: its environment beside the one handed to its parent: %s%s"
              % (child, env_diff(env, c["env"]) or "the same",
                 "; the folder Windows searches first for it: %r" % c["dll_directory"] if "dll_directory" in c
                 else ""))


def scenarios(temp, packed):
    plant = os.path.join(temp, "plant")
    empty = os.path.join(temp, "empty")
    os.makedirs(plant, exist_ok=True)
    os.makedirs(empty, exist_ok=True)
    for name in ("raqib_probe_planted", "colorsys", "sitecustomize", "startup"):
        with open(os.path.join(plant, name + ".py"), "w") as f:
            f.write(PLANT % name)
    nothing = os.path.join(temp, "nothing.bin")
    open(nothing, "w").close()
    lib = {"linux": {"LD_LIBRARY_PATH": empty}, "darwin": {"DYLD_LIBRARY_PATH": empty,
                                                         "DYLD_FALLBACK_LIBRARY_PATH": empty}}
    yield "plain", {}
    yield "plain, and on Windows the folder searched first put back to none at the start", {"RAQIB_PROBE_RESET": "1"}
    yield "the interpreter's variables", {
        "PYTHONPATH": plant, "PYTHONVERBOSE": "1", "PYTHONINSPECT": "1", "PYTHONOPTIMIZE": "2",
        "PYTHONHASHSEED": "0", "PYTHONUTF8": "1", "PYTHONDEVMODE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1", "PYTHONSTARTUP": os.path.join(plant, "startup.py"), "PYTHONWARNINGS": "ignore"}
    yield "the interpreter's home (an empty folder)", {"PYTHONHOME": empty}
    yield "the loader's search path (an empty folder)", lib.get(sys.platform, {"PATH": empty + os.pathsep
                                                                              + os.environ.get("PATH", "")})
    yield "the packer's: _MEIPASS2 (an empty folder)", {"_MEIPASS2": empty}
    yield "the packer's: _PYI_APPLICATION_HOME_DIR alone (an empty folder)", {"_PYI_APPLICATION_HOME_DIR": empty}
    yield "the packer's: _PYI_ARCHIVE_FILE alone (an empty file)", {"_PYI_ARCHIVE_FILE": nothing}
    yield "the packer's: _PYI_PARENT_PROCESS_LEVEL alone", {"_PYI_PARENT_PROCESS_LEVEL": "1"}
    yield "the packer's: as a packed parent of the same program leaves them, the home an empty folder", {
        "_PYI_ARCHIVE_FILE": packed, "_PYI_APPLICATION_HOME_DIR": empty, "_PYI_PARENT_PROCESS_LEVEL": "1"}
    yield "the packer's: PYINSTALLER_RESET_ENVIRONMENT", {"PYINSTALLER_RESET_ENVIRONMENT": "1"}


def proc_environ(pid):
    with open("/proc/%d/environ" % pid, "rb") as f:
        raw = f.read().split(b"\0")
    out = {}
    for item in raw:
        if b"=" in item:
            k, v = item.split(b"=", 1)
            k, v = k.decode("utf-8", "replace"), v.decode("utf-8", "replace")
            out[k] = v if told(k) else hashed(v)
    return out


def raqib_itself(exe, temp):
    """Linux: main's Raqib packed, in a short host watch, with a loader's and an interpreter's variable set: the
    environment the system holds for the watch and for every process under it, beside the one handed."""
    plant, empty = os.path.join(temp, "plant"), os.path.join(temp, "empty")
    mark = os.path.join(temp, "mark-raqib")
    home = os.path.join(temp, "home")
    os.makedirs(home, exist_ok=True)
    env = dict(os.environ, HOME=home, RAQIB_PROBE_MARK=mark, PYTHONPATH=plant, LD_LIBRARY_PATH=empty)
    p = subprocess.Popen([exe, "watch", "--host", "--rounds", "5", "--every", "3", "--no-open", "--no-page"],
                         env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    seen = {}
    until = time.monotonic() + 12
    while time.monotonic() < until and p.poll() is None:
        parents = {}
        for name in os.listdir("/proc"):
            if name.isdigit():
                try:
                    with open("/proc/%s/stat" % name) as f:
                        rest = f.read().rsplit(")", 1)[1].split()
                    parents[int(name)] = int(rest[1])
                except (OSError, IndexError, ValueError):
                    pass
        for pid in parents:
            chain, at = [], pid
            while at in parents and at != p.pid and len(chain) < 8:
                chain.append(at)
                at = parents[at]
            if (at == p.pid) and pid not in seen:
                try:
                    with open("/proc/%d/cmdline" % pid, "rb") as f:
                        argv = [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]
                    seen[pid] = (len(chain), argv[:3], proc_environ(pid))
                except OSError:
                    pass
        time.sleep(0.2)
    out, err = p.communicate(timeout=120)
    print("RAQIB ITSELF, packed, in a host watch: exit %s; planted modules that ran: %s"
          % (p.returncode, open(mark).read().split() if os.path.exists(mark) else "none"))
    for pid, (depth, argv, e) in sorted(seen.items(), key=lambda kv: (kv[1][0], kv[0])):
        short = [os.path.basename(a)[:60] if i == 0 else a[:60] for i, a in enumerate(argv)]
        print("  %s %s: the system's record of its environment beside the one handed to the watch: %s"
              % ("the watch" if depth == 0 else "under it (depth %d)" % depth, short, env_diff(env, e) or "the same"))
    for line in (out + err).splitlines():
        if any(w in line for w in ("PROCESS EVENTS", "helper", "Traceback", "rounds asked")):
            print("    " + line[:220])


def own_itself(exe, temp):
    """The branch's raqib.own and Raqib's entry, packed (packed_env_entry2.py): what they did on this machine."""
    empty = os.path.join(temp, "empty")
    os.makedirs(empty, exist_ok=True)
    lib = {"linux": {"LD_LIBRARY_PATH": empty}, "darwin": {"DYLD_LIBRARY_PATH": empty}}.get(sys.platform, {})
    for label, extra in (("plain", {}), ("a loader's path handed, and the packer's older name",
                                         dict(lib, _MEIPASS2=empty))):
        env = dict(os.environ)
        env.update(extra)
        code, got, err, took = run([exe, sys.executable], env)
        print("OWN, packed, %s: exit %s" % (label, code))
        if got is None:
            print("    it said nothing. stderr: %s" % " | ".join(err.splitlines()[-4:])[:600])
            continue
        print("    the entry: exit %s, said %r; own.LIBRARY_FOLDER %s; the hole's words: %s"
              % (got["entry_exit"], got["entry_said"], got["library_folder"], got["hole"]))
        if "dll_directory" in got["before"]:
            print("    the folder Windows searches first: before the entry %r; after it %r; for what it starts %r"
                  % (got["before"]["dll_directory"], got["after"]["dll_directory"],
                     got["child"].get("dll_directory", got["child"])))
        bad = dict((k, v) for k, v in got["late"].items() if v != "ok" and "No module named" not in v)
        print("    modules with a library of their own, loaded after the entry: %d ok, failed: %s"
              % (sum(1 for v in got["late"].values() if v == "ok"), bad or "none"))
        print("    its own environment beside the one handed to it: %s" % (env_diff(env, got["after"]["env"]) or "the same"))
        print("    own.handed() beside the one handed to it: %s" % (env_diff(env, got["handed"]) or "the same"))
        if "env" in got["child"]:
            print("    what it starts with own.handed() sees, beside the one handed to it: %s"
                  % (env_diff(env, got["child"]["env"]) or "the same"))
        else:
            print("    what it starts did not run: %s" % got["child"])


def main(argv):
    if argv[1] == "--own":
        temp = os.path.join(os.environ.get("RUNNER_TEMP") or os.getcwd(), "packed-env")
        os.makedirs(temp, exist_ok=True)
        print("PLATFORM %s; python %s" % (sys.platform, sys.version.split()[0]))
        own_itself(os.path.abspath(argv[2]), temp)
        if "--raqib" in argv and sys.platform == "linux":
            os.makedirs(os.path.join(temp, "plant"), exist_ok=True)
            raqib_itself(os.path.abspath(argv[argv.index("--raqib") + 1]), temp)
        return 0
    packed = os.path.abspath(argv[1])
    temp = os.path.join(os.environ.get("RUNNER_TEMP") or os.getcwd(), "packed-env")
    os.makedirs(temp, exist_ok=True)
    print("PLATFORM %s; python %s; packed entry %s" % (sys.platform, sys.version.split()[0], os.path.basename(packed)))
    ways = (("packed", [packed, sys.executable]), ("python -I", [sys.executable, "-I", ENTRY, sys.executable]),
            ("python, no flag (the control)", [sys.executable, ENTRY, sys.executable]))
    base = {}
    for n, (label, extra) in enumerate(scenarios(temp, packed)):
        print("SCENARIO %s: %s" % (label, sorted(extra)))
        for way, args in ways:
            if label.startswith("the packer's") and way != "packed":
                continue
            mark = os.path.join(temp, "mark-%d-%s" % (n, way.split()[0].replace(",", "")))
            env = dict(os.environ, RAQIB_PROBE_MARK=mark)
            env.update(extra)
            code, got, err, took = run(args, env)
            say(label, way, code, got, err, env, mark, base.get(way))
            if label == "plain":
                base[way] = got
    if "--raqib" in argv and sys.platform == "linux":
        raqib_itself(os.path.abspath(argv[argv.index("--raqib") + 1]), temp)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
