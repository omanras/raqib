"""The rig's service run (ADR-0013 A-9): `raqib service` on the rig's Linux machine, as root. It writes what it saw as
JSON for tools/rig/check.py (--service), which states X28 to X30; it judges nothing itself.

    sudo python3 tools/rig/service_run.py --out FACTS.json [--work DIR]

X28: a venv made in a folder every user can write (made here, mode 0777), raqib installed in it, and its
`raqib service install --no-start`: the exit, what it said, and whether a unit is there after (it must be
refused, exit 2, with the path said, and write nothing).
X29: a folder made here root's alone (under ROOT_PLACE, mode 0755), a venv in it by the system's own
interpreter (SYSTEM_PYTHON; the venv's python is a link to it), raqib installed in it from a copy of this
checkout (pip's build leaves nothing of root's in the checkout), then `raqib service install`; the unit waited
for until systemctl says it is active; the rig's stand-in agent (tools/rig/workload.py, copied there, readable
by all) run as a second user (AGENT_USER, made if missing) by systemd-run --uid, so that it is a tree of its
own and not under this run's; its main pid; and the service's events (EVENTS) read for a finding on that tree
(its subject.tree begins with that pid), after the stand-in ended or for at most SEEN_S more.
X30: `raqib service remove --purge`: its exit and words, whether the unit's file is left, and systemctl's
LoadState of the unit (not-found where no unit is left). Then the rig cleans up after itself: where a unit is
still there, it stops, disables and removes it by systemctl and says so (that is not X30's fact). The second
user, the venvs and the folders are left for the machine to throw away.

It never raises: each case is its own, an error in one is a fact of that case; off Linux nothing is run and the
reason is the fact (n/a), and not as root it is an error. Facts written, exit 0 whatever happened (2 only for
its own usage). Every program is started by `run` (a test hands its own; no test needs root, Linux or
systemctl); the waits go through SLEEP and CLOCK. Stdlib only; never imported by raqib.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PLATFORM = sys.platform
UNIT = "raqib-watch.service"
UNIT_PATH = "/etc/systemd/system/raqib-watch.service"
EVENTS = "/var/lib/raqib/.raqib/host/events.jsonl"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEM_PYTHON = "/usr/bin/python3"
ROOT_PLACE = "/usr/local/lib"          # where the rig makes root's own folder (X29)
AGENT_USER = "raqib-rig-agent"         # the second user (made up; made here if missing)
WORKLOAD = os.path.join(HERE, "workload.py")
ACTIVE_S = 90.0                        # the unit is waited for until active for at most this long
WORKLOAD_S = 240.0                     # the stand-in may run this long
SEEN_S = 90.0                          # after the stand-in ended, the events are read for this long more
POLL_S = 2.0
KEPT = 40                              # findings kept in the facts
SAID = 1500                            # characters of a program's words kept
SLEEP = time.sleep
CLOCK = time.monotonic


def euid():
    return os.geteuid()


def run(argv, timeout=120.0):
    """{"argv", "exit", "out", "err"} of one program, never raised: a timeout or a failed start is exit None and
    its reason. No shell; the folder /."""
    try:
        got = subprocess.run(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd="/", timeout=timeout, check=False)
        return {"argv": list(argv), "exit": got.returncode, "out": got.stdout.decode("utf-8", "replace")[-SAID:],
                "err": got.stderr.decode("utf-8", "replace")[-SAID:]}
    except subprocess.TimeoutExpired:
        return {"argv": list(argv), "exit": None, "out": "", "err": "no end in %d s (stopped)" % timeout}
    except OSError as exc:
        return {"argv": list(argv), "exit": None, "out": "", "err": "cannot be run (%s)" % type(exc).__name__}


def copy_source(dest):
    """The checkout's files that `pip install` builds from, copied (no .git, no caches): a build as root leaves
    nothing of root's in the runner's checkout."""
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.egg-info", "build", "dist",
                                                              ".pytest_cache", ".venv", "venv*"))
    return dest


def make_venv(venv, src):
    """A venv by the system's interpreter and raqib installed in it from src: {"venv", "pip"} as run says them,
    "error" where one failed."""
    made = run([SYSTEM_PYTHON, "-m", "venv", venv], timeout=300)
    out = {"venv": made}
    if made["exit"] != 0:
        out["error"] = "the venv cannot be made: %s" % (made["err"] or made["exit"])
        return out
    pip = run([venv + "/bin/python", "-m", "pip", "install", "--no-cache-dir", "--disable-pip-version-check",
               "--quiet", src], timeout=900)
    out["pip"] = pip
    if pip["exit"] != 0:
        out["error"] = "raqib cannot be installed in the venv: %s" % (pip["err"] or pip["exit"])
    return out


def raqib(venv, *args, timeout=300.0):
    return run([venv + "/bin/python", "-I", "-m", "raqib", "service"] + list(args), timeout=timeout)


def x28(work, src, out):
    """An install from a place every user can write: refused, nothing written. Its facts go into `out` as they
    are seen (an error later keeps them)."""
    place = tempfile.mkdtemp(prefix="raqib-x28-", dir=work)
    os.chmod(place, 0o777)
    out.update(place=place, mode="0777", unit_before=os.path.lexists(UNIT_PATH))
    made = make_venv(os.path.join(place, "venv"), src)
    if made.get("error"):
        out["error"] = made["error"]
        return
    got = raqib(os.path.join(place, "venv"), "install", "--no-start")
    out.update(exit=got["exit"], said=(got["err"] + got["out"]).strip(), unit_after=os.path.lexists(UNIT_PATH))


def systemctl(*args, timeout=60.0):
    return run([SYSTEMCTL] + list(args), timeout=timeout)


def wait_for(ask, done, limit):
    """ask() again every POLL_S until done(answer) or `limit` seconds: (the last answer, times asked)."""
    end, asked = CLOCK() + limit, 0
    while True:
        asked += 1
        answer = ask()
        if done(answer) or CLOCK() >= end:
            return answer, asked
        SLEEP(POLL_S)


def findings(pid):
    """(events read, every finding as {rule, tree, summary} (at most KEPT), those on the tree of `pid`)."""
    try:
        with open(EVENTS, "rb") as f:
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return 0, [], []
    found = []
    for line in lines:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict) or ev.get("kind") != "finding":
            continue
        rule = ev.get("rule") if isinstance(ev.get("rule"), dict) else {}
        subject = ev.get("subject") if isinstance(ev.get("subject"), dict) else {}
        found.append({"rule": str(rule.get("id")), "tree": str(subject.get("tree")),
                      "summary": str(ev.get("summary"))[:200]})
    mine = [f for f in found if pid and f["tree"].split(":", 1)[0] == str(pid)]
    return len(lines), found[-KEPT:], mine


def x29(work, src, out):
    """An install from root's own place: an active unit that sees a second user's stand-in agent. Its facts go
    into `out` as they are seen."""
    place = tempfile.mkdtemp(prefix="raqib-rig-", dir=ROOT_PLACE)
    os.chmod(place, 0o755)
    venv = os.path.join(place, "venv")
    out.update(place=place)
    made = make_venv(venv, src)
    if made.get("error"):
        out["error"] = made["error"]
        return
    out["venv"] = venv
    got = raqib(venv, "install")
    out["install"] = {"exit": got["exit"], "said": (got["out"] + got["err"]).strip()}
    answer, asked = wait_for(lambda: systemctl("is-active", UNIT), lambda a: a["out"].strip() == "active", ACTIVE_S)
    out["active"], out["active_asked"] = answer["out"].strip() or answer["err"].strip(), asked
    if run(["id", "-u", AGENT_USER])["exit"] != 0:
        made = run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", AGENT_USER])
        out["useradd"] = made["exit"]
    uid = run(["id", "-u", AGENT_USER])
    out["user"] = {"name": AGENT_USER, "uid": uid["out"].strip() if uid["exit"] == 0 else None}
    copy = os.path.join(place, "workload.py")
    shutil.copyfile(WORKLOAD, copy)
    os.chmod(copy, 0o644)
    agent = "raqib-rig-agent-%d" % os.getpid()
    started = run(["systemd-run", "--uid=" + AGENT_USER, "--collect", "--unit=" + agent, "--quiet", SYSTEM_PYTHON,
                   copy], timeout=60)
    pid = systemctl("show", "--property=MainPID", "--value", agent)["out"].strip()
    out["agent"] = {"unit": agent, "exit": started["exit"], "err": started["err"].strip(),
                    "pid": int(pid) if pid.isdigit() and pid != "0" else None}
    ended, _ = wait_for(lambda: systemctl("is-active", agent), lambda a: a["out"].strip() != "active", WORKLOAD_S)
    out["agent"]["ended"] = ended["out"].strip()
    seen, asked = wait_for(lambda: findings(out["agent"]["pid"]), lambda f: bool(f[2]), SEEN_S)
    out["events"], out["findings"], out["mine"], out["read_asked"] = seen[0], seen[1], seen[2], asked
    status = raqib(venv, "status", timeout=60)
    out["status"] = {"exit": status["exit"], "said": status["out"].strip()}


def x30(venv):
    """The removal leaves no unit: raqib's own removal, judged before the rig cleans up anything."""
    out = {}
    if venv:
        got = raqib(venv, "remove", "--purge")
        out.update(exit=got["exit"], said=(got["out"] + got["err"]).strip())
    else:
        out["error"] = "no venv of root's to run the removal from (X29 made none)"
    out["unit_file"] = os.path.lexists(UNIT_PATH)
    show = systemctl("show", "--property=LoadState", "--value", UNIT)
    out["load_state"] = show["out"].strip() if show["exit"] == 0 else None
    return out


def clean_up(facts):
    """What raqib's own removal left: the unit stopped, disabled, removed; the stand-in's unit stopped."""
    done = []
    agent = ((facts.get("x29") or {}).get("agent") or {}).get("unit")
    if agent:
        done.append(systemctl("stop", agent)["exit"])
    if os.path.lexists(UNIT_PATH):
        done.append(systemctl("disable", "--now", UNIT)["exit"])
        try:
            os.unlink(UNIT_PATH)
            done.append("removed %s" % UNIT_PATH)
        except OSError as exc:
            done.append("%s cannot be removed (%s)" % (UNIT_PATH, type(exc).__name__))
        done.append(systemctl("daemon-reload")["exit"])
    return done


def cases(work):
    facts = {}
    src = copy_source(os.path.join(work, "src"))
    for name, case in (("x28", x28), ("x29", x29)):
        facts[name] = {}
        try:
            case(work, src, facts[name])
        except Exception as exc:   # one case's error is that case's fact; what it saw before stays
            facts[name]["error"] = "%s: %s" % (type(exc).__name__, exc)
    try:
        facts["x30"] = x30(facts["x29"].get("venv"))   # the venv is said only once raqib is installed in it
    except Exception as exc:
        facts["x30"] = {"error": "%s: %s" % (type(exc).__name__, exc)}
    try:
        facts["cleanup"] = clean_up(facts)
    except Exception as exc:
        facts["cleanup"] = ["%s: %s" % (type(exc).__name__, exc)]
    return facts


def main(argv=None):
    p = argparse.ArgumentParser(prog="tools/rig/service_run.py")
    p.add_argument("--out", required=True)
    p.add_argument("--work")
    a = p.parse_args(argv)
    facts = {"platform": PLATFORM}
    try:
        if not PLATFORM.startswith("linux"):
            facts["not_run"] = "not Linux (%s): the service is a unit of systemd's (ADR-0013 A-2, S1)" % PLATFORM
        elif euid() != 0:
            facts["error"] = "not run as root (uid %d): the rig runs it with sudo" % euid()
        else:
            work = os.path.abspath(a.work or tempfile.mkdtemp(prefix="raqib-service-rig-"))
            os.makedirs(work, exist_ok=True)
            facts["work"] = work
            facts.update(cases(work))
    except Exception as exc:
        facts["error"] = "%s: %s" % (type(exc).__name__, exc)
    try:
        with open(a.out, "w", encoding="ascii") as f:
            json.dump(facts, f, indent=1, ensure_ascii=True)
        print("service_run: facts in %s" % a.out)
    except OSError as exc:
        print("service_run: the facts cannot be written to %s (%s)" % (a.out, type(exc).__name__))
    return 0


if __name__ == "__main__":
    sys.exit(main())
