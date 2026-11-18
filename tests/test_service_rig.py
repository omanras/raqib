"""M12.1 (ADR-0013 A-9, AA-3, AA-4): the rig's service run (tools/rig/service_run.py) and its check, X28 to X30
(tools/rig/check.py --service). Every fact here is made up: no test runs as root, needs Linux, starts systemctl
or systemd-run, or writes outside its tmp folder; the run's programs are a made-up `run`, its waits a made-up
clock. The pid, uid and paths are made up.
"""
import importlib.util
import io
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


service_run = load("rig_service_run", ROOT / "tools" / "rig" / "service_run.py")
check = load("rig_check_service", ROOT / "tools" / "rig" / "check.py")
rig = load("rig_check_tests_service", ROOT / "tests" / "test_rig_check.py")
PID = 4242
FINDING = {"kind": "finding", "rule": {"id": "NEW-AGENT-UNKNOWN"}, "subject": {"tree": "%d:python3:10:00:01" % PID},
           "summary": "unknown agent tree python3"}


def met_facts():
    return {"platform": "linux",
            "x28": {"place": "/tmp/raqib-x28-ab", "mode": "0777", "exit": 2, "unit_before": False, "unit_after": False,
                    "said": "raqib: raqib service install: refused: /tmp is writable by others (mode 1777) (on the"
                            " way to /tmp/raqib-x28-ab/venv/bin/python)."},
            "x29": {"place": "/usr/local/lib/raqib-rig-ab", "venv": "/usr/local/lib/raqib-rig-ab/venv",
                    "install": {"exit": 0, "said": "RESULT: installed, enabled and started"}, "active": "active",
                    "user": {"name": "raqib-rig-agent", "uid": "998"},
                    "agent": {"unit": "raqib-rig-agent-1", "exit": 0, "pid": PID, "ended": "inactive"},
                    "events": 12, "findings": [{"rule": "NEW-AGENT-UNKNOWN", "tree": FINDING["subject"]["tree"],
                                                "summary": FINDING["summary"]}],
                    "mine": [{"rule": "NEW-AGENT-UNKNOWN", "tree": FINDING["subject"]["tree"], "summary": "x"}]},
            "x30": {"exit": 0, "said": "RESULT: removed", "unit_file": False, "load_state": "not-found"}}


def states(facts):
    return {r[0].split(" ", 1)[0]: (r[1], r[2]) for r in check.read_service(facts)}


# --- X28 to X30 from made-up facts ---------------------------------------------------------------------------------

def test_e6_x28_to_x30_are_met_from_the_facts_of_a_good_run():
    got = states(met_facts())
    assert {k: v[0] for k, v in got.items()} == {"X28": "MET", "X29": "MET", "X30": "MET"}, got
    assert "/tmp is named" in got["X28"][1] and "pid 4242" in got["X29"][1] and "NEW-AGENT-UNKNOWN" in got["X29"][1]


@pytest.mark.parametrize("key,part,value,ident,words", [
    ("x28", "exit", 0, "X28", "exit 2 (exit 0)"),
    ("x28", "said", "RESULT: installed, not started", "X28", "a path said"),
    ("x28", "unit_after", True, "X28", "no unit after it"),
    ("x29", "install", {"exit": 2, "said": "refused"}, "X29", "the install exited 2"),
    ("x29", "active", "failed", "X29", "the unit is failed, not active"),
    ("x29", "agent", {"exit": 1, "pid": None}, "X29", "the stand-in did not start as raqib-rig-agent"),
    ("x29", "mine", [], "X29", "no finding on the stand-in's tree (pid 4242) in 12 event(s); findings seen:"
                               " NEW-AGENT-UNKNOWN 4242:python3"),
    ("x30", "exit", 1, "X30", "the removal exited 1"),
    ("x30", "unit_file", True, "X30", "the unit's file is left"),
    ("x30", "load_state", "loaded", "X30", "systemctl says LoadState=loaded"),
    ("x29", "error", "the venv cannot be made: made-up", "X29", "the rig's run of it failed: the venv cannot be"),
])
def test_e6_each_of_x28_to_x30_is_missed_with_what_is_missing(key, part, value, ident, words):
    facts = met_facts()
    facts[key][part] = value
    got = states(facts)
    assert got[ident][0] == "MISSED" and words in got[ident][1], got[ident]
    assert [v[0] for k, v in got.items() if k != ident] == ["MET", "MET"]


def test_e6_not_run_off_linux_is_na_and_silence_or_garbage_is_missed_never_raised():
    assert {v for v in states({"not_run": "not Linux (win32)"}).values()} == {("n/a", "not run: not Linux (win32)")}
    assert {v[0] for v in states(None).values()} == {"MISSED"}
    assert "silence is a finding" in states(None)["X28"][1]
    assert "the service's run failed: not run as root" in states({"error": "not run as root (uid 1000)"})["X30"][1]
    assert states({"platform": "linux"})["X29"] == ("MISSED", "the rig did not run it: no facts of x29")
    for junk in ({"x28": 5, "x29": {"agent": 7, "mine": "x", "user": 3}, "x30": []}, {"x29": {"install": None}},
                 {"x28": {"said": 9, "exit": "2"}}, ["x"], "x", 7):
        rows = check.read_service(junk)
        assert len(rows) == 3 and all(r[1] in ("MISSED", "n/a", "MET") for r in rows), rows
        assert all(r[1] != "MET" for r in rows)


def test_e6_check_main_says_x28_to_x30_with_service_and_nothing_else_changes(tmp_path, capsys):
    (tmp_path / "w.out").write_text(rig.REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(rig.WORKLOAD, encoding="utf-8")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--exit-code", "1",
            "--platform", "linux"]
    assert check.main(base) == 0
    before = capsys.readouterr().out
    (tmp_path / "s.json").write_text(json.dumps(met_facts()), encoding="ascii")
    assert check.main(base + ["--service", str(tmp_path / "s.json"), "--strict"]) in (0, 1)
    after = capsys.readouterr().out
    for ident in ("X28", "X29", "X30"):
        assert re.search(r"^MET +%s " % ident, after, re.M), after
        assert ident not in before
    words = [" ".join(line.split()) for line in after.splitlines()]   # the column's width grows with the names
    keep = [" ".join(line.split()) for line in before.splitlines() if re.match(r"^\S+ +X\d+ ", line)]
    assert keep and all(line in words for line in keep)   # X1 to X27 as they were
    assert check.main(base + ["--service", str(tmp_path / "missing.json")]) == 0
    assert re.search(r"^MISSED +X29 .*silence is a finding", capsys.readouterr().out, re.M)


# --- the run itself, over a made-up machine -----------------------------------------------------------------------

class Machine:
    """A made-up `run`: answers each program the run starts as the Linux machine would, the unit's file and the
    service's events in tmp. `refuse_root` makes the install from root's own place refused too."""

    def __init__(self, tmp, refuse_root=False):
        self.unit, self.events, self.calls, self.refuse_root = tmp / "unit", tmp / "events.jsonl", [], refuse_root

    def run(self, argv, timeout=120.0):
        argv = [str(a) for a in argv]
        self.calls.append(argv)

        def ok(out="", err="", code=0):
            return {"argv": argv, "exit": code, "out": out, "err": err}
        tail = argv[-3:]
        if argv[1:3] == ["-m", "venv"] or "pip" in argv:
            return ok()
        if tail == ["service", "install", "--no-start"] or (tail[-2:] == ["service", "install"] and self.refuse_root):
            return ok(err="raqib: raqib service install: refused: /tmp is writable by others (mode 1777) (on the"
                          " way to %s)" % argv[0], code=2)
        if tail[-2:] == ["service", "install"]:
            self.unit.write_text("# raqib-service/1\n", encoding="ascii")
            return ok(out="RESULT: installed, enabled and started\n")
        if argv[1:] == ["is-active", "raqib-watch.service"]:
            return ok(out="active\n" if self.unit.exists() else "inactive\n", code=0 if self.unit.exists() else 3)
        if argv[0] == "id":
            return ok(out="998\n")
        if argv[0] == "systemd-run":
            assert "--uid=raqib-rig-agent" in argv and "--collect" in argv
            if self.unit.exists():   # the service's watch sees the stand-in's tree
                self.events.write_text(json.dumps({"kind": "heartbeat"}) + "\n" + json.dumps(FINDING) + "\n",
                                       encoding="ascii")
            return ok()
        if "--property=MainPID" in argv:
            return ok(out="%d\n" % PID)
        if argv[1] == "is-active":
            return ok(out="inactive\n", code=3)
        if tail[-2:] == ["service", "status"]:
            return ok(out="RESULT: ACTIVE\n")
        if tail == ["service", "remove", "--purge"]:
            if self.unit.exists():
                self.unit.unlink()
            return ok(out="RESULT: removed\n")
        if "--property=LoadState" in argv:
            return ok(out="loaded\n" if self.unit.exists() else "not-found\n")
        if argv[1] in ("stop", "disable", "daemon-reload"):
            return ok()
        return ok(code=1, err="the made-up machine does not know %s" % argv)


@pytest.fixture
def machine(tmp_path, monkeypatch):
    m = Machine(tmp_path)
    clock = iter(range(0, 10 ** 6, 5))
    monkeypatch.setattr(service_run, "PLATFORM", "linux")
    monkeypatch.setattr(service_run, "euid", lambda: 0)
    monkeypatch.setattr(service_run, "run", m.run)
    monkeypatch.setattr(service_run, "copy_source", lambda dest: dest)
    monkeypatch.setattr(service_run, "SLEEP", lambda s: None)
    monkeypatch.setattr(service_run, "CLOCK", lambda: next(clock))
    monkeypatch.setattr(service_run, "UNIT_PATH", str(m.unit))
    monkeypatch.setattr(service_run, "EVENTS", str(m.events))
    (tmp_path / "usrlocal").mkdir()
    monkeypatch.setattr(service_run, "ROOT_PLACE", str(tmp_path / "usrlocal"))
    (tmp_path / "work").mkdir()
    return m, tmp_path


def test_e6_the_run_refuses_from_a_users_place_installs_from_roots_sees_the_second_user_and_removes(machine):
    m, tmp = machine
    assert service_run.main(["--out", str(tmp / "f.json"), "--work", str(tmp / "work")]) == 0
    facts = json.loads((tmp / "f.json").read_text(encoding="ascii"))
    assert {k: v[0] for k, v in states(facts).items()} == {"X28": "MET", "X29": "MET", "X30": "MET"}, facts
    assert facts["x29"]["place"].startswith(str(tmp / "usrlocal")) and facts["x29"]["agent"]["pid"] == PID
    assert facts["x28"]["place"].startswith(str(tmp / "work"))
    starts = [c for c in m.calls if "service" in c]
    assert [c[c.index("service") + 1:] for c in starts] == [["install", "--no-start"], ["install"], ["status"],
                                                           ["remove", "--purge"]]
    assert all(c[1] == "-I" for c in starts)   # the venv's python in isolated mode
    venvs = [c for c in m.calls if c[1:3] == ["-m", "venv"]]
    assert venvs and all(c[0] == service_run.SYSTEM_PYTHON for c in venvs)
    assert not m.unit.exists() and facts["cleanup"] == [0]   # only the stand-in's unit stopped: nothing was left


def test_e6_a_refused_install_from_roots_place_is_x29_missed_and_the_run_still_ends_clean(machine):
    m, tmp = machine
    m.refuse_root = True
    assert service_run.main(["--out", str(tmp / "f.json"), "--work", str(tmp / "work")]) == 0
    got = states(json.loads((tmp / "f.json").read_text(encoding="ascii")))
    assert got["X28"][0] == "MET" and got["X29"][0] == "MISSED" and "the install exited 2" in got["X29"][1]


def test_e6_off_linux_not_run_not_root_an_error_and_it_never_raises(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(service_run, "PLATFORM", "win32")
    assert service_run.main(["--out", str(tmp_path / "a.json")]) == 0
    assert states(json.loads((tmp_path / "a.json").read_text(encoding="ascii")))["X28"][0] == "n/a"
    monkeypatch.setattr(service_run, "PLATFORM", "linux")
    monkeypatch.setattr(service_run, "euid", lambda: 1000)
    assert service_run.main(["--out", str(tmp_path / "b.json")]) == 0
    assert "not run as root (uid 1000)" in json.loads((tmp_path / "b.json").read_text(encoding="ascii"))["error"]
    monkeypatch.setattr(service_run, "euid", lambda: 0)

    def broken(dest):
        raise OSError(13, "made-up")
    monkeypatch.setattr(service_run, "copy_source", broken)
    assert service_run.main(["--out", str(tmp_path / "c.json"), "--work", str(tmp_path / "w")]) == 0
    assert "made-up" in json.loads((tmp_path / "c.json").read_text(encoding="ascii"))["error"]
    assert service_run.main(["--out", str(tmp_path / "no" / "such" / "d.json")]) == 0
    assert "cannot be written" in capsys.readouterr().out


def test_e6_run_never_raises_and_the_rigs_new_code_is_ascii_stdlib_and_no_part_of_raqib():
    got = service_run.run([str(ROOT / "no-such-program-here")])
    assert got["exit"] is None and got["err"].startswith("cannot be run")
    for name in ("service_run.py", "check.py"):
        text = (ROOT / "tools" / "rig" / name).read_bytes().decode("ascii")
        assert "import requests" not in text and "urllib" not in text and "import raqib" not in text
    assert not [p for p in (ROOT / "raqib").rglob("*.py") if "service_run" in p.read_text(encoding="utf-8")]
    assert (ROOT / "tests" / "test_service_rig.py").read_bytes().isascii()
    assert isinstance(io.StringIO(), io.StringIO) and sys.version_info >= (3, 8)
