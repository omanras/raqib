"""M12.1 (ADR-0013 A-9, AA-3, AA-4, AC-10): the rig's service run (tools/rig/service_run.py) and its check, X28 to
X30 (tools/rig/check.py --service). Every fact here is made up: no test runs as root, needs Linux, starts
systemctl, journalctl or systemd-run, or writes outside its tmp folder; the run's programs are a made-up `run`, its
waits a made-up clock. The pid, uid and paths are made up.
"""
import importlib.util
import io
import json
import os
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
PLACE = "/usr/local/lib/raqib-x28-ab/open"
WARNING = ("/etc/systemd/system/raqib-watch.service:31: Unknown key name 'ProtectClock' in section 'Service',"
           " ignoring.")


def met_facts():
    return {"platform": "linux",
            "x28": {"place": PLACE, "mode": "0777", "uid": 0, "parent": "/usr/local/lib/raqib-x28-ab",
                    "parent_mode": "0755", "parent_uid": 0, "root_place": "/usr/local/lib", "exit": 2,
                    "unit_before": False, "unit_after": False,
                    "said": "raqib: raqib service install: refused: %s is writable by others (mode 0777) (on the"
                            " way to %s/venv/bin/python)." % (PLACE, PLACE)},
            "x29": {"place": "/usr/local/lib/raqib-rig-ab", "venv": "/usr/local/lib/raqib-rig-ab/venv",
                    "install": {"exit": 0, "said": "RESULT: installed, enabled, active 3 s after its start"},
                    "active": "active", "user": {"name": "raqib-rig-agent", "uid": "998"},
                    "agent": {"unit": "raqib-rig-agent-1", "exit": 0, "pid": PID, "ended": "inactive"},
                    "events": 12, "findings": [{"rule": "NEW-AGENT-UNKNOWN", "tree": FINDING["subject"]["tree"],
                                                "summary": FINDING["summary"]}],
                    "mine": [{"rule": "NEW-AGENT-UNKNOWN", "tree": FINDING["subject"]["tree"], "summary": "x"}],
                    "show": {"Id": "raqib-watch.service", "CapabilityBoundingSet": "cap_dac_read_search cap_sys_ptrace",
                             "RestrictAddressFamilies": "AF_UNIX AF_NETLINK", "Restart": "always"},
                    "journal": {"exit": 0, "read": 310, "lines": [], "err": ""},
                    "proc": {"pid": 5150, "CapBnd": "0000000000080004", "CapEff": "0000000000080004", "Seccomp": "2",
                             "NoNewPrivs": "1"}},
            "x30": {"exit": 0, "said": "RESULT: removed", "unit_file": False, "load_state": "not-found",
                    "active_state": "inactive", "state_dir": False}}


def states(facts):
    return {r[0].split(" ", 1)[0]: (r[1], r[2]) for r in check.read_service(facts)}


# --- X28 to X30 from made-up facts ---------------------------------------------------------------------------------

def test_e6_x28_to_x30_are_met_from_the_facts_of_a_good_run():
    got = states(met_facts())
    assert {k: v[0] for k, v in got.items()} == {"X28": "MET", "X29": "MET", "X30": "MET"}, got
    assert "%s is named" % PLACE in got["X28"][1] and "pid 4242" in got["X29"][1]
    assert "NEW-AGENT-UNKNOWN" in got["X29"][1] and "4 directive(s) shown, none warned of in 310" in got["X29"][1]
    assert "the main process (pid 5150): CapBnd=0000000000080004, Seccomp=2, NoNewPrivs=1" in got["X29"][1]
    assert check.CAP_BOUND == 0x80004 == (1 << 2) | (1 << 19)
    assert "ActiveState=inactive; no record's folder" in got["X30"][1]


@pytest.mark.parametrize("key,part,value,ident,words", [
    ("x28", "exit", 0, "X28", "exit 2 (exit 0)"),
    ("x28", "said", "RESULT: installed, not started", "X28", "the refusal naming %s or a path below it (it named"
                                                             " none)" % PLACE),
    ("x28", "said", "refused: /usr/local/lib is writable by others (mode 0777)", "X28", "(it named /usr/local/lib)"),
    ("x28", "said", "refused: /tmp is writable by others (mode 1777) (on the way to /tmp/x)", "X28", "named /tmp)"),
    ("x28", "said", "refused: %s-x is owned by uid 5" % PLACE, "X28", "(it named %s-x)" % PLACE),
    ("x28", "mode", "1777", "X28", "a place every user can write and not sticky (mode 1777)"),
    ("x28", "parent_mode", "0777", "X28", "inside a folder root's alone"),
    ("x28", "parent_uid", 1000, "X28", "inside a folder root's alone"),
    ("x28", "parent", "/tmp", "X28", "inside a folder root's alone (/tmp"),
    ("x28", "unit_after", True, "X28", "no unit after it"),
    ("x29", "install", {"exit": 2, "said": "refused"}, "X29", "the install exited 2"),
    ("x29", "install", {"exit": 1, "said": "NOT ACTIVE 3 s after its start"}, "X29", "the install exited 1"),
    ("x29", "active", "failed", "X29", "the unit is failed, not active"),
    ("x29", "agent", {"exit": 1, "pid": None}, "X29", "the stand-in did not start as raqib-rig-agent"),
    ("x29", "mine", [], "X29", "no finding on the stand-in's tree (pid 4242) in 12 event(s); findings seen:"
                               " NEW-AGENT-UNKNOWN 4242:python3"),
    ("x29", "show", {}, "X29", "its directives as systemctl show gives them (none read)"),
    ("x29", "journal", {"exit": 0, "read": 310, "lines": [WARNING]}, "X29", "it said: " + WARNING),
    ("x29", "journal", {"exit": 1, "read": 0, "lines": [], "err": "No journal files were found."}, "X29",
     "the manager's journal read (exit 1: No journal files were found.)"),
    ("x29", "journal", {"exit": 0, "read": 0, "lines": []}, "X29", "the manager's journal read"),
    ("x29", "proc", {"pid": 5150, "CapBnd": "000001ffffffffff", "Seccomp": "2", "NoNewPrivs": "1"}, "X29",
     "it read CapBnd=000001ffffffffff"),
    ("x29", "proc", {"pid": 5150, "CapBnd": "0000000000080000", "Seccomp": "2", "NoNewPrivs": "1"}, "X29",
     "(CapBnd 0x80004); it read CapBnd=0000000000080000"),
    ("x29", "proc", {"pid": 5150, "CapBnd": "0000000000080004", "Seccomp": "0", "NoNewPrivs": "1"}, "X29",
     "a seccomp filter (Seccomp 2); it read Seccomp=0"),
    ("x29", "proc", {"pid": 5150, "CapBnd": "0000000000080004", "Seccomp": "2", "NoNewPrivs": "0"}, "X29",
     "no new privileges (NoNewPrivs 1); it read NoNewPrivs=0"),
    ("x29", "proc", {"pid": None, "error": "no main pid (systemctl show: 0)"}, "X29",
     "the main process's own word (no main pid (systemctl show: 0))"),
    ("x29", "proc", {}, "X29", "it read CapBnd=None"),
    ("x30", "exit", 1, "X30", "the removal exited 1"),
    ("x30", "unit_file", True, "X30", "the unit's file is left"),
    ("x30", "load_state", "loaded", "X30", "systemctl says LoadState=loaded"),
    ("x30", "active_state", "active", "X30", "systemctl says ActiveState=active"),
    ("x30", "active_state", None, "X30", "systemctl says ActiveState=None"),
    ("x30", "state_dir", True, "X30", "the record's folder is left"),
    ("x29", "error", "the venv cannot be made: made-up", "X29", "the rig's run of it failed: the venv cannot be"),
])
def test_e6_each_of_x28_to_x30_is_missed_with_what_is_missing(key, part, value, ident, words):
    facts = met_facts()
    facts[key][part] = value
    got = states(facts)
    assert got[ident][0] == "MISSED" and words in got[ident][1], got[ident]
    assert [v[0] for k, v in got.items() if k != ident] == ["MET", "MET"]


def test_e6_capbnd_is_compared_as_a_number_and_the_journal_words_hold_not_support():
    facts = met_facts()
    facts["x29"]["proc"]["CapBnd"] = "80004"   # the same number, written short
    assert states(facts)["X29"][0] == "MET"
    for line in ("raqib-watch.service: unit configured to use IPAddressDeny but the system does not support"
                 " BPF/cgroup firewalling.", WARNING, "raqib-watch.service: invalid value, made-up"):
        assert service_run.JOURNAL_WORDS.search(line), line
    assert not service_run.JOURNAL_WORDS.search("Started raqib-watch.service - Raqib: the watch of this host.")


def test_e6_a_refusal_naming_a_path_below_the_place_is_met():
    facts = met_facts()
    facts["x28"]["said"] = "refused: %s/venv/lib/x.py is owned by uid 1000, not root" % PLACE
    assert states(facts)["X28"][0] == "MET"


def test_e6_not_run_is_na_only_off_linux_and_silence_or_garbage_is_missed_never_raised():
    assert {v for v in states({"platform": "win32", "not_run": "not Linux (win32)"}).values()} == {
        ("n/a", "not run: not Linux (win32)")}
    for facts in ({"platform": "linux", "not_run": "no --throwaway: made-up"}, {"not_run": "made-up"}):
        assert {v[0] for v in states(facts).values()} == {"MISSED"}
        assert "not run on Linux" in states(facts)["X28"][1]
    assert {v[0] for v in states(None).values()} == {"MISSED"}
    assert "silence is a finding" in states(None)["X28"][1]
    assert "the service's run failed: not run as root" in states({"error": "not run as root (uid 1000)"})["X30"][1]
    assert states({"platform": "linux"})["X29"] == ("MISSED", "the rig did not run it: no facts of x29")
    for junk in ({"x28": 5, "x29": {"agent": 7, "mine": "x", "user": 3, "journal": 4}, "x30": []},
                 {"x29": {"install": None, "journal": {"lines": "x"}}}, {"x28": {"said": 9, "exit": "2"}},
                 {"x28": {"parent_mode": "zz", "place": 3}}, ["x"], "x", 7):
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
    """A made-up `run`: answers each program the run starts as the Linux machine would, the unit's file, the
    service's events and its record's folder in tmp. `refuse_root` makes the install from root's own place
    refused too; `warn` is a line the made-up manager's journal holds."""

    def __init__(self, tmp, refuse_root=False):
        self.unit, self.events, self.state, self.calls = tmp / "unit", tmp / "events.jsonl", tmp / "state", []
        self.refuse_root, self.warn = refuse_root, None

    def run(self, argv, timeout=120.0, keep=1500):
        argv = [str(a) for a in argv]
        self.calls.append(argv)

        def ok(out="", err="", code=0):
            return {"argv": argv, "exit": code, "out": out[-keep:], "err": err[-keep:]}
        tail = argv[-3:]
        if argv[1:3] == ["-m", "venv"] or "pip" in argv:
            return ok()
        if tail == ["service", "install", "--no-start"] or (tail[-2:] == ["service", "install"] and self.refuse_root):
            place = os.path.dirname(os.path.dirname(os.path.dirname(argv[0])))
            return ok(err="raqib: raqib service install: refused: %s is writable by others (mode 0777) (on the"
                          " way to %s)" % (place, argv[0]), code=2)
        if tail[-2:] == ["service", "install"]:
            self.unit.write_text("# raqib-service/1\n", encoding="ascii")
            self.state.mkdir(exist_ok=True)
            return ok(out="RESULT: installed, enabled, active 3 s after its start\n")
        if argv[1:] == ["is-active", "raqib-watch.service"]:
            return ok(out="active\n" if self.unit.exists() else "inactive\n", code=0 if self.unit.exists() else 3)
        if argv[0] == service_run.ID:
            return ok(out="998\n")
        if argv[0] == service_run.SYSTEMD_RUN:
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
        if argv[1:] == ["show", "raqib-watch.service", "--no-pager"]:
            return ok(out="Id=raqib-watch.service\nRestart=always\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n"
                          "CapabilityBoundingSet=cap_dac_read_search cap_sys_ptrace\n" + "X=y\n" * 2000)
        if argv[0] == service_run.JOURNALCTL:
            assert argv[1:] == ["--no-pager", "-b", "-o", "cat", "_PID=1"]
            lines = ["Started raqib-watch.service - Raqib: the watch of this host.", "Reloading finished."] * 3000
            return ok(out="\n".join(lines + ([self.warn] if self.warn else [])) + "\n")
        if tail == ["service", "remove", "--purge"]:
            if self.unit.exists():
                self.unit.unlink()
            if self.state.exists():
                self.state.rmdir()
            return ok(out="RESULT: removed\n")
        if "--property=LoadState,ActiveState" in argv:
            return ok(out="LoadState=loaded\nActiveState=active\n" if self.unit.exists() else
                      "LoadState=not-found\nActiveState=inactive\n")
        if argv[1] in ("stop", "disable", "daemon-reload"):
            return ok()
        return ok(code=1, err="the made-up machine does not know %s" % argv)


@pytest.fixture
def machine(tmp_path, monkeypatch):
    m = Machine(tmp_path)
    clock = iter(range(0, 10 ** 6, 5))
    real_mode_of = service_run.mode_of
    monkeypatch.setattr(service_run, "PLATFORM", "linux")
    monkeypatch.setattr(service_run, "euid", lambda: 0)
    monkeypatch.setattr(service_run, "run", m.run)
    monkeypatch.setattr(service_run, "copy_source", lambda dest: dest)
    monkeypatch.setattr(service_run, "SLEEP", lambda s: None)
    monkeypatch.setattr(service_run, "CLOCK", lambda: next(clock))
    monkeypatch.setattr(service_run, "UNIT_PATH", str(m.unit))
    monkeypatch.setattr(service_run, "EVENTS", str(m.events))
    monkeypatch.setattr(service_run, "STATE_DIR", str(m.state))
    (tmp_path / "proc" / str(PID)).mkdir(parents=True)   # made up: the unit's main process's status as /proc has it
    (tmp_path / "proc" / str(PID) / "status").write_text(
        "Name:\tpython3\nNoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000000000080004\nCapBnd:\t0000000000080004\n",
        encoding="ascii")
    monkeypatch.setattr(service_run, "PROC", str(tmp_path / "proc"))
    monkeypatch.setattr(service_run, "mode_of", lambda p: (0, real_mode_of(p)[1]))   # made up: root's, as on the rig
    (tmp_path / "usrlocal").mkdir()
    monkeypatch.setattr(service_run, "ROOT_PLACE", str(tmp_path / "usrlocal"))
    (tmp_path / "work").mkdir()
    return m, tmp_path


def facts_of(tmp, *extra):
    assert service_run.main(["--throwaway", "--out", str(tmp / "f.json"), "--work", str(tmp / "work")] +
                            list(extra)) == 0
    return json.loads((tmp / "f.json").read_text(encoding="ascii"))


@pytest.mark.skipif(os.name == "nt", reason="modes as POSIX reads them")
def test_e6_the_run_refuses_from_a_users_place_installs_from_roots_sees_the_second_user_and_removes(machine):
    m, tmp = machine
    facts = facts_of(tmp)
    assert {k: v[0] for k, v in states(facts).items()} == {"X28": "MET", "X29": "MET", "X30": "MET"}, facts
    assert facts["x29"]["place"].startswith(str(tmp / "usrlocal")) and facts["x29"]["agent"]["pid"] == PID
    x28 = facts["x28"]
    assert x28["parent"].startswith(str(tmp / "usrlocal")) and x28["place"] == x28["parent"] + "/open"
    assert (x28["mode"], x28["parent_mode"], x28["parent_uid"]) == ("0777", "0755", 0)   # 0777: no sticky bit
    starts = [c for c in m.calls if "service" in c]
    assert [c[c.index("service") + 1:] for c in starts] == [["install", "--no-start"], ["install"], ["status"],
                                                           ["remove", "--purge"]]
    assert all(c[1] == "-I" for c in starts)   # the venv's python in isolated mode
    venvs = [c for c in m.calls if c[1:3] == ["-m", "venv"]]
    assert venvs and all(c[0] == service_run.SYSTEM_PYTHON for c in venvs)
    assert all(c[0].startswith("/") for c in m.calls)   # every program by its whole path, none by PATH
    assert facts["x29"]["show"]["Restart"] == "always" and facts["x29"]["journal"]["read"] == 6000
    assert facts["x29"]["journal"]["lines"] == []   # lines naming the unit, none a warning
    assert facts["x29"]["proc"] == {"pid": PID, "CapBnd": "0000000000080004", "CapEff": "0000000000080004",
                                    "Seccomp": "2", "NoNewPrivs": "1"}
    assert facts["x30"]["state_dir"] is False and facts["x30"]["active_state"] == "inactive"
    assert not m.unit.exists() and facts["cleanup"] == [0]   # only the stand-in's unit stopped: nothing was left


@pytest.mark.skipif(os.name == "nt", reason="modes as POSIX reads them")
def test_e6_a_main_process_holding_more_than_the_two_capabilities_is_x29_missed(machine):
    m, tmp = machine
    status = tmp / "proc" / str(PID) / "status"
    status.write_text(status.read_text(encoding="ascii").replace("CapBnd:\t0000000000080004",
                                                                 "CapBnd:\t000001ffffffffff"), encoding="ascii")
    got = states(facts_of(tmp))
    assert got["X29"][0] == "MISSED" and "it read CapBnd=000001ffffffffff" in got["X29"][1]
    status.unlink()
    got = states(facts_of(tmp))
    assert got["X29"][0] == "MISSED" and "cannot be read (FileNotFoundError)" in got["X29"][1]


@pytest.mark.skipif(os.name == "nt", reason="modes as POSIX reads them")
def test_e6_a_warning_of_the_manager_on_the_unit_is_x29_missed(machine):
    m, tmp = machine
    m.warn = WARNING
    got = states(facts_of(tmp))
    assert got["X29"][0] == "MISSED" and "it said: " + WARNING in got["X29"][1]


@pytest.mark.skipif(os.name == "nt", reason="modes as POSIX reads them")
def test_e6_a_refused_install_from_roots_place_is_x29_missed_and_the_run_still_ends_clean(machine):
    m, tmp = machine
    m.refuse_root = True
    got = states(facts_of(tmp))
    assert got["X28"][0] == "MET" and got["X29"][0] == "MISSED" and "the install exited 2" in got["X29"][1]


def test_e6_without_throwaway_nothing_is_run_and_the_reason_is_the_fact(machine):
    m, tmp = machine
    assert service_run.main(["--out", str(tmp / "f.json"), "--work", str(tmp / "work")]) == 0
    facts = json.loads((tmp / "f.json").read_text(encoding="ascii"))
    assert m.calls == [] and set(facts) == {"platform", "not_run"} and facts["not_run"].startswith("no --throwaway")
    assert "thrown away" in facts["not_run"] and os.listdir(str(tmp / "usrlocal")) == []
    assert {v[0] for v in states(facts).values()} == {"MISSED"}   # on Linux, not run is not n/a


def test_e6_off_linux_not_run_not_root_an_error_and_it_never_raises(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(service_run, "PLATFORM", "win32")
    assert service_run.main(["--out", str(tmp_path / "a.json")]) == 0
    assert states(json.loads((tmp_path / "a.json").read_text(encoding="ascii")))["X28"][0] == "n/a"
    monkeypatch.setattr(service_run, "PLATFORM", "linux")
    monkeypatch.setattr(service_run, "euid", lambda: 1000)
    assert service_run.main(["--throwaway", "--out", str(tmp_path / "b.json")]) == 0
    assert "not run as root (uid 1000)" in json.loads((tmp_path / "b.json").read_text(encoding="ascii"))["error"]
    monkeypatch.setattr(service_run, "euid", lambda: 0)

    def broken(dest):
        raise OSError(13, "made-up")
    monkeypatch.setattr(service_run, "copy_source", broken)
    assert service_run.main(["--throwaway", "--out", str(tmp_path / "c.json"), "--work", str(tmp_path / "w")]) == 0
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
