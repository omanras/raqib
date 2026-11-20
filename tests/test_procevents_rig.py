"""M14.1a and its REDO (ADR-0007 BQ-2, BR-7): the rig's run of the reader of Linux's process events
(tools/rig/procevents_run.py) and its check, X31 (tools/rig/check.py --procevents). Every fact here is made up: no
test here opens a netlink socket, starts a program or a server, or needs Linux; the run's reader, its runner, its
`which`, its server and its clock are the test's. The pids and paths are made up."""
import ast
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_tool = load("rig_procevents_run", ROOT / "tools" / "rig" / "procevents_run.py")
check = load("rig_check_procevents", ROOT / "tools" / "rig" / "check.py")
TOOL = (ROOT / "tools" / "rig" / "procevents_run.py").read_text(encoding="ascii")
NAMES = ["touch", "mv", "cp", "rm", "curl", "curl", "curl", "wget", "getent", "nc", "python", "sh", "shred", "git"]
RUN_PID = 3131
KERNEL = os.uname().release if hasattr(os, "uname") else None   # what the run writes of this system (BS-8)
KERNEL_SAID = "kernel %s: " % KERNEL if KERNEL else ""
CLEAN = {"since": "2026-11-20T10:00:00.000000Z", "last": "2026-11-20T10:00:02.000000Z", "reused": 0, "events": {"fork": 30, "exec": 16, "exit": 30}, "given": 16,
         "missed": {"exe": 0, "stat": 0}, "unread": {"comm": 3}, "threads": 4, "older": 2,
         "lost": {"count": 0, "why": None}, "beyond": 0, "live": 1, "refused": None, "ended": None, "said": []}


def act(name, pid, rc=0, exe=None, code=None, signal=None, ended="2026-11-20T10:00:01.000000Z", given=True):
    expect = "/usr/bin/%s" % name
    out = {"act": name, "argv0": name, "expect": expect, "pid": pid, "rc": rc, "ms": 2.0}
    if given:
        out["given"] = {"pid": pid, "ppid": RUN_PID, "exe": expect if exe is None else exe, "earlier": [],
                        "started_ticks": 9,
                        "began": "2026-11-20T10:00:00.900000Z", "ended": ended,
                        "code": (rc if rc >= 0 else None) if code is None else code,
                        "signal": (-rc if rc < 0 else None) if signal is None else signal, "unread": {}}
    return out


def met_facts():
    acts = [act(n, 5000 + i, rc=128 if n == "git" else 0) for i, n in enumerate(NAMES)]
    acts[9] = {"act": "nc", "argv0": "nc", "not_run": "not installed"}
    acts.append(act("sh", 5100, rc=-9))                  # ended by a signal: the signal is its end's code
    return {"platform": "linux", "uid": 1001, "run_pid": RUN_PID, "acts": acts, "children": [], "counts": json.loads(json.dumps(CLEAN)),
            "refused": None, "stop_problems": [], "error": None}


def x31(facts):
    rows = check.read_procevents(facts)
    assert len(rows) == 1 and rows[0][0] == check.PROCEVENTS_NAME and rows[0][0].startswith("X31 ")
    return rows[0][1], rows[0][2]


def test_e6_x31_is_met_from_the_facts_of_a_good_run_and_an_act_not_installed_is_said_not_run():
    state, words = x31(met_facts())
    assert state == check.MET, words
    assert words.startswith("14 act(s) given with their program and their end's code") and \
        "not run: nc (not installed)" in words and "lost 0, beyond 0" in words


def _set(facts, path, value):
    target = facts
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


MISSES = [
    (("acts", 0, "given"), None, "touch (pid 5000) not given by read()"),
    (("acts", 1, "given", "exe"), "/usr/bin/other", "mv (pid 5001): its program read as /usr/bin/other, not"
                                                    " /usr/bin/mv"),
    (("acts", 2, "given", "exe"), None, "cp (pid 5002): its program read as None, not /usr/bin/cp"),
    (("acts", 3, "given", "ended"), None, "rm (pid 5003): its end not heard"),
    (("acts", 6, "given", "ppid"), 4000, "curl (pid 5006): its parent 4000, not the run's own 3131"),
    (("acts", 7, "given", "ppid"), None, "wget (pid 5007): its parent None, not the run's own 3131"),
    (("run_pid",), None, "touch (pid 5000): its parent 3131, not the run's own None"),
    (("acts", 4, "given", "code"), 1, "curl (pid 5004): its end's code 1 (signal None), not 0"),
    (("acts", 13, "given", "code"), 0, "git (pid 5013): its end's code 0 (signal None), not 128"),
    (("acts", 14, "given", "signal"), 15, "sh (pid 5100): its end's signal 15, not 9"),
    (("acts", 5, "rc"), None, "curl (pid 5005): the run has no exit code for it"),
    (("counts", "lost"), {"count": 1, "why": "the kernel's queue overflowed"}, "lost 1 (the kernel's queue"),
    (("counts", "beyond"), 2, "beyond the bound 2"),
    (("counts", "ended"), "the reader's thread ended before the stop", "the reader's thread ended: the reader's"),
    (("counts",), None, "no counts"),
    (("stop_problems",), ["the socket could not be closed"], "the stop's problems: the socket could not be closed"),
    (("acts",), [{"act": "nc", "not_run": "not installed"}], "no act ran"),
    (("error",), "OSError: boom", "the run failed: OSError: boom"),
    (("not_run",), "the run was not started", "not run on Linux: the run was not started"),
]


@pytest.mark.parametrize("path, value, words", MISSES, ids=["%s-%d" % ("-".join(map(str, m[0])), i)
                                                            for i, m in enumerate(MISSES)])
def test_e6_x31_is_missed_with_what_is_missing(path, value, words):
    facts = met_facts()
    _set(facts, path, value)
    state, said = x31(facts)
    assert state == check.MISSED and words in said, said


def test_e6_x31_unread_is_said_with_a_program_not_read():
    facts = met_facts()
    facts["acts"][0]["given"].update(exe=None, unread={"exe": "not read at its exec (ENOENT: gone before the read)"})
    state, said = x31(facts)
    assert state == check.MISSED and "(unread: {'exe': 'not read at its exec (ENOENT: gone before the read)'})" in said


def test_e7_x31_is_na_off_linux_or_for_a_refusal_that_names_no_right_of_this_user_else_missed():
    assert x31({"platform": "win32", "not_run": "not Linux (win32): the process events are the Linux kernel's"}) == (
        check.SKIP, "not run: not Linux (win32): the process events are the Linux kernel's")
    assert x31({"platform": "darwin", "acts": []}) == (check.SKIP, "not run: not Linux (darwin)")
    for right in ("EPERM", "EACCES"):
        why = ("the process events are not read: the bind to the connector's group of process events was refused"
               " (%s); this kernel keeps its process events from this user" % right)
        assert x31(dict(met_facts(), refused=why)) == (
            check.SKIP, "start() was refused for want of a right of this user: %s" % why)
    for why in ("the process events are not read: the kernel did not answer the ask to listen within 2 s",
                "the process events are not read: the socket (AF_NETLINK, the connector) was refused (EAFNOSUPPORT)",
                "the process events are not read: the kernel answered the ask to listen with EINVAL"):
        assert x31(dict(met_facts(), refused=why)) == (
            check.MISSED, "start() was refused where the kernel is known to answer: %s" % why)


def test_e6_x31_silence_or_garbage_is_missed_and_never_raises():
    assert x31(None)[0] == check.MISSED and "silence is a finding" in x31(None)[1]
    for bad in ([], "text", {"platform": "linux", "acts": "x"}, {"platform": "linux", "acts": [{"pid": 1}]},
                {"platform": "linux", "acts": [None]}):
        assert x31(bad)[0] == check.MISSED, bad


def test_e6_check_main_says_x31_with_procevents_and_nothing_else_changes(tmp_path, capsys):
    report, workload = tmp_path / "w.out", tmp_path / "wl.out"
    report.write_text("RESULT: CLEAN\n", encoding="utf-8")
    workload.write_text("", encoding="utf-8")
    base = ["--report", str(report), "--workload", str(workload), "--platform", "linux"]
    assert check.main(base) == 0
    without = capsys.readouterr().out
    assert "X31" not in without
    (tmp_path / "p.json").write_text(json.dumps(met_facts()), encoding="utf-8")
    check.main(base + ["--procevents", str(tmp_path / "p.json")])
    out = capsys.readouterr().out
    assert "MET     X31 every short act that ran is given by the process events' reader with its program, its parent" \
        in out

    def rows(text):     # the table's width follows its longest name: the rows are compared by their words
        return [" ".join(line.split()) for line in text.splitlines() if "X31" not in line and "RIG:" not in line]
    assert rows(out) == rows(without)
    check.main(base + ["--procevents", str(tmp_path / "missing.json"), "--strict"])
    out = capsys.readouterr().out
    assert "MISSED  X31" in out and "left no facts (silence is a finding)" in out


# --- the run, with a made-up system --------------------------------------------------------------------------------
class World:
    """The run's system, made up: `which` finds every program but those in `absent`; each act started gets the
    next pid; the reader gives each act's process at the next read (its exec first, its end at the read after,
    as a real read may), unless `drop` names it."""

    def __init__(self, absent=(), refuse=None, drop=(), start_raises=None):
        self.absent, self.refuse, self.drop, self.start_raises = set(absent), refuse, set(drop), start_raises
        self.pid, self.started, self.pending, self.ends, self.stopped, self.closed = 6000, [], [], [], 0, 0
        self.clock = 0.0

    def which(self, name, path=None):
        base = name.rsplit("/", 1)[-1]
        return None if base in self.absent else "/usr/bin/%s" % base

    def run(self, argv, env, cwd):
        assert "HTTP_PROXY" not in env and "https_proxy" not in env and env["GIT_TERMINAL_PROMPT"] == "0"
        self.pid += 1
        base = argv[0].rsplit("/", 1)[-1]
        rc = 128 if base == "git" else 0
        self.started.append((self.pid, argv))
        if base not in self.drop:
            self.pending.append({"pid": self.pid, "ppid": os.getpid(), "exe": os.path.realpath("/usr/bin/%s" % base),
                                 "started_ticks": 7,
                                 "began": "b", "ended": None, "code": None, "signal": None, "unread": {}})
            self.ends.append({"pid": self.pid, "started_ticks": 7, "began": "b", "ended": "e", "code": rc,
                              "signal": None, "unread": {}})
        return {"pid": self.pid, "rc": rc, "ms": 1.0}

    def server(self):
        def close():
            self.closed += 1
        return 8080, close

    def sleep(self, seconds):
        self.clock += seconds

    def now(self):
        return self.clock

    def reader(self):
        world = self

        class Reader:
            def start(self):
                if world.start_raises:
                    raise world.start_raises
                return world.refuse

            def read(self):
                out = {"processes": world.pending, "ends": world.ends if not world.pending else [], "older": []}
                if world.pending:
                    world.pending = []
                else:
                    world.ends = []
                return out

            def counts(self):
                return json.loads(json.dumps(CLEAN))

            def stop(self):
                world.stopped += 1
                return []
        return Reader()


def collect(world, tmp_path, platform="linux"):
    return run_tool.collect(reader=world.reader, run=world.run, which=world.which, server=world.server,
                            platform=platform, work=str(tmp_path), sleep=world.sleep, clock=world.now)


def test_e6_the_run_runs_the_probes_acts_and_its_facts_are_x31_met(tmp_path):
    world = World()
    facts = collect(world, tmp_path)
    assert [a["act"] for a in facts["acts"]] == NAMES
    argvs = [argv for _, argv in world.started]
    assert all("127.0.0.1:8080" in " ".join(a) for a in argvs if a[0] in ("curl", "wget", "git")) and \
        ["getent", "hosts", "localhost"] in argvs and ["nc", "-z", "-w", "3", "127.0.0.1", "8080"] in argvs
    assert argvs[10][0] == sys.executable and "urlopen('http://127.0.0.1:8080/'" in argvs[10][2]
    assert world.stopped == 1 and world.closed == 1 and facts["error"] is None and facts["refused"] is None
    assert all(a["given"]["ended"] == "e" for a in facts["acts"])     # the end a later read gave, put together
    assert x31(json.loads(json.dumps(facts)))[0] == check.MET


def test_e6_an_act_not_installed_is_said_not_run_and_one_not_given_is_x31_missed(tmp_path):
    facts = collect(World(absent={"nc"}, drop={"wget"}), tmp_path)
    nc = [a for a in facts["acts"] if a["act"] == "nc"][0]
    assert nc == {"act": "nc", "argv0": "nc", "not_run": "not installed"}
    state, said = x31(facts)
    assert state == check.MISSED and "wget (pid 6008) not given by read()" in said and "nc" not in said


def test_e6_off_linux_nothing_is_run_and_a_refusal_is_the_fact(tmp_path):
    world = World()
    off = collect(world, tmp_path, platform="win32")
    assert off["not_run"].startswith("not Linux (win32)") and world.started == [] and world.stopped == 0
    assert x31(off)[0] == check.SKIP
    why = "the process events are not read: the kernel did not answer the ask to listen within 2 s"
    refused = collect(World(refuse=why), tmp_path)
    assert refused["refused"] == why and refused["acts"] == [] and refused["counts"] == CLEAN
    assert x31(refused) == (check.MISSED, KERNEL_SAID + "start() was refused where the kernel is known to answer: %s"
                            % why)
    assert refused["kernel"] == KERNEL
    assert refused["run_pid"] == os.getpid()


def test_e6_the_run_never_raises_and_main_writes_its_facts_and_exits_0(tmp_path, capsys):
    bad = collect(World(start_raises=RuntimeError("odd thing")), tmp_path)
    assert bad["error"] == "RuntimeError: odd thing" and x31(bad)[0] == check.MISSED
    world = World()
    out = tmp_path / "facts.json"
    assert run_tool.main(["--out", str(out)], reader=world.reader, run=world.run, which=world.which,
                         server=world.server, platform="linux", work=str(tmp_path), sleep=world.sleep,
                         clock=world.now) == 0
    assert x31(json.loads(out.read_text(encoding="utf-8")))[0] == check.MET
    assert "procevents_run: linux; 14 act(s) ran, 0 not run" in capsys.readouterr().out
    assert run_tool.main(["--out", str(tmp_path / "no" / "such" / "f.json")], platform="win32") == 0
    with pytest.raises(SystemExit) as exc:
        run_tool.main([])
    assert exc.value.code == 2


def test_e6_the_runs_code_is_ascii_stdlib_and_raqibs_reader_alone_and_asks_no_right():
    tree = ast.parse(TOOL)
    mods = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    mods |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert {m.split(".")[0] for m in mods} - {"raqib"} <= set(sys.stdlib_module_names) and "raqib" in mods
    assert [ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)] == [
        "from raqib import procevents"]
    for word in ("sudo", "pkexec", "setuid", "doas", "example.", "github.", "python.org"):
        assert word not in TOOL, word
    assert (ROOT / "tools" / "rig" / "procevents_run.py").read_bytes().isascii()
    assert (ROOT / "tests" / "test_procevents_rig.py").read_bytes().isascii()
    assert (ROOT / "tools" / "rig" / "check.py").read_bytes().isascii()


# --- REDO 2 (Amendment BS): the kernel's release, a loss by the kernel's count, a record given again -----------
def test_e7_bs8_x31_shows_the_kernels_release_and_n_a_and_missed_are_as_they_were():
    facts = dict(met_facts(), kernel="6.8.0-1017-made-up")
    state, said = x31(facts)
    assert state == check.MET and said.startswith("kernel 6.8.0-1017-made-up: 14 act(s) given")
    why = "the process events are not read: the bind ... was refused (EPERM)"
    assert x31(dict(facts, refused=why)) == (
        check.SKIP, "kernel 6.8.0-1017-made-up: start() was refused for want of a right of this user: %s" % why)
    why = "the process events are not read: the kernel did not answer the ask to listen within 2 s"
    assert x31(dict(facts, refused=why))[0] == check.MISSED
    assert x31({"platform": "win32", "kernel": None, "not_run": "not Linux (win32)"}) == (
        check.SKIP, "not run: not Linux (win32)")


def test_e7_bs5_a_loss_by_the_kernels_count_alone_is_x31_missed():
    facts = met_facts()
    facts["counts"]["lost"] = {"count": 0, "events": 3, "why": "3 of them came with no ENOBUFS: a loss the kernel did"
                                                               " not tell"}
    state, said = x31(facts)
    assert state == check.MISSED and "at least 3 event(s) lost by the kernel's count (3 of them came" in said


def test_e2_bs3_heard_takes_a_record_given_again_after_its_end_and_an_end_only_of_its_own_holder():
    heard = run_tool.Heard()
    p = {"pid": 7001, "ppid": RUN_PID, "exe": "/usr/bin/sh", "started_ticks": 9, "began": "b1", "ended": None,
         "code": None, "signal": None, "unread": {}}
    heard.take({"processes": [p], "ends": [], "older": []})
    heard.take({"processes": [], "ends": [dict(pid=7001, started_ticks=9, began="b1", ended="e1", code=0, signal=None,
                                               unread={})], "older": []})
    assert heard.of(7001)["ended"] == "e1"
    again = dict(p, exe="/usr/bin/curl", unread={"ended": "the end given before was its leader thread's"})
    heard.take({"processes": [again], "ends": [], "older": []})
    assert heard.of(7001)["ended"] is None and heard.of(7001)["exe"] == "/usr/bin/curl"
    heard.take({"processes": [], "ends": [dict(pid=7001, started_ticks=None, began="b0", ended="e0", code=1,
                                               signal=None, unread={})], "older": []})   # another holder's end
    assert heard.of(7001)["ended"] is None
