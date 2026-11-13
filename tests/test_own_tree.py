"""M7.27 (ADR-0007 Amendment BH): the watch's own tree is what the watch started.

Every record here is SYNTHETIC (made in memory, in the shape the live readers write: tests/test_reused_pid.py's rows,
tests/test_hostwin.py's host stand-in, tests/test_round_channel.py's channel events): user `user`, host `host`, RFC
5737 documentation addresses only. Nothing was captured from a machine.
"""
import ast
import datetime
import inspect
import json
import os
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "discover"))

from raqib import discover, hostwin, notify, own  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
import synthetic  # noqa: E402
import test_hostwin as th  # noqa: E402
import test_reused_pid as rp  # noqa: E402
import test_round_channel as rc  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
AT = rp.AT
W = rp.W
AGENTX = rp.AGENTX
PYTHON = rp.PYTHON
PS = W + "WindowsPowerShell\\v1.0\\powershell.exe"
row, trees, acted = rp.row, rp.trees, rp.acted
STRANGERS = "that the watch did not start (ADR-0007 BH-3"
UNPROVEN = "the watch recorded as started by it whose start in the sample was not read"
TAKEN = "taken for the watch's own by their dated links alone"
UTC = datetime.timezone.utc


def sample(rows, self_="732", helpers=None, talk=()):
    """{source: (path, text, error)} of one sample as the live reader writes it: its snapshot line (self_ None: an
    export, no line), with " helpers=" where the reader was handed the record (helpers: the pids, "" none alive)."""
    head = [] if self_ is None else [hostwin.SNAPSHOT_LINE % (AT, self_, 1) + (
        "" if helpers is None else hostwin.SNAPSHOT_HELPERS % helpers)]
    procs = "\n".join(head + [synthetic.csv_line(synthetic.WIN_PROCESS)] + [synthetic.csv_line(r) for r in rows])
    tcp = "\n".join([synthetic.csv_line(synthetic.WIN_TCP)] + [synthetic.csv_line(t) for t in talk])
    return {"win-process-1": ("tests/test_own_tree.py win-process-1 (SYNTHETIC)", procs + "\n", None),
            "win-tcp-1": ("tests/test_own_tree.py win-tcp-1 (SYNTHETIC)", tcp + "\n", None)}


def build(rows, self_="732", helpers=None, talk=(), **kw):
    return discover.run(sample(rows, self_, helpers, talk), CATALOG, live=True, processes=True, **kw)


def tcp(pid, port, dest="203.0.113.40"):
    return ("192.0.2.10", port, dest, 443, "Established", pid, "2026-11-13T10:00:25.000Z")


def said(inv, words):
    return [h for h in inv["holes"] if words in h]


def base(reader="10:00:00.000", helper="10:00:20.000"):
    """Idle, System, explorer, the powershell that started the watch, the reader (732), the helper it recorded
    (wevtutil 7400) and the conhost that helper started (7410)."""
    return [row(0, 0, "System Idle Process", None, "07:40:02.000", ""), row(4, 0, "System", None, "07:40:02.000", ""),
            row(3000, 2990, "explorer.exe", "C:\\Windows\\explorer.exe", "07:41:00.000"),
            row(5100, 3000, "powershell.exe", PS, "09:59:00.000"),
            row(732, 5100, "python.exe", PYTHON, reader),
            row(7400, 732, "wevtutil.exe", W + "wevtutil.exe", helper),
            row(7410, 7400, "conhost.exe", W + "conhost.exe", "10:00:20.100")]


MODEL_CALL = tcp(732, 50600)   # the watch's own model call (the suspect layer is a thread of the watch)


# --- E1 (BH-1): every program Raqib starts is recorded as it starts --------------------------------------------

STARTS = {"Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}
OTHER_STARTS = {"system", "popen", "startfile", "posix_spawn", "posix_spawnp", "execv", "execve", "execvp", "execvpe",
                "execl", "execle", "execlp", "execlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl",
                "spawnle", "spawnlp", "spawnlpe", "fork", "forkpty", "create_subprocess_exec",
                "create_subprocess_shell"}
# The short list: a start that is not recorded, each with its reason.
NOT_RECORDED = {
    ("raqib/discover.py", "run_ss"):
        "ss: subprocess.run gives no pid, and tests/test_discover.py's B-1 guard holds discover.py to this one"
        " subprocess.run and no Popen (tests replace discover.subprocess.run). ss runs to its end inside the call, in"
        " the thread that takes the sample; one still running under the reader's pid in a sample is not the watch's"
        " (BH-3) and is named (the builder's question Q1 of this task)",
    ("raqib/hooks/os_sysmon.py", "read_live"):
        "the `raqib os-sysmon` command's one read (raqib/cli.py), a command of its own that takes no process"
        " sample; subprocess.run gives no pid. The watch's channel reads through read_live_bounded, recorded",
    ("raqib/doctor.py", "run_version"):
        "`raqib doctor`, a command of its own: it takes no process sample, so no tree of its own is left out",
}
STARTS_NOTHING = {"raqib/cli.py": "the command line: its commands start programs only through the modules above"}


def _starts(path):
    """[(enclosing function, recorded, text)] of every call in a module that starts a program: subprocess.<start>,
    or a parameter whose default is one (read_live_bounded's popen), called. Recorded: the call is the first
    argument of own.started(...)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("subprocess", "asyncio"):
            out.append(("<import>", False, ast.unparse(node)))
        if not isinstance(node, ast.Call):
            continue
        f, fns, up = node.func, [], parents.get(node)
        while up is not None:
            if isinstance(up, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fns.append(up)
            up = parents.get(up)
        start = isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and (
            (f.value.id == "subprocess" and f.attr in STARTS) or (f.value.id in ("os", "asyncio")
                                                                 and f.attr in OTHER_STARTS))
        if isinstance(f, ast.Name):
            for fn in fns:
                args = fn.args.args[-len(fn.args.defaults):] if fn.args.defaults else []
                pairs = list(zip(args, fn.args.defaults)) + list(zip(fn.args.kwonlyargs, fn.args.kw_defaults))
                for a, d in pairs:
                    if a.arg == f.id and isinstance(d, ast.Attribute) and getattr(d.value, "id", None) == \
                            "subprocess" and d.attr in STARTS:
                        start = True
        if start:
            p = parents.get(node)
            recorded = isinstance(p, ast.Call) and p.args and p.args[0] is node and isinstance(p.func, ast.Attribute) \
                and getattr(p.func.value, "id", None) == "own" and p.func.attr == "started"
            out.append((fns[0].name if fns else "<module>", bool(recorded), ast.unparse(node)[:80]))
    return out


def test_e1_every_program_raqib_starts_is_recorded_or_in_the_short_list_with_its_reason():
    unrecorded, recorded = {}, set()
    for path in sorted((ROOT / "raqib").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        for fn, ok, text in _starts(path):
            if ok:
                recorded.add((rel, fn))
            else:
                unrecorded.setdefault((rel, fn), []).append(text)
        if rel in STARTS_NOTHING:
            assert _starts(path) == [], rel
    assert set(unrecorded) == set(NOT_RECORDED), unrecorded      # the list is whole, and none of it is stale
    assert all(reason for reason in NOT_RECORDED.values())
    assert {("raqib/notify.py", "run_program"), ("raqib/hooks/os_sysmon.py", "read_live_bounded")} <= recorded
    # raqib/own.py: the standard library only, and no network
    tree = ast.parse((ROOT / "raqib" / "own.py").read_text(encoding="utf-8"))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert imported - {"__future__"} <= set(sys.stdlib_module_names)
    assert not imported & {"socket", "ssl", "http", "urllib", "asyncio", "selectors", "select", "ctypes", "subprocess",
                           "raqib"}
    assert (ROOT / "raqib" / "own.py").read_bytes().isascii()


class FakeProc:
    def __init__(self, pid):
        self.pid, self.returncode = pid, 0

    def communicate(self, timeout=None):
        return b"", b""


def test_e1_the_notifier_and_the_channels_reader_are_recorded_when_they_start(monkeypatch):
    made = []

    def popen(argv, **kw):   # pids above any pid_max: never a real process's
        made.append(FakeProc(4242001 + len(made)))
        return made[-1]
    monkeypatch.setattr(notify.subprocess, "Popen", popen)
    assert notify.run_program([os.path.abspath(os.sep + "raqib-fake-notifier"), "x"], {}) == (0, None)
    assert os_sysmon.read_live_bounded(1.0, popen=popen, environ={}) == ("", None)
    assert {4242001, 4242002} <= set(own.RECORD.kept())


def test_e1_the_record_is_thread_safe_bounded_and_forgets_what_a_sample_shows_ended():
    rec = own.Record(kept_max=50, clock=lambda: 1000.0)
    threads = [threading.Thread(target=lambda b=b: [rec.add(b * 1000 + i) for i in range(200)]) for b in range(1, 9)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(rec.kept()) == 50 and own.KEPT_MAX == 256
    rec = own.Record(clock=lambda: 1000.0)
    for pid in (10, 11, 12, 13):
        rec.add(pid, at=1000.0)
    starts = {10: 999.5, 11: None, 12: 1000.0 + own.STARTED_AFTER + 1.0, 3: 50.0}   # 12: another process; 13 ended
    assert rec.alive(starts, since=None) == [10, 11]
    assert set(rec.kept()) == {10, 11, 12, 13}          # a sample that may not list every process forgets nothing
    assert rec.alive(starts, since=1001.0) == [10, 11] and set(rec.kept()) == {10, 11}
    assert rec.alive({10: 1000.0 - own.STARTED_BEFORE - 1.0}, since=None) == []   # started long before its record
    rec.add(14, at=1002.0)
    assert rec.alive({}, since=1001.0) == [] and 14 in rec.kept()   # recorded after the sample began: kept
    p = FakeProc(15)
    assert rec.started(p) is p and 15 in rec.kept() and rec.started(object()) is not None


# --- E2 (BH-2): the sample names them; a text without them reads as before -----------------------------------

def test_e2_the_snapshot_line_carries_the_helpers_and_a_line_without_them_reads_as_before():
    assert hostwin.SNAPSHOT_HELPERS == discover.WIN_SNAPSHOT_HELPERS == " helpers=%s"
    assert hostwin.SNAPSHOT_LINE == discover.WIN_SNAPSHOT_LINE

    def snap(line):
        records, problems = discover.parse_win_process(line + "\n\"ProcessId\",\"ParentProcessId\",\"Name\"\n", "w")
        assert problems == [] and records[0]["kind"] == "snapshot"
        return records[0]
    line = hostwin.SNAPSHOT_LINE % (AT, "732,7300", 1)
    old = snap(line)
    assert "helpers" not in old and (old["self"], old["launchers"]) == (732, [7300])
    for helpers, want in (("7400,7410", [7400, 7410]), ("", [])):
        new = snap(line + hostwin.SNAPSHOT_HELPERS % helpers)
        assert new["helpers"] == want
        assert {k: v for k, v in new.items() if k not in ("helpers", "text")} == \
            {k: v for k, v in old.items() if k != "text"}
    meta = {"snapshot": AT, "self": 1540, "processes": 0}
    (rec,), _ = discover.parse_proc(json.dumps(meta) + "\n")
    assert "helpers" not in rec and rec["self"] == 1540
    (rec,), _ = discover.parse_proc(json.dumps(dict(meta, helpers=[1700])) + "\n")
    assert rec["helpers"] == [1700]
    # no existing fixture carries a record: each reads as before (their pins are the inventories they gave)
    for base_dir in (ROOT / "tests" / "fixtures", ROOT / "raqib" / "rules" / "hostdata"):
        for path in base_dir.rglob("*"):
            if path.is_file() and path.suffix in (".txt", ".csv", ".json", ".xml"):
                text = path.read_bytes()
                assert b" helpers=" not in text and b'"helpers"' not in text, path


@pytest.mark.skipif(not hasattr(os, "sysconf"), reason="no clock tick rate here: a Linux start is not read")
def test_e2_the_linux_snapshot_names_the_recorded_pids_alive_in_it_and_the_parser_proves_them(tmp_path):
    clk, now = os.sysconf("SC_CLK_TCK"), 1794564000.0
    btime = int(now) - 1000
    root = tmp_path / "proc"
    root.mkdir()
    (root / "stat").write_text("cpu 0\nbtime %d\n" % btime)
    for pid, ppid, name, age in ((1540, 1, "python3", 600.0), (1700, 1540, "notify-send", 0.5),
                                 (1710, 1540, "sleep", 500.0)):
        d = root / str(pid)
        d.mkdir()
        (d / "status").write_text("Name:\t%s\nPPid:\t%d\n" % (name, ppid))
        (d / "cmdline").write_bytes(name.encode("ascii") + b"\0")
        (d / "environ").write_bytes(b"")
        ticks = int(round((now - age - btime) * clk))
        (d / "stat").write_text("%d (%s) S %d %s %d 0 0\n" % (pid, name, ppid, " ".join(["0"] * 17), ticks))
    rec = own.Record(clock=lambda: now)
    rec.add(1700, at=now)
    rec.add(1710, at=now)        # its pid now held by a process 500 s older than the record: another process
    rec.add(1720, at=now - 5.0)  # ended before the snapshot: not in it
    text = discover.snapshot_proc(str(root), AT, 1540, record=rec)
    assert json.loads(text.splitlines()[0])["helpers"] == [1700] and 1720 not in rec.kept()
    assert "helpers" not in json.loads(discover.snapshot_proc(str(root), AT, 1540).splitlines()[0])
    inv = discover.run({"proc": ("tests/test_own_tree.py proc (SYNTHETIC)", text, None)}, CATALOG, processes=True)
    (strangers,) = said(inv, STRANGERS)
    assert strangers.endswith(": pid 1710 under parent pid 1540 (the reader's own pid)")   # the helper is not named


# --- E3 (BH-3): the watch's own tree is what it started ----------------------------------------------------------

@pytest.mark.parametrize("name, path", [("agentx.exe", AGENTX), ("powershell.exe", PS),
                                        ("wevtutil.exe", W + "wevtutil.exe")], ids=["agentx", "powershell", "wevtutil"])
def test_e3a_a_process_that_names_the_reader_its_parent_and_was_not_recorded_is_judged(name, path):
    rows = base() + [row(2400, 732, name, path, "10:00:10.000"), row(2410, 2400, "cmd.exe", W + "cmd.exe",
                                                                     "10:00:11.000")]
    talk = [tcp(2400, 50500), MODEL_CALL]
    inv = build(rows, helpers="7400", talk=talk)
    assert trees(inv) == [(2400, [2400, 2410])]            # started after the reader, under it, not recorded
    assert not {732, 7400, 7410} & acted(inv)              # the helper and its conhost: no tree, nobody's act
    (strangers,) = said(inv, STRANGERS)
    assert strangers.startswith("1 process(es)") and strangers.endswith(
        ": pid 2400 under parent pid 732 (the reader's own pid)")
    assert trees(build(rows, talk=talk)) == []             # no record: M7.26's tree takes it by its dates


def launcher_rows():
    """A Python harness (7300) that started the watch (7320) and an agent beside it (2400, with its child)."""
    rows = [r for r in base() if r[0] not in (732, 7400, 7410)]
    return rows + [row(7300, 5100, "python.exe", PYTHON, "09:59:30.000"),
                   row(7320, 7300, "python.exe", PYTHON, "10:00:00.000"),
                   row(7400, 7320, "wevtutil.exe", W + "wevtutil.exe", "10:00:20.000"),
                   row(7410, 7400, "conhost.exe", W + "conhost.exe", "10:00:20.100"),
                   row(2400, 7300, "agentx.exe", AGENTX, "10:00:05.000"),
                   row(2410, 2400, "cmd.exe", W + "cmd.exe", "10:00:06.000")]


def test_e3b_another_child_of_the_readers_launcher_is_not_the_watchs_and_the_launcher_is_no_candidate():
    talk = [tcp(2400, 50500), tcp(7300, 50610), tcp(7320, 50600)]    # the harness and the watch talk too
    inv = build(launcher_rows(), self_="7320,7300", helpers="7400", talk=talk)
    assert inv["self"] == [7300, 7320] and trees(inv) == [(2400, [2400, 2410])]
    assert not {7300, 7320, 7400, 7410} & acted(inv)       # the launcher itself only: no candidate, no act
    (strangers,) = said(inv, STRANGERS)
    assert strangers.endswith(": pid 2400 under parent pid 7300 (the reader's own pid)")
    assert trees(build(launcher_rows(), self_="7320,7300", talk=talk)) == []   # no record: M7.26 hides it


def test_e3c_an_old_chain_that_reads_younger_than_the_reader_a_clock_set_back_is_judged():
    rows = base() + [row(700, 732, "wininit.exe", W + "wininit.exe", "10:00:01.000"),
                     row(760, 700, "services.exe", W + "services.exe", "10:00:02.000"),
                     row(2400, 760, "agentx.exe", AGENTX, "10:00:03.000"),
                     row(2410, 2400, "cmd.exe", W + "cmd.exe", "10:00:04.000")]
    talk = [tcp(2400, 50500), MODEL_CALL]
    inv = build(rows, helpers="7400", talk=talk)
    assert trees(inv) == [(2400, [2400, 2410])] and not {732, 7400, 7410} & acted(inv)
    (strangers,) = said(inv, STRANGERS)
    assert strangers.endswith(": pid 700 under parent pid 732 (the reader's own pid)")
    assert trees(build(rows, talk=talk)) == []             # no record: as test_e2_negative of M7.26 pins


@pytest.mark.parametrize("helper", ["09:00:00.000", ""], ids=["before-the-reader", "start-unread"])
def test_e3_negative_a_recorded_pid_not_proven_by_its_start_is_not_the_watchs_and_is_named(helper):
    inv = build(base(helper=helper), helpers="7400", talk=[MODEL_CALL])
    assert inv["candidates"] == [] and not {7400, 7410} & acted(inv)
    (unproven,) = said(inv, UNPROVEN)
    assert unproven.endswith("judged as any other process: pid 7400")


# --- E4 (BH-3 MUST NOT TOUCH): a sample with no record keeps M7.26's tree, and says so --------------------------

def test_e4_a_sample_with_no_record_keeps_m726s_tree_and_the_hole_says_the_record_was_not_there():
    rows = base() + [row(2400, 732, "agentx.exe", AGENTX, "10:00:10.000"),
                     row(2410, 2400, "cmd.exe", W + "cmd.exe", "10:00:11.000")]
    talk = [tcp(2400, 50500)]
    old = build(rows, talk=talk)                           # the reader's line of before: no " helpers="
    assert trees(old) == [] and old["self"] == [732] and not said(old, STRANGERS) and not said(old, UNPROVEN)
    (taken,) = said(old, TAKEN)
    assert taken.startswith("4 process(es)") and "the sample carries no record of what the watch started" in taken
    assert "pid 7400 under parent pid 732 (the reader's own pid)" in taken and "pid 2410 under parent pid 2400" in taken
    new = build(rows, helpers="", talk=talk)               # a record with nothing alive in it: the same rows judged
    assert trees(new) == [(2400, [2400, 2410])] and not said(new, TAKEN)
    export = build(rows, self_=None, talk=talk)            # an export names no reader: nothing taken, nothing said
    assert trees(export) == [(2400, [2400, 2410])] and not said(export, TAKEN)
    started = inspect.signature(hostwin.self_tree).parameters["started"]
    assert started.default is inspect.Parameter.empty      # BG-5: no walk of launchers by images alone
    with pytest.raises(TypeError):
        hostwin.self_tree([(1, 0, "python.exe")], 1)


# --- E5 (BH-4): no walk of parents passes through the watch's tree ------------------------------------------------

def test_e5_a_process_under_a_helper_by_a_link_not_dated_is_nobodys_act_while_the_reader_talks():
    rows = base() + [row(7500, 7400, "WerFault.exe", W + "WerFault.exe", "")]   # its start not read
    inv = build(rows, helpers="7400", talk=[MODEL_CALL])
    assert inv["candidates"] == [] and not {732, 7400, 7500} & acted(inv)       # the reader is no candidate
    (unread,) = said(inv, rp.UNREAD)
    assert "pid 7500 under parent pid 7400 (in the reader's tree)" in unread


@pytest.mark.parametrize("helpers", [None, "7400"], ids=["no-record", "record"])
def test_e5_the_bridge_an_orphan_chain_under_the_reader_gives_its_acts_to_no_ancestor_of_the_reader(helpers):
    rows = base() + [row(700, 732, "wininit.exe", W + "wininit.exe", ""),      # the link to the reader not dated
                     row(760, 700, "services.exe", W + "services.exe", "07:40:10.000"),
                     row(800, 760, "svchost.exe", W + "svchost.exe", "07:40:20.000"),
                     row(2400, 3000, "agentx.exe", AGENTX, "09:30:00.000"),     # an agent of its own, beside
                     row(2410, 2400, "cmd.exe", W + "cmd.exe", "09:31:00.000"),
                     row(2420, 2410, "PING.EXE", W + "PING.EXE", "09:31:01.000")]
    talk = [tcp(5100, 50700), MODEL_CALL, tcp(2400, 50500)]   # the shell that started the watch talks, and the watch
    inv = build(rows, helpers=helpers, talk=talk)
    assert trees(inv) == [(2400, [2400, 2410, 2420])]           # neither the shell nor the reader takes the chain
    members = {732, 7400, 7410}
    assert [a["via"] for a in inv["candidates"][0]["acts"]] == [[], [2410]]
    assert not any(set(a["via"]) & members for c in inv["candidates"] for a in c["acts"])
    assert not any(set(a["via"]) & members for t in inv["act_roots"] for a in t["acts"])
    (unread,) = said(inv, rp.UNREAD)
    assert "pid 700 under parent pid 732 (the reader's own pid)" in unread


# --- E6 (BH-5): the holes say what was read --------------------------------------------------------------------

def test_e6_the_broken_hole_says_what_was_read_and_marks_the_reader_as_its_child_the_count_whole():
    rows = [r if r[0] != 5100 else row(5100, 3000, "powershell.exe", PS, "10:00:05.000") for r in base()]
    rows += [row(9000, 3000, "notepad.exe", W + "notepad.exe", "10:00:10.000")]
    rows += [row(9100 + k, 9000, "conhost.exe", W + "conhost.exe", "08:00:00.000") for k in range(24, -1, -1)]
    inv = build(rows, helpers="7400")
    (broken,) = said(inv, rp.BROKEN)
    assert broken == ("26 " + rp.BROKEN + ": the holder of the parent pid started after the child (a pid taken again,"
                      " or a clock set back between the two; BH-5); the child has no parent in this round (its acts go"
                      " to no ancestor through it): " + ", ".join(
                          ["pid 732 (the reader's own pid) under parent pid 5100"] +
                          ["pid %d under parent pid 9000" % (9100 + k) for k in range(19)]) + " and 6 more")


# --- E7 (BH-6): the live reader's own rows, the channel's path, the act roots' two walks -----------------------

def filetime(text):
    """The FILETIME of "HH:MM:SS.fff" on 2026-11-13 (UTC)."""
    d = datetime.datetime.strptime("2026-11-13T" + text, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=UTC) - \
        datetime.datetime(1601, 1, 1, tzinfo=UTC)
    return (d.days * 86400 + d.seconds) * 10 ** 7 + d.microseconds * 10


def epoch(text):
    return datetime.datetime.strptime("2026-11-13T" + text, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=UTC).timestamp()


def test_e7_through_the_live_readers_own_rows_a_process_it_could_not_open_and_pid_0():
    host = th.FakeHost([(0, 0, "System Idle Process", None, 0),
                        (3000, 2990, "explorer.exe", "C:\\Windows\\explorer.exe", filetime("07:41:00.000")),
                        (5100, 3000, "powershell.exe", PS, filetime("09:59:00.000")),
                        (732, 5100, "python.exe", PYTHON, filetime("10:00:00.000")),
                        (7400, 732, "wevtutil.exe", W + "wevtutil.exe", filetime("10:00:20.000")),
                        (7410, 7400, "conhost.exe", W + "conhost.exe", filetime("10:00:20.100")),
                        (2400, 732, "powershell.exe", PS, filetime("10:00:10.000")),   # names the reader: not recorded
                        (2410, 2400, "cmd.exe", W + "cmd.exe", filetime("10:00:11.000")),
                        (7600, 732, "conhost.exe", W + "conhost.exe", filetime("10:00:12.000"))],   # cannot be opened
                       [(5, "192.0.2.10", 50500, "203.0.113.40", 443, 2400),
                        (5, "192.0.2.10", 50600, "203.0.113.40", 443, 732)], {}, denied=(7600,))
    rec = own.Record(clock=lambda: epoch("10:00:30.000"))
    rec.add(7400, at=epoch("10:00:20.300"))
    rec.add(7700, at=epoch("10:00:25.000"))               # ended before the sample: forgotten by it
    entry, denied, _, mine = hostwin.process_text(host, 1, 732, AT, rec)
    assert entry[1].splitlines()[0] == hostwin.SNAPSHOT_LINE % (AT, "732", 1) + hostwin.SNAPSHOT_HELPERS % "7400"
    assert mine == [732] and denied == [7600] and 7700 not in rec.kept()
    assert th.rows_of_text(entry[1])[-1]["CreationDate"] == ""          # as the live reader writes it
    inv = discover.run({"win-process-1": entry, "win-tcp-1": hostwin.tcp_text(host, 1, AT)[0]}, CATALOG, live=True,
                       processes=True)
    assert trees(inv) == [(2400, [2400, 2410])] and not {732, 7400, 7410, 7600} & acted(inv)
    (unread,) = said(inv, rp.UNREAD)
    assert "pid 7600 under parent pid 732 (the reader's own pid)" in unread
    assert said(inv, STRANGERS)[0].endswith(": pid 2400 under parent pid 732 (the reader's own pid)")
    first, _, _, _ = hostwin.process_text(host, 1, 732, AT)   # no record handed: the line as before
    assert first[1].splitlines()[0] == hostwin.SNAPSHOT_LINE % (AT, "732", 1)


def test_e7_the_channels_path_a_parent_timed_by_the_channel_and_its_child_by_the_sample():
    rows = base() + [row(2410, 2400, "cmd.exe", W + "cmd.exe", "10:00:11.000")]   # its parent is in the channel only
    g = rc.guid_of(2400)
    xml = rc.channel_xml(rc.created(900, "2026-11-13 10:00:10.000", 2400, AGENTX, g, 732, PYTHON, rc.guid_of(732),
                                    "agentx"),
                         rc.talked(901, "2026-11-13 10:00:10.500", 2400, AGENTX, g))
    channel = ("tests/test_own_tree.py sysmon (SYNTHETIC)", xml, None)
    inv = discover.run(dict(sample(rows, helpers="7400", talk=[MODEL_CALL]), sysmon=channel), CATALOG, live=True,
                       processes=True, channel=True)
    assert trees(inv) == [(2400, [2400, 2410])] and not {732, 7400, 7410} & acted(inv)
    assert said(inv, STRANGERS)[0].endswith(": pid 2400 under parent pid 732 (the reader's own pid)")
    old = discover.run(dict(sample(rows, talk=[MODEL_CALL]), sysmon=channel), CATALOG, live=True, processes=True,
                       channel=True)
    assert trees(old) == []           # no record: the channel's start proves it the reader's by its date (M7.26)


def act_root_rows(agentx="09:30:00.000", ping="09:31:01.000"):
    """agentx under the user's AppData, started from a listed shell (powershell), runs cmd which runs ping."""
    return [row(760, 700, "services.exe", W + "services.exe", "07:40:10.000"),
            row(3000, 2990, "explorer.exe", "C:\\Windows\\explorer.exe", "07:41:00.000"),
            row(5100, 3000, "powershell.exe", PS, "09:29:00.000"),
            row(2400, 5100, "agentx.exe", AGENTX, agentx),
            row(2410, 2400, "cmd.exe", W + "cmd.exe", "09:31:00.000"),
            row(2420, 2410, "PING.EXE", W + "PING.EXE", ping)]


LISTEN = [("0.0.0.0", 135, "0.0.0.0", 0, "Listen", 760, "2026-11-13T07:40:10.000Z")]


def test_e7_the_act_roots_children_walk_does_not_cross_a_broken_link():
    assert [t["pid"] for t in build(act_root_rows(), self_=None, talk=LISTEN)["act_roots"]] == [2400]
    inv = build(act_root_rows(ping="09:30:30.000"), self_=None, talk=LISTEN)   # ping older than the cmd it names
    assert inv["act_roots"] == [] and said(inv, rp.BROKEN)[0].endswith(": pid 2420 under parent pid 2410")


def test_e7_the_act_roots_shell_parent_walk_does_not_cross_a_broken_link():
    inv = build(act_root_rows(agentx="09:31:30.000", ping="09:31:31.000"), self_=None, talk=LISTEN)   # agentx after cmd
    assert inv["act_roots"] == [] and said(inv, rp.BROKEN)[0].endswith(": pid 2410 under parent pid 2400")
