"""M10.3c-b (ADR-0011 Amendment Y): `raqib forward --to eventlog:`, the Windows event log as a destination of the
forwarder. No test here calls the real system, on any platform: every forwarder is given a made-up advapi32
(Fake below, through Forwarder(loader=)), and an autouse fixture replaces forward.eventlog_dll - the loader a
forwarder with no loader of its own would use - by a guard that refuses and records, so a forwarder built with
none reaches no system either, on Windows too. The platform is injected (win32, or another where the test needs
"not Windows"). Every clock and wait of the forwarder is injected (no sleep)."""
import ast
import ctypes
import hashlib
import importlib.util
import io
import json
import os
import re
import threading
from pathlib import Path

import pytest

from raqib import cli, event, forward, link

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("forward_tests_for_eventlog", ROOT / "tests" / "test_forward.py")
tf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tf)

# Y-2's tables, in the ruling's words and not by the forwarder's own code
TYPE_OF = {"high": 1, "medium": 2, "hole": 2, "low": 4, "info": 4, "none": 4}   # 1 Error, 2 Warning, 4 Information
ID_OF = {"finding": 1001, "source-finding": 1002, "note": 1003, "tree": 1004, "hole": 1005, "knock": 1006,
         "heartbeat": 1007, "watch": 1008}
HEAD = re.compile(r"raqib-part ([0-9]+)/([0-9]+) id=(\S+) sha256=([0-9a-f]{64}) chars=([0-9]+)\Z")


class Call:
    """One function of the made-up DLL: ctypes' restype and argtypes can be set on it, as on a real one."""

    def __init__(self, fn):
        self.fn, self.restype, self.argtypes = fn, None, None

    def __call__(self, *args):
        return self.fn(*args)


class Fake:
    """A made-up advapi32. `refuse_open` opens refused (handle 0) before one is given; `refuse` the numbers of
    ReportEventW's calls refused (1 is the first call of the test), or a test of the strings (`refuse_if`);
    `raise_at` a call number that raises OSError; `during` a function called at each call with its number. Each
    call is kept: `events` [(handle, type, category, id, user, count, size, strings, raw, taken)]."""

    def __init__(self, refuse_open=0, refuse=(), refuse_if=None, raise_at=None, during=None):
        self.refuse_open, self.refuse, self.refuse_if = refuse_open, set(refuse), refuse_if
        self.raise_at, self.during = raise_at, during
        self.loads, self.opens, self.closes, self.events = [], [], [], []
        self.next = 0x5150
        self.RegisterEventSourceW = Call(self.register)
        self.ReportEventW = Call(self.report)
        self.DeregisterEventSource = Call(self.deregister)
        self.lock = threading.Lock()

    def load(self, name):
        self.loads.append(name)
        return self

    def register(self, server, source):
        with self.lock:
            if self.refuse_open:
                self.refuse_open -= 1
                self.opens.append((server, source, 0))
                return 0
            self.next += 1
            self.opens.append((server, source, self.next))
            return self.next

    def report(self, handle, kind, category, ident, user, count, size, strings, raw):
        texts = tuple(strings[i] for i in range(count))
        n = len(self.events) + 1
        if self.during:
            self.during(n)
        if n == self.raise_at:
            raise OSError(5, "made-up: refused by raising")
        taken = n not in self.refuse and not (self.refuse_if and self.refuse_if(texts))
        self.events.append((handle, kind, category, ident, user, count, size, texts, raw, taken))
        return 1 if taken else 0

    def deregister(self, handle):
        self.closes.append(handle)
        return 1

    def taken(self):
        return [e for e in self.events if e[-1]]

    def lines(self):
        """The lines the log took, put back together from their parts, in order (a reader's way, Y-3)."""
        out, parts = [], []
        for e in self.taken():
            texts = e[7]
            if e[3] == 1009:
                m = HEAD.match(texts[0])
                parts = [texts[1]] if m and m.group(1) == "1" else parts + [texts[1]]   # a part 1 begins anew
                if m and m.group(1) == m.group(2):
                    whole = "".join(parts)
                    assert hashlib.sha256(whole.encode("utf-8")).hexdigest() == m.group(4)
                    assert len(whole) == int(m.group(5))
                    out.append(whole)
                    parts = []
            else:
                out.append(texts[0])
        return out


GUARD = []   # the default loader's calls: a forwarder built with no loader of its own (none reaches the system)


def guard(name):
    GUARD.append(name)
    raise OSError(2, "made-up: the tests reach no real system (%s)" % name)


@pytest.fixture(autouse=True)
def no_real_system_and_no_thread_left(monkeypatch):
    """No test here reaches the real event log: forward.eventlog_dll is the guard. And, as tests/test_forward.py
    holds (N-7), every run is on a thread of its own and no thread of the forwarder outlives its test."""
    monkeypatch.setattr(forward, "eventlog_dll", guard)
    before = {t for t in threading.enumerate() if t.name.startswith(tf.THREADS)}
    monkeypatch.setattr(forward.Forwarder, "run", tf.bounded_run)
    yield
    assert not tf.left_behind(before)


def efwd(tmp_path, path, system, clock=None, **kw):
    kw.setdefault("name", "e")
    kw.setdefault("platform", "win32")
    clock = clock or tf.Clock()
    kw.setdefault("mono", clock)
    return forward.Forwarder(kw.pop("name"), path, "eventlog:", home=str(tmp_path / "home"), out=io.StringIO(),
                             clock=clock, wait=clock.wait, loader=system.load if system else None, **kw)


def text_of(raw):
    return raw[:-1].decode("ascii")


def long_line(chars, start=1):
    """A whole event line (a note) of exactly `chars` characters without its newline."""
    bare = len(tf.lines(1, start)[0]) - 1
    raw = tf.lines(1, start, size=chars - bare)[0]
    assert len(raw) - 1 == chars
    return raw


def on_windows(monkeypatch):
    """cli.main's forwarder as on Windows, with the made-up system: the platform and the loader injected."""
    real = forward.Forwarder
    system = Fake()
    monkeypatch.setattr(forward, "Forwarder", lambda *a, **k: real(*a, platform="win32", loader=system.load, **k))
    return system


# --- E1 (Y-1, Y-5): the destination, what it refuses, the state ----------------------------------------------
def test_e1_eventlog_colon_in_any_case_is_the_whole_destination_and_anything_after_the_colon_is_exit_2(
        tmp_path, capsys, monkeypatch):
    for url in ("eventlog:", "EVENTLOG:", "EventLog:", "eVeNtLoG:"):
        assert forward.destination(url) == ({"scheme": "eventlog"}, None)
    for url in ("eventlog:x", "eventlog://", "eventlog:Application", "eventlog: ", "eventlog://h:1/", "EVENTLOG:/"):
        with pytest.raises(forward.UsageError, match="nothing follows the colon"):
            forward.destination(url)
    with pytest.raises(forward.UsageError, match=r"or eventlog: \(Windows\)"):
        forward.destination("eventlogs://h:1/")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    on_windows(monkeypatch)
    path = tf.write(tmp_path / "e.jsonl", tf.lines(2))
    capsys.readouterr()
    assert cli.main(["forward", path, "--to", "eventlog:x", "--name", "e", "--once"], out=io.StringIO()) == 2
    assert "nothing follows the colon" in capsys.readouterr().err
    assert link.where({"scheme": "eventlog"}) == "the Windows event log" and "eventlog" in link.SCHEMES
    assert link.DELIVERY_OF["eventlog"] == "written" and forward.EVENTLOG_SCHEME == link.EVENTLOG == "eventlog"


def test_e1_with_eventlog_a_token_ca_plain_shape_hec_framing_and_facility_are_exit_2_each_with_its_reason(
        tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    system = on_windows(monkeypatch)
    path = tf.write(tmp_path / "e.jsonl", tf.lines(2))
    token = tf.secret(tmp_path / "token.txt")
    ca = tf.write(tmp_path / "ca.pem", [b"made-up\n"])
    base = ["forward", path, "--to", "eventlog:", "--name", "e", "--once"]
    for more, reason in ((["--token-file", token], "the Windows event log takes no token"),
                         (["--ca", ca], "eventlog: takes no --ca"),
                         (["--plain"], "eventlog: takes no --plain"),
                         (["--shape", "hec"], "--shape hec is HTTP's"),
                         (["--framing", "newline"], "an event of the Windows event log is never framed"),
                         (["--framing", "octet"], "an event of the Windows event log is never framed"),
                         (["--facility", "13"], "the Windows event log has no facility"),
                         (["--facility", "x"], "the Windows event log has no facility")):
        capsys.readouterr()
        assert cli.main(base + more, out=io.StringIO()) == 2, more
        err = capsys.readouterr().err
        assert reason in err, (more, err)
        assert tf.TOKEN not in err
    assert not os.path.exists(forward.state_path("e", str(tmp_path / "home")))   # refused before anything
    assert system.loads == [] and system.events == [] and GUARD == []


def test_e1_on_a_system_that_is_not_windows_eventlog_is_exit_2_saying_so(tmp_path, capsys, monkeypatch):
    path = tf.write(tmp_path / "e.jsonl", tf.lines(2))
    system = Fake()
    for platform in ("linux", "darwin", "cygwin", "freebsd14"):
        with pytest.raises(forward.UsageError, match="eventlog: is Windows'") as got:   # the platform injected
            efwd(tmp_path, path, system, platform=platform)
        assert platform in str(got.value)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    real = forward.Forwarder
    monkeypatch.setattr(forward, "Forwarder", lambda *a, **k: real(*a, platform="linux", loader=system.load, **k))
    capsys.readouterr()
    assert cli.main(["forward", path, "--to", "eventlog:", "--name", "e", "--once"], out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert "eventlog: is Windows'" in err and "linux" in err
    assert system.loads == [] and GUARD == []


def test_e1_the_state_holds_eventlog_written_and_nothing_of_a_host_port_or_facility_and_link_reads_it(tmp_path):
    home = str(tmp_path / "home")
    path = tf.write(tmp_path / "e.jsonl", [])
    clock = tf.Clock()
    f = efwd(tmp_path, path, Fake(), clock=clock)
    assert f.facility is None and f.framing is None and f.delivery == "written" and not f.plain
    f.write_state()
    s = tf.state(tmp_path, "e")
    assert s["destination"] == {"scheme": "eventlog"} and s["delivery"] == "written" and s["shape"] == "raqib"
    assert "facility" not in s and "framing" not in s and s["plain"] is False
    assert link.state_problem(s) is None
    rows = link.read(home, clock.t)
    assert [(r["name"], r["code"], r["word"], r["to"]) for r in rows] == [("e", 0, "OK", "the Windows event log")]
    assert rows[0]["lines"][0] == "to the Windows event log (shape raqib, delivery written)"
    assert link.errors_of("eventlog") is link.EVENTLOG_ERRORS and set(link.EVENTLOG_ERRORS) == set(link.ERRORS)
    assert link.errors_of("journal") is link.JOURNAL_ERRORS and link.errors_of("https") is link.ERRORS
    for word in ("connect", "late", "write"):   # its own words: no collector, no connection, no answer
        said = link.EVENTLOG_ERRORS[word]
        assert "Windows event log" in said and not any(w in said for w in ("collector", "connection", "answer"))
    failing = dict(json.loads(json.dumps(s)), failing={"since": s["written"], "tries": 2, "error": "connect",
                                                       "status": None})
    said = link.judge(failing, clock.t)[2][-1]
    assert "connect (the source Raqib of the Windows event log cannot be opened)" in said
    out = io.StringIO()
    assert forward.status("e", home=home, out=out, clock=clock) == 0 and "to the Windows event log" in out.getvalue()
    app = pytest.importorskip("raqib.app")   # the Link screen: the rows' own words
    assert any("to the Windows event log" in line for line, _ in app.link_view(rows)["text"])
    for change in (lambda d: d["destination"].update(host="127.0.0.1"), lambda d: d["destination"].update(port=1),
                   lambda d: d["destination"].update(path=""), lambda d: d.update(facility=13),
                   lambda d: d.update(framing=None), lambda d: d.update(delivery="sent"),
                   lambda d: d.update(delivery="acknowledged"), lambda d: d.update(plain=True),
                   lambda d: d.update(shape="hec")):
        bad = json.loads(json.dumps(s))
        change(bad)
        assert link.state_problem(bad), bad
        assert link.judge(bad, clock.t)[:2] == (3, "UNREADABLE")


# --- E2 (Y-2): the system's calls through one object; one event a line ----------------------------------------
def test_e2_nothing_of_windows_at_import_and_the_system_is_loaded_at_the_first_send_only(tmp_path):
    tree = ast.parse((ROOT / "raqib" / "forward.py").read_text(encoding="ascii"))
    inside = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inside |= {id(n) for n in ast.walk(fn)}
    windows = [n for n in ast.walk(tree) if isinstance(n, (ast.Attribute, ast.Name)) and
               (getattr(n, "attr", None) or getattr(n, "id", None)) in ("WinDLL", "windll", "oledll", "OleDLL")]
    assert windows and all(id(n) in inside for n in windows)   # only inside a function, never at import
    system = Fake()
    path = tf.write(tmp_path / "e.jsonl", tf.lines(3))
    f = efwd(tmp_path, path, system, batch=1)
    assert system.loads == [] and f.evapi is None   # built: nothing loaded
    assert f.step() == "moved" and system.loads == ["advapi32"]
    api = f.evapi
    assert isinstance(api, forward.EventLogApi)
    f.step()
    assert system.loads == ["advapi32"] and f.evapi is api and len(system.taken()) == 2   # once, kept


def test_e2_the_calls_have_the_measured_signatures():
    system = Fake()
    forward.EventLogApi(system.load)
    handle, word, dword = ctypes.c_void_p, ctypes.c_ushort, ctypes.c_ulong
    assert system.RegisterEventSourceW.restype is handle
    assert system.RegisterEventSourceW.argtypes == [ctypes.c_wchar_p, ctypes.c_wchar_p]
    assert system.ReportEventW.restype is ctypes.c_long
    assert system.ReportEventW.argtypes == [handle, word, word, dword, ctypes.c_void_p, word, dword,
                                            ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_void_p]
    assert system.DeregisterEventSource.argtypes == [handle] and system.DeregisterEventSource.restype is ctypes.c_long
    assert ctypes.sizeof(word) == 2 and ctypes.sizeof(ctypes.c_wchar_p) == ctypes.sizeof(ctypes.c_void_p)


def test_e2_the_type_and_the_id_by_y2s_tables_over_every_kind_and_severity_and_an_event_with_neither():
    raw = tf.lines(1)[0]
    assert set(event.KINDS) == set(ID_OF)
    for kind in tuple(event.KINDS) + ("other", 5, None):
        for sev in ("high", "medium", "low", "hole", "info", "none", "weird", ["high"], None):
            obj = {"kind": kind, "severity": sev}
            got = forward.eventlog_events(raw, obj)
            want_type = TYPE_OF.get(sev, 2) if isinstance(sev, str) else 2
            want_id = ID_OF.get(kind, 1000) if isinstance(kind, str) else 1000
            assert got == [(want_type, want_id, (text_of(raw),))], (kind, sev, got)
    for obj in ({}, None, [], "x", tf.Raising({"kind": "note"})):   # neither a kind nor a severity: never calm
        assert forward.eventlog_events(raw, obj) == [(2, 1000, (text_of(raw),))], obj


def test_e2_every_line_is_one_event_its_one_string_the_line_as_written_in_order_and_the_source_closed(tmp_path):
    rows = tf.severities() + tf.odd_rows() + tf.lines(20)
    path = tf.write(tmp_path / "e.jsonl", rows + [b"not json\n"])
    system = Fake()
    f = efwd(tmp_path, path, system)
    assert f.run(once=True) == 0 and f.offset == os.path.getsize(path) and f.skipped == 1
    assert [e[7] for e in system.events] == [(text_of(r),) for r in rows]
    assert [(e[1], e[3]) for e in system.events[:6]] == [(1, 1001), (2, 1001), (4, 1001), (2, 1005), (4, 1005),
                                                         (4, 1003)]
    assert all(e[2] == 0 and e[4] is None and e[5] == 1 and e[6] == 0 and e[8] is None for e in system.events)
    assert [o[:2] for o in system.opens] == [(None, "Raqib")] and system.closes == [system.opens[0][2]]
    assert {e[0] for e in system.events} == {system.opens[0][2]}
    s = tf.state(tmp_path, "e")
    assert s["delivery"] == "written" and s["sent"] == len(rows) and s["failing"] is None


def exchange(tmp_path, system, events):
    """One EventLogSend's exchange on the test's own thread (its thread is never started)."""
    path = tf.write(tmp_path / "x.jsonl", [])
    job = forward.EventLogSend(efwd(tmp_path, path, system, name="x"), events)
    return job, job.exchange()


@pytest.mark.parametrize("way", ["taken", "refused", "raises", "abandoned", "close raises"])
def test_e2_the_source_is_opened_once_a_send_and_closed_on_every_way_out(tmp_path, way):
    box = {}
    system = Fake(refuse=[2] if way == "refused" else (), raise_at=2 if way == "raises" else None,
                  during=(lambda n: n == 2 and setattr(box["job"], "abandoned", True)) if way == "abandoned" else None)
    if way == "close raises":
        system.DeregisterEventSource = Call(lambda h: (system.closes.append(h), (_ for _ in ()).throw(OSError(6))))
    events = [(4, 1003, ("line %d" % i,)) for i in range(4)]
    path = tf.write(tmp_path / "x.jsonl", [])
    job = box["job"] = forward.EventLogSend(efwd(tmp_path, path, system, name="x"), events)
    r = job.exchange()
    want = {"taken": ("taken", None), "refused": ("failed", "write"), "raises": ("failed", "write"),
            "abandoned": ("failed", "late"), "close raises": ("taken", None)}[way]
    assert (r.kind, r.error) == want
    assert len(system.opens) == 1 and system.closes == [system.opens[0][2]]   # opened once, closed once
    assert len(system.events) == {"taken": 4, "refused": 2, "raises": 1, "abandoned": 2, "close raises": 4}[way]


@pytest.mark.parametrize("how", ["no source", "the open raises", "no advapi32", "no such call"])
def test_e2_a_source_that_cannot_be_opened_is_connect_and_nothing_is_closed_that_was_not_opened(tmp_path, how):
    system = Fake(refuse_open=1 if how == "no source" else 0)
    if how == "the open raises":
        system.RegisterEventSourceW = Call(lambda *a: (_ for _ in ()).throw(OSError(5, "made-up")))
    if how == "no advapi32":
        system.load = lambda name: (_ for _ in ()).throw(OSError(126, "made-up: no such module"))
    if how == "no such call":
        del system.ReportEventW
    path = tf.write(tmp_path / "x.jsonl", [])
    r = forward.EventLogSend(efwd(tmp_path, path, system, name="x"), [(4, 1003, ("a",))]).exchange()
    assert (r.kind, r.error, r.phase) == ("failed", "connect", "connect")
    assert system.closes == [] and system.events == []


# --- E3 (Y-3): a line longer than one string is handed in parts -----------------------------------------------
def test_e3_a_long_line_goes_in_parts_in_order_and_a_reader_puts_it_back_whole_by_its_sha256_and_length(tmp_path):
    big = long_line(100000, 2)
    rows = [tf.lines(1)[0], big, tf.lines(1, 3)[0]]
    path = tf.write(tmp_path / "e.jsonl", rows)
    system = Fake()
    f = efwd(tmp_path, path, system)
    assert f.run(once=True) == 0 and f.refused == 0 and f.sent == 3
    parts = [e for e in system.events if e[3] == 1009]
    assert len(system.events) == 6 and len(parts) == 4 and system.events[1:5] == parts   # in the line's place
    whole = text_of(big)
    for i, e in enumerate(parts, 1):
        assert e[1] == 4 and e[5] == 2 and len(e[7]) == 2   # the line's own type (a note: Information)
        m = HEAD.match(e[7][0])
        assert m and len(e[7][0]) <= 300 and len(e[7][1]) <= 30000
        assert (int(m.group(1)), int(m.group(2)), m.group(3)) == (i, 4, forward.classify(big)["id"])
        assert m.group(4) == hashlib.sha256(big[:-1]).hexdigest() and int(m.group(5)) == len(whole) == 100000
    assert "".join(e[7][1] for e in parts) == whole
    assert system.lines() == [text_of(r) for r in rows]


def test_e3_a_line_of_exactly_30000_characters_is_one_event_and_of_30001_two():
    one = forward.eventlog_events(long_line(30000), event.note({"text": "x"}, tf.FACTS, "2026-11-03T07:50:01.250Z",
                                                                1, "note:1"))
    assert len(one) == 1 and one[0][1] == 1003 and len(one[0][2]) == 1 and len(one[0][2][0]) == 30000
    raw = long_line(30001)
    two = forward.eventlog_events(raw, forward.classify(raw))
    assert [(e[1], len(e[2]), len(e[2][1])) for e in two] == [(1009, 2, 30000), (1009, 2, 1)]
    assert two[0][2][0].startswith("raqib-part 1/2 id=%s " % forward.classify(raw)["id"]) and two[1][2][0].startswith("raqib-part 2/2 ")


def test_e3_an_id_that_is_no_text_of_at_most_128_printable_characters_is_written_as_a_dash():
    raw = tf.lines(1, size=forward.MAX_BYTES - 300)[0]   # the longest line the forwarder reads whole: 18 parts
    for ident, want in (("a" * 128, "a" * 128), ("r1:9", "r1:9"), ("a" * 129, "-"), ("a b", "-"), ("", "-"),
                        ("x\ty", "-"), ("\u00e9", "-"), (5, "-"), (None, "-"), (["r1"], "-")):
        got = forward.eventlog_events(raw, {"id": ident, "kind": "note", "severity": "info"})
        assert len(got) == 18
        for e in got:
            m = HEAD.match(e[2][0])
            assert m and m.group(3) == want and len(e[2][0]) <= 300, (ident, e[2][0][:80])
    got = forward.eventlog_events(raw, None)
    assert HEAD.match(got[0][2][0]).group(3) == "-" and got[0][:2] == (2, 1009)


def test_e3_if_any_part_is_refused_the_send_failed_nothing_passes_and_then_every_line_arrives_whole(tmp_path):
    rows = [tf.lines(1)[0], long_line(100000, 2), tf.lines(1, 3)[0]]
    path = tf.write(tmp_path / "e.jsonl", rows)
    system = Fake(refuse=[3])   # the long line's second part
    f = efwd(tmp_path, path, system)
    assert f.step() == "failed" and f.failing["error"] == "write"
    assert f.offset == 0 and f.sent == 0 and f.refused == 0 and len(system.events) == 3
    for _ in range(6):
        if f.offset == os.path.getsize(path):
            break
        f.step()
    assert f.offset == os.path.getsize(path) and f.sent == 3 and f.failing is None
    seen = []
    for line in system.lines():
        if line not in seen:
            seen.append(line)
    assert seen == [text_of(r) for r in rows]


# --- E4 (Y-4): written, and paced --------------------------------------------------------------------------------
def test_e4_500_lines_ask_the_injected_wait_for_at_least_five_seconds_at_most_100_events_a_second(tmp_path):
    assert forward.EVENTLOG_PACE == 100
    rows = tf.lines(500)
    path = tf.write(tmp_path / "e.jsonl", rows)
    system = Fake()
    clock = tf.Clock()
    f = efwd(tmp_path, path, system, clock=clock)
    assert f.run(once=True) == 0 and f.sent == 500
    assert [e[7] for e in system.events] == [(text_of(r),) for r in rows]
    assert len(clock.waits) == 5 and sum(clock.waits) >= 500 / 100.0 - 1e-6
    assert all(0 < w <= 100 / 100.0 + 1e-6 for w in clock.waits), clock.waits
    assert tf.state(tmp_path, "e")["delivery"] == "written"


def test_e4_a_long_lines_parts_are_counted_in_the_pace(tmp_path):
    rows = [long_line(100000)] + tf.lines(6, 2)   # 7 lines, 10 events: one batch
    path = tf.write(tmp_path / "e.jsonl", rows)
    system = Fake()
    clock = tf.Clock()
    f = efwd(tmp_path, path, system, clock=clock)
    assert f.run(once=True) == 0 and len(system.events) == 10
    assert len(clock.waits) == 1 and 10 / 100.0 - 1e-6 <= clock.waits[0] <= 10 / 100.0 + 1e-6, clock.waits


def test_e4_stop_during_the_pace_ends_the_wait_at_once_and_the_batch_written_stays_passed(tmp_path):
    rows = tf.lines(300)
    path = tf.write(tmp_path / "e.jsonl", rows)
    system = Fake()
    clock = tf.Clock()
    f = efwd(tmp_path, path, system, clock=clock)
    clock.then = lambda c: f.stop() or True   # Stop comes during the first wait
    assert f.run(once=True) == 1
    assert len(clock.waits) == 1 and f.offset == sum(len(r) for r in rows[:100])
    assert [e[7] for e in system.events] == [(text_of(r),) for r in rows[:100]]
    s = tf.state(tmp_path, "e")
    assert s["sent"] == 100 and s["cursor"]["offset"] == f.offset and s["failing"] is None


# --- E5 (Y-5): no source is a collector that is down; a refused event halves the batch --------------------------
def test_e5_a_source_that_cannot_be_opened_is_failing_connect_nothing_passes_and_when_it_opens_none_is_lost(
        tmp_path):
    rows = tf.lines(30)
    path = tf.write(tmp_path / "e.jsonl", rows)
    f = efwd(tmp_path, path, Fake(refuse_open=1))
    assert f.run(once=True) == 1
    s = tf.state(tmp_path, "e")
    assert s["failing"]["error"] == "connect" and s["sent"] == 0 and s["cursor"]["offset"] == 0
    assert "connect" in f.out.getvalue()
    system = Fake(refuse_open=2)   # J-10: tried again; the source opens at the third try
    clock = tf.Clock()
    g = efwd(tmp_path, path, system, clock=clock)
    clock.then = lambda c: g.offset == os.path.getsize(path)   # Stop once every line is passed
    assert g.run() == 0
    assert [round(w) for w in clock.waits[:2]] == [1, 2] and system.closes == [system.opens[2][2]]
    assert [e[7][0] for e in system.events] == [text_of(r) for r in rows]
    s = tf.state(tmp_path, "e")
    assert s["failing"] is None and s["sent"] == 30 and s["behind"] == 0


def test_e5_an_event_refused_is_failing_write_nothing_passes_the_next_batch_halved_and_none_is_lost(tmp_path):
    rows = tf.lines(30)
    path = tf.write(tmp_path / "e.jsonl", rows)
    system = Fake(refuse=[5, 6, 7])   # the fifth call refused; then the next batch's first two; then it takes
    f = efwd(tmp_path, path, system)
    assert f.step() == "failed" and f.failing["error"] == "write" and f.size == 15
    assert f.offset == 0 and f.sent == 0 and "an event refused" in f.out.getvalue()
    assert f.step() == "failed" and f.size == 7 and f.offset == 0   # the sixth refused: halved again
    for _ in range(10):
        if f.offset == os.path.getsize(path):
            break
        f.step()
    assert f.offset == os.path.getsize(path) and f.sent == 30 and f.failing is None and f.refused == 0
    seen = []
    for e in system.taken():
        if e[7][0] not in seen:
            seen.append(e[7][0])
    assert seen == [text_of(r) for r in rows]   # every line arrived, in order, none lost
    assert len(system.opens) == len(system.closes)


def test_e5_x4_an_event_refused_at_every_try_halves_the_batch_so_its_neighbours_are_not_handed_again(tmp_path):
    first = tf.lines(2)
    bad = tf.lines(1, 3, text="refused")[0]
    path = tf.write(tmp_path / "e.jsonl", first + [bad])
    system = Fake(refuse_if=lambda texts: "refused 3" in texts[0])
    f = efwd(tmp_path, path, system)
    assert f.step() == "failed" and f.failing["error"] == "write" and f.size == 1   # three lines: halved to one
    for _ in range(8):
        if f.sent == 2:
            break
        f.step()
    assert f.sent == 2
    for _ in range(4):
        assert f.step() == "failed" and f.failing["error"] == "write"   # the refused one, alone, at every try
    got = [e[7][0] for e in system.events]
    assert 2 <= got.count(text_of(first[0])) <= 3 and 2 <= got.count(text_of(first[1])) <= 3
    assert f.sent == 2 and f.refused == 0 and f.offset == len(first[0]) + len(first[1])   # nothing passed by


# --- E8 (Y-1, Y-4, Y-6): what the documents say ----------------------------------------------------------------
def test_e8_the_threat_model_forward_md_and_the_guide_say_the_event_log():
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    spec = " ".join((ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8").split())
    guide = " ".join((ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8").split())
    assert ("and `raqib forward --to eventlog:` hands them to the Windows event log (the Application log) because a"
            " person ran it. Nothing is installed, registered or switched on by either") in threat
    for text in ("Whoever reads the Application log reads the events (by default any signed-in user)",
                 "Any process can write events under the source `Raqib`",
                 "an event that says Raqib is a lead, not a proof",
                 "The Application log is bounded and overwrites its oldest",
                 "Raqib's events push other programs' out, and are pushed out",
                 "at most 100 events a second", "the forwarder's events carry no user",
                 "the watched agent can do it on purpose", "an administrator's process can clear it"):
        assert text in threat, text
    assert "M10." not in threat
    for text in ("--to eventlog:", "the Application log", "the source `Raqib`", "nothing registered",
                 "1001 finding", "1002 source-finding", "1003 note", "1004 tree", "1005 hole", "1006 knock",
                 "1007 heartbeat", "1008 watch", "1000", "1009", "Error", "Warning", "Information",
                 "raqib-part I/N id=ID sha256=HEX chars=TOTAL", "30000 characters",
                 # Z-2, Z-3, Z-4: the reader's rule whole, what tells of a loss, the system's own reason
                 "the line is whole when part N/N is added", "the sha256 of its characters as ASCII bytes",
                 "A set that never reaches N/N, or whose hash is not the head's, is no line: drop it",
                 "keep them apart by the process", "no heartbeat (id 1007) for more than two beats",
                 "`failing.status` is the system's own error number", "`written`", "not a search of the log", "at most 100 events a second",
                 "parts counted", "the description for the event cannot be found", "{\"scheme\": \"eventlog\"}",
                 "\"the Windows event log\""):
        assert text in spec, text
    assert "(`eventlog:`, Windows only" in guide and "at most 100 events a second" in guide


# --- E9: ASCII, and no real system --------------------------------------------------------------------------------
def test_e9_the_new_code_is_ascii_and_a_forwarder_with_no_loader_of_its_own_reaches_only_the_guard(tmp_path):
    for rel in ("raqib/forward.py", "raqib/link.py", "raqib/cli.py", "tests/test_forward_eventlog.py",
                "tools/rig/forward_run.py", "tools/rig/check.py", "tests/test_forward_rig.py"):
        (ROOT / rel).read_bytes().decode("ascii")
    assert forward.eventlog_dll is guard   # the autouse fixture's, on every platform
    del GUARD[:]
    path = tf.write(tmp_path / "e.jsonl", tf.lines(2))
    f = efwd(tmp_path, path, None)
    assert f.step() == "failed" and f.failing["error"] == "connect" and f.offset == 0
    assert GUARD == ["advapi32"] and f.evapi is None   # asked of the guard; nothing kept; tried again next send
    del GUARD[:]


# --- Z (the Table's rulings on the review of 1ab2aa2) -----------------------------------------------------------
def test_z4_a_refusal_carries_the_systems_own_error_number_and_none_where_the_system_gave_none(tmp_path, monkeypatch):
    path = tf.write(tmp_path / "e.jsonl", tf.lines(3))
    monkeypatch.setattr(forward.ctypes, "get_last_error", lambda: 5, raising=False)   # access denied, made up
    system = Fake(refuse_open=1, refuse={1})
    f = efwd(tmp_path, path, system)
    assert f.step() == "failed" and (f.failing["error"], f.failing["status"]) == ("connect", 5)
    assert f.step() == "failed" and (f.failing["error"], f.failing["status"]) == ("write", 5)
    f.write_state()
    s = tf.state(tmp_path, "e")
    assert link.state_problem(s) is None and s["failing"]["status"] == 5
    said = link.judge(s, f.clock())[2][-1]
    assert "write (an event was refused by the Windows event log (the status is the system's error number))" in said
    assert said.endswith(", status 5")
    monkeypatch.setattr(forward.ctypes, "get_last_error", lambda: 0, raising=False)   # no reason given: none said
    g = efwd(tmp_path, path, Fake(refuse={1}), name="g")
    assert g.step() == "failed" and g.failing["status"] is None
    monkeypatch.setattr(forward.ctypes, "get_last_error", lambda: 1 / 0, raising=False)   # asking fails: none
    h = efwd(tmp_path, path, Fake(refuse={1}), name="h")
    assert h.step() == "failed" and h.failing["status"] is None


def test_z5_the_words_of_stuck_speak_of_no_name_and_no_connect_for_the_journal_and_the_event_log():
    for table in (link.EVENTLOG_ERRORS, link.JOURNAL_ERRORS):
        assert table["stuck"] == link.LOCAL_STUCK and "resolves" not in table["stuck"] and "connect" not in table["stuck"]
        assert set(table) == set(link.ERRORS)
    assert "resolves" in link.ERRORS["stuck"]   # the negative: a network send's words stay
