"""M14.1b and its REDO (ADR-0007 Amendments BU-1, BU-2, BW-1, BW-4, BW-5, BW-8): the reader in a process of its own.

`python -m raqib.procevents --serve` (procevents.serve) and its client procevents.Helper: with fakes everywhere,
and as a real child process on Linux (skipped elsewhere)."""
import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import procevents  # noqa: E402

LINUX = sys.platform.startswith("linux")
REFUSAL = procevents.PREFIX + "the socket was refused (EPERM: a fake)"


class FakeReader:
    """A stand-in Reader: start() gives `why`; each read() gives the next batch."""

    def __init__(self, why=None, batches=()):
        self.why, self.batches = why, list(batches)
        self.reads = self.stops = 0

    def start(self):
        return self.why

    def read(self):
        self.reads += 1
        return self.batches.pop(0) if self.batches else {"processes": [], "ends": [], "older": []}

    def counts(self):
        return {"missed": {"exe": 0, "stat": 0}, "lost": {"count": 0, "events": 0, "why": None}, "ended": None,
                "beyond": 0}

    def stop(self):
        self.stops += 1
        return []


def serve(lines, reader, **kw):
    out = io.StringIO()
    code = procevents.serve(io.StringIO(lines), out, reader, **kw)
    return code, out.getvalue().splitlines()


def parsed(lines):
    return [json.loads(x) for x in lines]


def proc(n, exe="/bin/true", **kw):
    return dict({"pid": n, "ppid": 1, "exe": exe, "earlier": [], "started_ticks": 5, "began": "T%d" % n,
                 "ended": None, "code": None, "signal": None, "unread": {}}, **kw)


# --- E1, E8: the serve protocol, with fakes ---------------------------------------------------------------------
def test_e1_ready_first_then_one_json_line_per_read_each_of_version_1_then_stop_exits_0():
    reader = FakeReader(batches=[{"processes": [proc(7)], "ends": [], "older": []}])
    code, out = serve("read 1\nread\nstop\nread 9\n", reader)
    out = parsed(out)
    assert code == 0 and out[0] == {"ready": None, "v": 1} and all(x["v"] == procevents.VERSION == 1 for x in out)
    assert set(out[1]) == {"v", "processes", "ends", "older", "more", "counts", "ask"}
    assert out[1]["ask"] == 1 and out[1]["processes"] == [proc(7)] and out[1]["more"] is False
    assert out[2]["ask"] is None and out[2]["processes"] == []     # `read` with no number: "ask" is None
    assert len(out) == 3 and reader.stops == 1                         # nothing after `stop`; the reader stopped


def test_e1_the_end_of_input_stops_the_reader_and_exits_0():
    reader = FakeReader()
    code, out = serve("read 1\n", reader)
    assert code == 0 and len(out) == 2 and reader.stops == 1
    code, out = serve("", FakeReader())
    assert code == 0 and parsed(out) == [{"ready": None, "v": 1}]


def test_e1_a_refusal_is_the_first_line_and_the_helper_exits_0_reading_nothing():
    reader = FakeReader(why=REFUSAL)
    code, out = serve("read 1\nread 2\n", reader)
    assert code == 0 and parsed(out) == [{"ready": REFUSAL, "v": 1}] and reader.reads == 0 and reader.stops == 1


def test_e1_the_bound_holds_2000_entries_in_all_and_more_says_the_rest_comes_next():
    assert procevents.SERVE_MAX == 2000
    batch = {"processes": [proc(n) for n in range(2500)], "ends": [proc(9000 + n) for n in range(10)],
             "older": [proc(9500)]}
    reader = FakeReader(batches=[batch, {"processes": [proc(1)], "ends": [], "older": []}])
    code, out = serve("read 1\nread 2\nread 3\n", reader)
    first, second, third = parsed(out)[1:]
    assert len(first["processes"]) == 2000 and first["ends"] == [] and first["older"] == [] and first["more"] is True
    assert len(second["processes"]) == 500 and len(second["ends"]) == 10 and len(second["older"]) == 1
    assert second["more"] is False
    assert [p["pid"] for p in first["processes"] + second["processes"]] == list(range(2500))   # in order, once each
    assert third["processes"] == [proc(1)] and reader.reads == 2   # a new read only when the rest was given whole


def test_e1_bw1_2000_entries_with_long_paths_are_packed_under_the_lines_bound_in_order():
    assert procevents.LINE_MAX == 1 << 20
    batch = {"processes": [proc(n, exe="/opt/" + "p" * 3000, earlier=[{"exe": "/e/" + "q" * 900, "unread": {}}])
                           for n in range(2000)], "ends": [], "older": []}
    code, out = serve("".join("read %d\n" % n for n in range(1, 12)), FakeReader(batches=[batch]))
    answers = parsed(out[1:])
    assert all(len(line) + 1 <= procevents.LINE_MAX for line in out)
    given = [p["pid"] for a in answers for p in a["processes"]]
    assert given == list(range(2000)) and answers[0]["more"] is True
    assert [a["more"] for a in answers if a["processes"]][-1] is False
    assert all(p["exe"] == "/opt/" + "p" * 3000 for a in answers for p in a["processes"])   # none shrunk


def test_e1_bw1_an_entry_that_alone_would_pass_the_bound_gives_its_program_as_unread():
    big = proc(3, exe="/x/" + "z" * 600, earlier=[{"exe": "/y/" + "w" * 600, "unread": {}}])
    code, out = serve("read 1\nread 2\n", FakeReader(batches=[{"processes": [big, proc(4)], "ends": [],
                                                                 "older": []}]), line_max=900)
    given = [x for a in parsed(out[1:]) for x in a["processes"]]
    got = given[0]
    assert got["exe"] is None and got["unread"]["exe"] == procevents.TOO_LONG_EXE and got["pid"] == 3
    assert got["earlier"] == [{"exe": None, "unread": {"exe": procevents.TOO_LONG_EXE}}]
    assert given[1:] == [proc(4)] and all(len(x) + 1 <= 900 for x in out)


def test_e1_e8_a_line_that_is_not_a_command_is_answered_with_an_error_and_the_helper_lives():
    mark = "\x1b[31mZQ-NOT-ECHOED"
    code, out = serve("hello %s\nread 1 2\nread x\n\nREAD 1\nread \u00b2\nread 4\n" % mark, FakeReader())
    out = parsed(out)
    assert code == 0 and [x.get("error") for x in out[1:7]] == [procevents.NOT_A_COMMAND] * 6
    assert all(x["v"] == 1 for x in out) and out[7]["ask"] == 4 and "ZQ-NOT-ECHOED" not in json.dumps(out)


def test_e1_an_output_that_cannot_be_written_stops_the_reader_and_exits_1():
    class Broken(io.StringIO):
        def write(self, text):
            raise BrokenPipeError(32, "Broken pipe")
    reader = FakeReader()
    assert procevents.serve(io.StringIO("read 1\n"), Broken(), reader) == 1 and reader.stops == 1


def test_e1_main_serves_only_with_serve():
    assert procevents.main(["--other"]) == 2


# --- E5: the command ---------------------------------------------------------------------------------------------
def test_e5_the_command_is_this_interpreter_minus_p_or_i_and_a_constant_program_with_the_path_as_json():
    path = ["", "/a b", "rel/x", "/c\"';$(x)", 7]
    assert procevents.command("/x/py", isolated=False, path=path) == [
        "/x/py", "-P", "-c", procevents.SERVE_PROGRAM, json.dumps(["/a b", "/c\"';$(x)"])]
    assert procevents.command("/x/py", isolated=True, path=["/a"]) == ["/x/py", "-I", "-c", procevents.SERVE_PROGRAM,
                                                                      '["/a"]']
    assert procevents.SERVE_PROGRAM == ("import json, sys; sys.path[:] = json.loads(sys.argv[1]); from raqib import"
                                        " procevents; sys.exit(procevents.main(['--serve']))")
    got = procevents.command()
    assert got[:4] == [sys.executable, "-I" if sys.flags.isolated else "-P", "-c", procevents.SERVE_PROGRAM]
    assert json.loads(got[4]) == [p for p in sys.path if os.path.isabs(p)]


@pytest.mark.parametrize("flag", ["-I", "-P"])
def test_e5_the_program_sets_the_path_given_and_adds_no_entry(flag, tmp_path):
    paths = [str(ROOT), str(tmp_path)] + [p for p in sys.path if os.path.isabs(p) and "site-packages" not in p][:3]
    out = subprocess.run([sys.executable, flag, "-c", procevents.PATH_PROGRAM + "; print(json.dumps(sys.path))",
                          json.dumps(paths)], cwd="/", capture_output=True, timeout=60)
    assert out.returncode == 0 and json.loads(out.stdout) == paths


# --- E1, E2, E4, E8: the client, with a fake process --------------------------------------------------------------
class FakeProc:
    """A helper process: its output is a real pipe the test writes to; its input records the asks and, like a
    pipe nobody reads, takes one line and fails the test on a second (`drains` False)."""

    def __init__(self, argv=None, drains=True, **kw):
        self.args, self.kw, self.pid = argv, kw, 4242
        r, self._w = os.pipe()
        self.stdout = os.fdopen(r, "rb")
        self.asked, self.drains = [], drains
        self.stdin = self
        self.closed = self.terminated = False
        self.returncode = None
        self.waits = []

    def write(self, data):
        if self.closed:
            raise ValueError("closed")
        if not self.drains and self.asked:
            raise AssertionError("a second ask written into an input nobody reads: it would block")
        self.asked.append(data)

    def flush(self):
        pass

    def close(self):
        self.closed = True

    def say(self, value):
        os.write(self._w, (value if isinstance(value, str) else json.dumps(value)).encode() + b"\n")

    def end(self):
        os.close(self._w)

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.closed and not getattr(self, "stuck", False):
            self.returncode = 0
            return 0
        raise subprocess.TimeoutExpired("helper", timeout)

    def terminate(self):
        self.terminated = True
        self.stuck = False


READY = {"ready": None, "v": 1}


def answer(n, **kw):
    return dict({"processes": [], "ends": [], "older": [], "more": False, "counts": {}, "ask": n, "v": 1}, **kw)


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def fake_helper(drains=True, **kw):
    made = []

    def popen(argv, **pkw):
        made.append(FakeProc(argv, drains=drains, **pkw))
        return made[-1]
    started = []
    h = procevents.Helper(started=lambda p: started.append(p) or p, popen=popen, **kw)
    assert h.start() is None
    return h, made[0], started


def test_e2_start_goes_through_started_in_the_directory_root_and_does_not_wait():
    h, p, started = fake_helper()
    assert started == [p] and p.args == procevents.command() and p.kw == {"cwd": "/"}
    assert p.asked == []                                       # nothing asked before the ready line came
    p.say(READY)
    p.say(answer(1, processes=[proc(3)]))
    got, why = h.ask(1.0)
    assert why is None and got["processes"] == [proc(3)] and p.asked == [b"read 1\n"]


def test_e2_a_start_that_fails_is_a_reason_never_a_raise():
    def popen(argv, **kw):
        raise OSError(2, "No such file or directory")
    h = procevents.Helper(popen=popen)
    why = h.start()
    assert why.startswith("the helper could not be started (") and h.ask(0.1) == (None, procevents.ENDED)
    assert h.stop() == []


def test_e4_before_its_first_line_the_helper_is_starting_for_5_s_then_late():
    clock = Clock()
    h, p, _ = fake_helper(clock=clock)
    assert procevents.STARTING_SECONDS == 5.0
    assert h.ask(0.0) == (None, procevents.STARTING)
    clock.t += 4.9
    assert h.ask(0.0) == (None, procevents.STARTING)
    clock.t += 0.2
    assert h.ask(0.0) == (None, procevents.LATE) and p.asked == []
    p.say(READY)
    p.say(answer(1))
    assert h.ask(1.0)[1] is None


def test_e1_bw1_one_ask_unanswered_at_most_and_a_late_answer_is_taken_by_the_next_ask_once():
    h, p, _ = fake_helper()
    p.say(READY)
    t0 = time.monotonic()
    assert h.ask(0.2) == (None, procevents.LATE)            # ask 1 written, no answer in time
    assert h.ask(0.2) == (None, procevents.LATE)            # nothing written: ask 1 is still out
    assert time.monotonic() - t0 < 1.5 and p.asked == [b"read 1\n"] and h.outstanding == 1
    p.say(answer(1, processes=[proc(1)]))                   # ask 1's answer, late
    got, why = h.ask(1.0)
    assert why is None and got["ask"] == 1 and got["processes"] == [proc(1)] and h.outstanding is None
    p.say(answer(2, processes=[proc(2)]))
    got, why = h.ask(1.0)
    assert got["ask"] == 2 and p.asked == [b"read 1\n", b"read 2\n"]


def test_e1_bw1_an_input_that_never_drains_takes_one_ask_in_10000_and_every_ask_returns_in_time():
    h, p, _ = fake_helper(drains=False)
    p.say(READY)
    assert h.ask(0.5) == (None, procevents.LATE)            # the ready line read, ask 1 written: never answered
    t0 = time.monotonic()
    for _ in range(10000):
        assert h.ask(0.0) == (None, procevents.LATE)
    assert p.asked == [b"read 1\n"] and time.monotonic() - t0 < 20
    assert h.stop() == []


def test_e1_bw1_a_line_of_2_mib_is_not_a_line_and_the_next_line_is_read():
    h, p, _ = fake_helper()
    p.say(READY)

    def big():
        os.write(p._w, b'{"v": 1, "x": "' + b"a" * (2 << 20) + b'"}\n')
        p.say(answer(1))
    t = threading.Thread(target=big)
    t.start()
    assert h.ask(5.0) == (None, procevents.NOT_A_LINE)
    got, why = h.ask(5.0)
    t.join(5)
    assert why is None and got["ask"] == 1


def test_e1_bw1_an_endless_stream_of_lines_holds_4_lines_and_never_keeps_ask_past_its_deadline():
    h, p, _ = fake_helper()
    p.say(READY)
    stop = threading.Event()

    def stream():
        try:
            while not stop.is_set():
                os.write(p._w, json.dumps(answer(0)).encode() + b"\n")
        except OSError:
            pass
    t = threading.Thread(target=stream, daemon=True)
    t.start()
    try:
        for _ in range(50):
            t0 = time.monotonic()
            assert h.ask(0.05) == (None, procevents.NOT_A_LINE)   # an answer to no ask of its
            assert time.monotonic() - t0 < 1.0
        time.sleep(0.3)
        assert h._lines.qsize() <= procevents.HELD_LINES == 4
    finally:
        stop.set()
        assert h.stop() == []
        p.stdout.close()
        t.join(5)


@pytest.mark.parametrize("line", ["not json at all", "[1, 2]", '{"error": "x", "v": 1}', '{"ready": null}',
                                  '{"ready": null, "v": 2}', '{"ready": null, "v": true}', '{"ready": null, "v": 1,'
                                  ' "x": 1}', "[" * 100000])
def test_e8_a_ready_line_of_another_shape_or_version_is_not_a_line(line):
    h, p, _ = fake_helper()
    p.say(line)
    assert h.ask(1.0) == (None, procevents.NOT_A_LINE)


@pytest.mark.parametrize("bad", [answer("1"), answer(True), answer(1.0), answer(2), dict(answer(1), v=2),
                                 {k: v for k, v in answer(1).items() if k != "v"}, dict(answer(1), extra=1),
                                 answer(1, processes={}), answer(1, more="no"), answer(1, counts=[])])
def test_e8_an_answer_of_another_shape_number_or_version_is_not_a_line(bad):
    h, p, _ = fake_helper()
    p.say(READY)
    p.say(bad)
    assert h.ask(1.0) == (None, procevents.NOT_A_LINE)


def test_e2_a_refusal_in_the_ready_line_is_kept_and_said():
    h, p, _ = fake_helper()
    p.say({"ready": REFUSAL, "v": 1})
    assert h.ask(1.0) == (None, procevents.REFUSED) and h.refused == REFUSAL
    assert h.ask(1.0) == (None, procevents.REFUSED) and p.asked == []


def test_e2_a_helper_whose_output_ends_has_ended_and_every_later_ask_says_so_at_once():
    h, p, _ = fake_helper()
    p.say(READY)
    p.end()
    assert h.ask(1.0) == (None, procevents.ENDED) and h.ended
    t0 = time.monotonic()
    assert h.ask(5.0) == (None, procevents.ENDED) and time.monotonic() - t0 < 1.0


def test_e2_stop_closes_the_input_waits_then_ends_it_and_a_second_stop_does_nothing():
    h, p, _ = fake_helper()
    assert h.stop() == [] and p.closed and p.waits == [procevents.STOP_SECONDS] and not p.terminated
    assert h.stop() == []
    h, p, _ = fake_helper()
    p.stuck = True
    problems = h.stop()
    assert p.terminated and problems == ["the helper did not end within 2 s of its input's end: it was ended"]


def test_e2_a_client_let_go_without_stop_closes_its_helpers_input():
    made = []
    h = procevents.Helper(popen=lambda argv, **kw: made.append(FakeProc(argv)) or made[-1])
    assert h.start() is None and not made[0].closed
    del h
    assert made[0].closed


def test_e2_the_client_reads_its_pipe_in_a_thread_of_its_own():
    made = []

    class Thread(threading.Thread):
        def __init__(self, **kw):
            made.append(kw)
            super().__init__(**kw)
    h = procevents.Helper(popen=FakeProc, thread=Thread)
    assert h.start() is None and made[0]["daemon"] is True and made[0]["name"] == "raqib-procevents-helper"
    h.proc.end()
    assert h.ask(1.0) == (None, procevents.ENDED)


# --- the real helper, a child process on Linux ---------------------------------------------------------------------
def _gone(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            return f.read().rsplit(b")", 1)[1].split()[0] in (b"Z", b"X")
    except OSError:
        return True


def _answered(h, seconds=10.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        got, why = h.ask(1.0)
        if why == procevents.REFUSED:
            pytest.skip("the kernel refused here: %s" % h.refused)
        if why is None:
            return got
    raise AssertionError("the real helper did not answer within %g s (%s)" % (seconds, why))


@pytest.mark.skipif(not LINUX, reason="the helper's reader is Linux's")
def test_e1_the_real_helper_answers_lines_and_exits_0_at_stop_and_at_the_end_of_its_input():
    for last in (b"stop\n", b""):
        child = subprocess.Popen(procevents.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, cwd="/")
        first = json.loads(child.stdout.readline())
        if first["ready"] is not None:
            child.stdin.close()
            assert child.wait(10) == 0
            pytest.skip("the kernel refused here: %s" % first["ready"])
        assert first == READY
        child.stdin.write(b"read 1\nnonsense\nread 2\n" + last)
        child.stdin.flush()
        one, err, two = (json.loads(child.stdout.readline()) for _ in range(3))
        assert one["ask"] == 1 and set(one) == set(procevents.ANSWER_KEYS)
        assert err == {"error": procevents.NOT_A_COMMAND, "v": 1} and two["ask"] == 2
        child.stdin.close()
        assert child.wait(10) == 0 and child.stdout.read() == b""


@pytest.mark.skipif(not LINUX, reason="the helper's reader is Linux's")
def test_e5_a_real_helper_started_beside_a_raqib_py_and_a_json_folder_loads_neither(tmp_path, monkeypatch):
    marks = tmp_path / "marks"
    (tmp_path / "raqib.py").write_text("open(%r, 'w').write('raqib.py')\n" % str(marks), encoding="ascii")
    (tmp_path / "json").mkdir()
    (tmp_path / "json" / "__init__.py").write_text("open(%r, 'w').write('json')\n" % str(marks), encoding="ascii")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "path", ["", str(tmp_path)[1:]] + sys.path)   # relative entries: never given
    h = procevents.Helper()
    assert str(tmp_path) not in h.argv[4] and h.start() is None
    try:
        got = _answered(h)
        assert got["v"] == 1 and not marks.exists()
    finally:
        assert h.stop() == []


@pytest.mark.skipif(not LINUX, reason="the helper's reader is Linux's")
def test_e1_the_helper_does_not_outlive_the_process_that_started_it():
    """A watch killed with no stop (SIGKILL): its pipe to the helper ends, and so does the helper."""
    code = ("import sys, time; sys.path.insert(0, %r); from raqib import procevents; h = procevents.Helper();"
            " h.start(); print(h.proc.pid, flush=True); t = time.monotonic() + 10\n"
            "while h.ask(1.0)[1] is not None and time.monotonic() < t: pass\n"
            "print('asked', flush=True); time.sleep(60)" % str(ROOT))
    parent = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        pid = int(parent.stdout.readline())
        assert parent.stdout.readline().strip() == b"asked" and not _gone(pid)
        parent.send_signal(signal.SIGKILL)
        parent.wait(10)
        deadline = time.monotonic() + 10
        while not _gone(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _gone(pid)
    finally:
        if parent.poll() is None:
            parent.kill()


@pytest.mark.skipif(not LINUX, reason="the helper's reader is Linux's")
def test_e2_the_real_helper_hears_every_child_its_fork_end_code_and_parent_and_a_missed_program_is_explained():
    """In this sandbox (2 CPUs, other work) even the reader's own process may read a program late: not every
    program is required; every child is heard, and a program not read says why (BT-6, the Table's note)."""
    h = procevents.Helper()
    assert h.start() is None
    try:
        got = _answered(h)
        children = []
        for n in range(20):
            child = subprocess.Popen(["true"] if n % 2 else ["sh", "-c", "exit 3"])
            child.wait()
            children.append((child.pid, child.returncode))
        heard, deadline = {}, time.monotonic() + 10
        while time.monotonic() < deadline and not all(heard.get(pid, {}).get("ended") for pid, _ in children):
            got, why = h.ask(2.0)
            if why is not None:
                continue
            for rec in got["processes"]:
                heard[rec["pid"]] = rec
            for end in got["ends"]:
                if end["pid"] in heard:
                    heard[end["pid"]].update(ended=end["ended"], code=end["code"])
        missed = 0
        for pid, code in children:
            rec = heard[pid]
            assert rec["began"] and rec["ended"] and rec["code"] == code and rec["ppid"] == os.getpid(), rec
            if rec["exe"] is None:
                missed += 1
                assert rec["unread"].get("exe"), rec
        assert got["counts"]["lost"]["count"] == 0 and got["counts"]["refused"] is None
        assert got["counts"]["missed"]["exe"] >= missed
    finally:
        assert h.stop() == []
    assert h.proc.returncode == 0


@pytest.mark.skipif(not LINUX, reason="the helper's reader is Linux's")
def test_e2_a_real_client_let_go_ends_its_helper():
    h = procevents.Helper()
    assert h.start() is None
    _answered(h)
    pid = h.proc.pid
    del h
    deadline = time.monotonic() + 10
    while not _gone(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert _gone(pid)


def test_e9_the_helper_and_the_client_are_the_standard_librarys_and_ascii():
    text = (ROOT / "raqib" / "procevents.py").read_text(encoding="utf-8")
    assert text.isascii()
    assert (ROOT / "tests" / "test_procevents_helper.py").read_text(encoding="utf-8").isascii()
    for gone in ("requests", "urllib", "http.client", "socket.create_connection"):
        assert gone not in text
