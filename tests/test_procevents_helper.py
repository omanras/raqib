"""M14.1b E1, E2 (ADR-0007 Amendment BU-1, BU-2): the reader in a process of its own.

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
        return {"missed": {"exe": 0, "stat": 0}, "lost": {"count": 0, "events": 0, "why": None}, "ended": None}

    def stop(self):
        self.stops += 1
        return []


def serve(lines, reader, **kw):
    out = io.StringIO()
    code = procevents.serve(io.StringIO(lines), out, reader, **kw)
    return code, [json.loads(x) for x in out.getvalue().splitlines()]


def proc(n, **kw):
    return dict({"pid": n, "ppid": 1, "exe": "/bin/true", "earlier": [], "started_ticks": 5, "began": "T%d" % n,
                 "ended": None, "code": None, "signal": None, "unread": {}}, **kw)


# --- E1: the serve protocol, with fakes ------------------------------------------------------------------------
def test_e1_ready_first_then_one_json_line_per_read_then_stop_exits_0():
    reader = FakeReader(batches=[{"processes": [proc(7)], "ends": [], "older": []}])
    code, out = serve("read 1\nread\nstop\nread 9\n", reader)
    assert code == 0 and out[0] == {"ready": None}
    assert set(out[1]) == {"processes", "ends", "older", "more", "counts", "ask"}
    assert out[1]["ask"] == 1 and out[1]["processes"] == [proc(7)] and out[1]["more"] is False
    assert out[2]["ask"] is None and out[2]["processes"] == []     # `read` with no number: "ask" is None
    assert len(out) == 3 and reader.stops == 1                         # nothing after `stop`; the reader stopped


def test_e1_the_end_of_input_stops_the_reader_and_exits_0():
    reader = FakeReader()
    code, out = serve("read 1\n", reader)
    assert code == 0 and len(out) == 2 and reader.stops == 1
    code, out = serve("", FakeReader())
    assert code == 0 and out == [{"ready": None}]


def test_e1_a_refusal_is_the_first_line_and_the_helper_exits_0_reading_nothing():
    reader = FakeReader(why=REFUSAL)
    code, out = serve("read 1\nread 2\n", reader)
    assert code == 0 and out == [{"ready": REFUSAL}] and reader.reads == 0 and reader.stops == 1


def test_e1_the_bound_holds_2000_entries_in_all_and_more_says_the_rest_comes_next():
    assert procevents.SERVE_MAX == 2000
    batch = {"processes": [proc(n) for n in range(2500)], "ends": [proc(9000 + n) for n in range(10)],
             "older": [proc(9500)]}
    reader = FakeReader(batches=[batch, {"processes": [proc(1)], "ends": [], "older": []}])
    code, out = serve("read 1\nread 2\nread 3\n", reader)
    first, second, third = out[1:]
    assert len(first["processes"]) == 2000 and first["ends"] == [] and first["older"] == [] and first["more"] is True
    assert len(second["processes"]) == 500 and len(second["ends"]) == 10 and len(second["older"]) == 1
    assert second["more"] is False
    assert [p["pid"] for p in first["processes"] + second["processes"]] == list(range(2500))   # in order, once each
    assert third["processes"] == [proc(1)] and reader.reads == 2   # a new read only when the rest was given whole
    code, out = serve("read 1\nread 2\n", FakeReader(batches=[batch]), bound=3)
    assert [len(out[1][k]) for k in ("processes", "ends", "older")] == [3, 0, 0] and out[1]["more"] is True


def test_e1_a_line_that_is_not_a_command_is_answered_with_an_error_and_the_helper_lives():
    mark = "\x1b[31mZQ-NOT-ECHOED"
    code, out = serve("hello %s\nread 1 2\nread x\n\nREAD 1\nread 4\n" % mark, FakeReader())
    assert code == 0 and [x.get("error") for x in out[1:6]] == [procevents.NOT_A_COMMAND] * 5
    assert out[6]["ask"] == 4 and "ZQ-NOT-ECHOED" not in json.dumps(out)


def test_e1_an_output_that_cannot_be_written_stops_the_reader_and_exits_1():
    class Broken(io.StringIO):
        def write(self, text):
            raise BrokenPipeError(32, "Broken pipe")
    reader = FakeReader()
    assert procevents.serve(io.StringIO("read 1\n"), Broken(), reader) == 1 and reader.stops == 1


def test_e1_main_serves_only_with_serve():
    assert procevents.main(["--other"]) == 2


# --- E2: the client, with a fake process -------------------------------------------------------------------------
class FakeProc:
    """A helper process: its output is a real pipe the test writes to; its input records the asks."""

    def __init__(self, argv=None, **kw):
        self.args, self.kw, self.pid = argv, kw, 4242
        r, self._w = os.pipe()
        self.stdout = os.fdopen(r, "rb")
        self.asked = []
        self.stdin = self
        self.closed = self.terminated = False
        self.returncode = None
        self.waits = []

    def write(self, data):
        if self.closed:
            raise ValueError("closed")
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


def answer(n, **kw):
    return dict({"processes": [], "ends": [], "older": [], "more": False, "counts": {}, "ask": n}, **kw)


def fake_helper(**kw):
    made = []

    def popen(argv, **pkw):
        made.append(FakeProc(argv, **pkw))
        return made[-1]
    started = []
    h = procevents.Helper(started=lambda p: started.append(p) or p, popen=popen, **kw)
    assert h.start() is None
    return h, made[0], started


def test_e2_the_command_is_this_interpreter_with_its_isolation():
    assert procevents.command("/x/py", isolated=True) == ["/x/py", "-I", "-m", "raqib.procevents", "--serve"]
    assert procevents.command("/x/py", isolated=False) == ["/x/py", "-m", "raqib.procevents", "--serve"]
    assert procevents.command() == [sys.executable] + (["-I"] if sys.flags.isolated else []) + [
        "-m", "raqib.procevents", "--serve"]
    assert procevents.Helper().argv == procevents.command()


def test_e2_start_goes_through_started_and_ask_takes_its_own_answer():
    h, p, started = fake_helper()
    assert started == [p] and p.args == procevents.command()
    p.say({"ready": None})
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


def test_e2_ask_never_blocks_past_its_timeout_and_a_late_line_is_not_taken_by_the_next_ask():
    h, p, _ = fake_helper()
    t0 = time.monotonic()
    assert h.ask(0.2) == (None, procevents.LATE)            # the ready line is late
    p.say({"ready": None})
    assert h.ask(0.2) == (None, procevents.LATE)            # ask 1 sent, no answer in time
    assert time.monotonic() - t0 < 1.5
    p.say(answer(1, processes=[proc(1)]))                   # ask 1's late answer
    p.say(answer(2, processes=[proc(2)]))
    got, why = h.ask(1.0)
    assert why is None and got["ask"] == 2 and got["processes"] == [proc(2)] and h.stale == 1
    assert p.asked == [b"read 1\n", b"read 2\n"]


def test_e2_a_line_that_is_not_the_helpers_is_said_so():
    h, p, _ = fake_helper()
    p.say("not json at all")
    assert h.ask(1.0) == (None, procevents.NOT_A_LINE)      # as the ready line
    p.say({"ready": None})
    assert h.ask(0.1) == (None, procevents.LATE)
    for bad in ("[1, 2]", '{"error": "x"}', '{"ask": 2, "processes": []}', json.dumps(answer(9))):
        p.say(bad)
    for _ in range(4):
        assert h.ask(1.0) == (None, procevents.NOT_A_LINE)


def test_e2_a_refusal_in_the_ready_line_is_kept_and_said():
    h, p, _ = fake_helper()
    p.say({"ready": REFUSAL})
    assert h.ask(1.0) == (None, procevents.REFUSED) and h.refused == REFUSAL
    assert h.ask(1.0) == (None, procevents.REFUSED) and p.asked == []


def test_e2_a_helper_whose_output_ends_has_ended_and_every_later_ask_says_so_at_once():
    h, p, _ = fake_helper()
    p.say({"ready": None})
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


# --- E1, E2: the real helper, a child process on Linux -------------------------------------------------------------
def _gone(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            return f.read().rsplit(b")", 1)[1].split()[0] in (b"Z", b"X")
    except OSError:
        return True


def _real():
    return subprocess.Popen(procevents.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, cwd=str(ROOT))


@pytest.mark.skipif(not LINUX, reason="the helper's reader is Linux's")
def test_e1_the_real_helper_answers_lines_and_exits_0_at_stop_and_at_the_end_of_its_input():
    for last in (b"stop\n", b""):
        child = _real()
        first = json.loads(child.stdout.readline())
        if first["ready"] is not None:
            child.stdin.close()
            assert child.wait(10) == 0
            pytest.skip("the kernel refused here: %s" % first["ready"])
        assert first == {"ready": None}
        child.stdin.write(b"read 1\nnonsense\nread 2\n" + last)
        child.stdin.flush()
        one, err, two = (json.loads(child.stdout.readline()) for _ in range(3))
        assert one["ask"] == 1 and set(one) == {"processes", "ends", "older", "more", "counts", "ask"}
        assert err == {"error": procevents.NOT_A_COMMAND} and two["ask"] == 2
        child.stdin.close()
        assert child.wait(10) == 0 and child.stdout.read() == b""


@pytest.mark.skipif(not LINUX, reason="the helper's reader is Linux's")
def test_e1_the_helper_does_not_outlive_the_process_that_started_it():
    """A watch killed with no stop (SIGKILL): its pipe to the helper ends, and so does the helper."""
    code = ("import sys, time; sys.path.insert(0, %r); from raqib import procevents; h = procevents.Helper();"
            " h.start(); print(h.proc.pid, flush=True); h.ask(5.0); print('asked', flush=True); time.sleep(60)"
            % str(ROOT))
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
        got, why = h.ask(5.0)
        if why == procevents.REFUSED:
            pytest.skip("the kernel refused here: %s" % h.refused)
        assert why is None, why
        children = []
        for n in range(20):
            child = subprocess.Popen(["true"] if n % 2 else ["sh", "-c", "exit 3"])
            child.wait()
            children.append((child.pid, child.returncode))
        heard, deadline = {}, time.monotonic() + 10
        while time.monotonic() < deadline and not all(heard.get(pid, {}).get("ended") for pid, _ in children):
            got, why = h.ask(2.0)
            assert why is None, why
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


def test_e7_the_helper_and_the_client_are_the_standard_librarys_and_ascii():
    text = (ROOT / "raqib" / "procevents.py").read_text(encoding="utf-8")
    assert text.isascii()
    assert (ROOT / "tests" / "test_procevents_helper.py").read_text(encoding="utf-8").isascii()
    for gone in ("requests", "urllib", "http.client", "socket.create_connection"):
        assert gone not in text


def test_e2_the_client_reads_its_pipe_in_a_thread_of_its_own():
    made = []

    class Thread(threading.Thread):
        def __init__(self, **kw):
            made.append(kw)
            super().__init__(**kw)
    h = procevents.Helper(popen=FakeProc, thread=Thread)
    assert h.start() is None and made[0]["daemon"] is True
    h.proc.end()
    assert h.ask(1.0) == (None, procevents.ENDED)


def test_e2_a_client_let_go_without_stop_closes_its_helpers_input():
    made = []
    h = procevents.Helper(popen=lambda argv, **kw: made.append(FakeProc(argv)) or made[-1])
    assert h.start() is None and not made[0].closed
    del h
    assert made[0].closed


@pytest.mark.skipif(not LINUX, reason="the helper's reader is Linux's")
def test_e2_a_real_client_let_go_ends_its_helper():
    h = procevents.Helper()
    assert h.start() is None
    h.ask(5.0)
    pid = h.proc.pid
    del h
    deadline = time.monotonic() + 10
    while not _gone(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert _gone(pid)
