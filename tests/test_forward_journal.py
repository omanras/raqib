"""M10.3c-a (ADR-0011 Amendment W): `raqib forward --to journal:`, the system's journal as a destination of the
forwarder. No test here touches a real journal or /run: the forwarder's journal is a stand-in (StandIn below), a
datagram socket bound in a short folder of the test's own that parses the native protocol back, receives the
descriptors of memory files (recvmsg with ancillary data) and the sender's pid (SO_PASSCRED, as the journal's
trusted _PID); an autouse fixture points the module's JOURNAL at a path in such a folder where nothing is, so a
Forwarder built with no `journal` reaches no journal either. Every clock and wait of the forwarder is injected
(no sleep); a test that needs AF_UNIX datagrams or a memory file skips, with the reason, where the system has
none (Windows runs this file too)."""
import array
import importlib.util
import io
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from raqib import cli, forward, link

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("forward_tests_for_journal", ROOT / "tests" / "test_forward.py")
tf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tf)

PRIORITY_OF = {"high": 2, "medium": 4, "low": 5, "hole": 4, "none": 6, "info": 6}   # W-2, J-6, in the ruling's words
READ_MAX = 1024 * 1024    # the stand-in reads a datagram of at most this many bytes (more is a problem it says)
JOIN_S = 30.0             # the stand-in's thread is joined within this (it ends at the test's own datagram)


def _no_dgram():
    if not hasattr(socket, "AF_UNIX"):
        return "this system has no AF_UNIX sockets"
    try:
        socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM).close()
    except OSError as exc:
        return "this system has no AF_UNIX datagram sockets (%s)" % type(exc).__name__
    if not hasattr(socket.socket, "recvmsg"):
        return "this system has no recvmsg"
    return None


NO_DGRAM = _no_dgram()
NO_MEMFD = NO_DGRAM or (None if hasattr(os, "memfd_create") and hasattr(socket, "SCM_RIGHTS") else
                        "this system has no memory file (os.memfd_create) or no SCM_RIGHTS")
needs_dgram = pytest.mark.skipif(NO_DGRAM is not None, reason=NO_DGRAM or "")
needs_memfd = pytest.mark.skipif(NO_MEMFD is not None, reason=NO_MEMFD or "")


def short_folder():
    """A folder whose socket path fits AF_UNIX's limit (about 100 bytes), whatever the test's tmp_path is."""
    return tempfile.mkdtemp(prefix="rqj-")


def parse(data):
    """The native protocol read back: (fields {key: value}, keys in order, problem or None)."""
    fields, keys, i = {}, [], 0
    while i < len(data):
        nl = data.find(b"\n", i)
        eq = data.find(b"=", i)
        if nl < 0:
            return fields, keys, "a field with no newline at its end"
        if 0 <= eq < nl:
            key, value, i = data[i:eq], data[eq + 1:nl], nl + 1
        else:
            key, size = data[i:nl], int.from_bytes(data[nl + 1:nl + 9], "little")
            value = data[nl + 9:nl + 9 + size]
            if len(data) < nl + 9 or len(value) != size or data[nl + 9 + size:nl + 10 + size] != b"\n":
                return fields, keys, "a field by length that is cut or has no newline after it"
            i = nl + 10 + size
        keys.append(key)
        fields[key] = value
    return fields, keys, None


class StandIn:
    """A stand-in journal: a datagram socket bound at `path`, read by a thread of its own. Each datagram is one
    entry, parsed by the native protocol; one that carries a descriptor (SCM_RIGHTS) is a memory file, read whole
    from its start and closed, its seals kept. Each entry is kept as {"fields", "keys", "how" (datagram or memfd),
    "length", "seals", "pid" (SO_PASSCRED where the system has it)}; what does not parse is a problem. A datagram
    with no bytes and no descriptor is the test's own Stop (the forwarder never sends one): what came before it
    is read first."""

    def __init__(self, path):
        self.path, self.entries, self.problems = path, [], []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(path)
        if hasattr(socket, "SO_PASSCRED"):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.thread = threading.Thread(target=self.serve, name="stand-in-journal", daemon=True)
        self.thread.start()

    def serve(self):
        room = socket.CMSG_SPACE(16 * 4) + socket.CMSG_SPACE(3 * 4)
        try:
            while True:
                data, ancillary, flags, _ = self.sock.recvmsg(READ_MAX, room)
                fds, pid = [], None
                for level, kind, payload in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        got = array.array("i")
                        got.frombytes(payload[:len(payload) - len(payload) % got.itemsize])
                        fds += list(got)
                    elif level == socket.SOL_SOCKET and kind == getattr(socket, "SCM_CREDENTIALS", None):
                        pid = struct.unpack("3i", payload[:12])[0]
                if not data and not fds:
                    return
                if flags & getattr(socket, "MSG_TRUNC", 0):
                    self.problems.append("a datagram longer than the stand-in reads")
                how, seals = "datagram", None
                if fds:
                    how = "memfd"
                    if data or len(fds) != 1:
                        self.problems.append("a memory file with bytes or other descriptors beside it")
                    for fd in fds:
                        try:
                            seals = forward.fcntl.fcntl(fd, 1034) if forward.fcntl else None   # F_GET_SEALS
                            os.lseek(fd, 0, os.SEEK_SET)
                            parts = []
                            while True:
                                part = os.read(fd, 1 << 20)
                                if not part:
                                    break
                                parts.append(part)
                            data = b"".join(parts)
                        finally:
                            os.close(fd)
                fields, keys, problem = parse(data)
                if problem:
                    self.problems.append(problem)
                self.entries.append({"fields": fields, "keys": keys, "how": how, "length": len(data),
                                     "seals": seals, "pid": pid})
        except Exception as exc:   # the stand-in's own failure is the test's fact
            self.problems.append("the stand-in failed: %s: %s" % (type(exc).__name__, exc))

    def stop(self):
        """The test's Stop: every datagram sent before it is read, then the thread ends and the socket closes."""
        if self.thread.is_alive():
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                s.sendto(b"", self.path)
            except OSError:
                pass
            finally:
                s.close()
            self.thread.join(JOIN_S)
        self.sock.close()
        return self

    def messages(self):
        return [e["fields"].get(b"MESSAGE") for e in self.entries]


@pytest.fixture(autouse=True)
def no_real_journal_and_no_thread_left(monkeypatch):
    """No test here reaches a real journal: JOURNAL is a path in a folder of the test's own where nothing is.
    And, as tests/test_forward.py holds (N-7), every run is on a thread of its own and no thread of the
    forwarder outlives its test."""
    folder = short_folder()
    monkeypatch.setattr(forward, "JOURNAL", os.path.join(folder, "none"))
    before = {t for t in threading.enumerate() if t.name.startswith(tf.THREADS)}
    monkeypatch.setattr(forward.Forwarder, "run", tf.bounded_run)
    yield
    shutil.rmtree(folder, ignore_errors=True)
    assert not tf.left_behind(before)


@pytest.fixture
def journals():
    """StandIn(s) in short folders of the test's own, each stopped and removed after the test."""
    made = []

    def make(path=None):
        folder = None
        if path is None:
            folder = short_folder()
            path = os.path.join(folder, "j")
        j = StandIn(path)
        made.append((j, folder))
        return j
    yield make
    for j, folder in made:
        j.stop()
        if folder:
            shutil.rmtree(folder, ignore_errors=True)


def jfwd(tmp_path, path, journal, clock=None, **kw):
    kw.setdefault("name", "j")
    kw.setdefault("platform", "linux")
    clock = clock or tf.Clock()
    kw.setdefault("mono", clock)
    return forward.Forwarder(kw.pop("name"), path, "journal:", home=str(tmp_path / "home"), out=io.StringIO(),
                             clock=clock, wait=clock.wait, journal=journal, **kw)


def obj_of(raw):
    return forward.classify(raw)


def expected_fields(raw, obj):
    """What W-2 says one entry holds, by the ruling's words and not by the forwarder's own code."""
    want = {b"MESSAGE": raw[:-1], b"SYSLOG_IDENTIFIER": b"raqib", b"SYSLOG_FACILITY": b"13"}
    obj = obj if isinstance(obj, dict) else {}
    sev = obj.get("severity")
    want[b"PRIORITY"] = b"%d" % PRIORITY_OF.get(sev, 4) if isinstance(sev, str) else b"4"
    watch = obj.get("watch") if isinstance(obj.get("watch"), dict) else {}
    for key, value in ((b"RAQIB_ID", obj.get("id")), (b"RAQIB_KIND", obj.get("kind")),
                       (b"RAQIB_HOST", watch.get("host")), (b"RAQIB_TIME", obj.get("time"))):
        if isinstance(value, str) and len(value) <= 256 and not any(ord(c) < 32 or 127 <= ord(c) <= 159
                                                                    for c in value):
            try:
                want[key] = value.encode("utf-8")
            except UnicodeEncodeError:   # a lone surrogate is no text the journal can hold: left out
                pass
    return want


def limit_of(folder):
    """The largest datagram a socket of this system's own kind (the forwarder's) can send to a stand-in's: found
    by trying (EMSGSIZE above it), never a constant. Each one taken is read at once (nothing waits in a queue)."""
    sink_path = os.path.join(folder, "probe")
    sink = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sink.bind(sink_path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.settimeout(10)
        sink.settimeout(10)
        low, high = 1, 64 * 1024 * 1024
        while low < high:
            mid = (low + high + 1) // 2
            try:
                s.sendto(b"x" * mid, sink_path)
                sink.recv(mid + 1)
                low = mid
            except OSError as exc:
                if exc.errno != forward.errno.EMSGSIZE:
                    raise
                high = mid - 1
        return low
    finally:
        s.close()
        sink.close()
        os.remove(sink_path)


# --- E1 (W-1, W-6): the destination, what it refuses, the state ----------------------------------------------
def test_e1_journal_colon_is_the_whole_destination_and_anything_after_the_colon_is_exit_2(tmp_path, capsys,
                                                                                        monkeypatch):
    assert forward.destination("journal:") == ({"scheme": "journal"}, None)
    assert forward.destination("JOURNAL:")[0] == {"scheme": "journal"}
    for url in ("journal:x", "journal://", "journal:/run/systemd/journal/socket", "journal: ", "journal://h:1/"):
        with pytest.raises(forward.UsageError, match="nothing follows the colon"):
            forward.destination(url)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    path = tf.write(tmp_path / "e.jsonl", tf.lines(2))
    capsys.readouterr()
    assert cli.main(["forward", path, "--to", "journal:x", "--name", "j", "--once"], out=io.StringIO()) == 2
    assert "nothing follows the colon" in capsys.readouterr().err
    assert link.where({"scheme": "journal"}) == "the journal" and "journal" in link.SCHEMES
    assert link.DELIVERY_OF["journal"] == "sent" and forward.JOURNAL_SCHEME == "journal"


def test_e1_with_journal_a_token_ca_plain_shape_and_framing_are_exit_2_each_with_its_reason(tmp_path, capsys,
                                                                                           monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    path = tf.write(tmp_path / "e.jsonl", tf.lines(2))
    token = tf.secret(tmp_path / "token.txt")
    ca = tf.write(tmp_path / "ca.pem", [b"made-up\n"])
    base = ["forward", path, "--to", "journal:", "--name", "j", "--once"]
    for more, reason in ((["--token-file", token], "the journal takes no token"),
                         (["--ca", ca], "journal: takes no --ca"),
                         (["--plain"], "journal: takes no --plain"),
                         (["--shape", "hec"], "--shape hec is HTTP's"),
                         (["--framing", "newline"], "an entry of the journal is never framed"),
                         (["--framing", "octet"], "an entry of the journal is never framed"),
                         (["--facility", "24"], "a whole number from 0 to 23"),
                         (["--facility", "x"], "a whole number from 0 to 23")):
        capsys.readouterr()
        assert cli.main(base + more, out=io.StringIO()) == 2, more
        err = capsys.readouterr().err
        assert reason in err, (more, err)
        assert tf.TOKEN not in err
    assert not os.path.exists(forward.state_path("j", str(tmp_path / "home")))   # refused before anything


def test_e1_the_state_holds_journal_sent_and_facility_and_link_status_and_where_read_it(tmp_path):
    home = str(tmp_path / "home")
    path = tf.write(tmp_path / "e.jsonl", [])
    clock = tf.Clock()
    f = jfwd(tmp_path, path, forward.JOURNAL, clock=clock)
    assert f.facility == 13 and f.framing is None and f.delivery == "sent" and not f.plain
    f.write_state()
    s = tf.state(tmp_path, "j")
    assert s["destination"] == {"scheme": "journal"} and s["delivery"] == "sent" and s["facility"] == 13
    assert "framing" not in s and s["plain"] is False and s["shape"] == "raqib"
    assert link.state_problem(s) is None
    g = jfwd(tmp_path, path, forward.JOURNAL, clock=clock, name="k", facility="3")
    g.write_state()
    assert tf.state(tmp_path, "k")["facility"] == 3
    rows = link.read(home, clock.t)
    assert [(r["name"], r["code"], r["word"], r["to"]) for r in rows] == [("j", 0, "OK", "the journal"),
                                                                         ("k", 0, "OK", "the journal")]
    assert rows[0]["lines"][0] == "to the journal (shape raqib, delivery sent, facility 13)"   # X-3: no framing
    assert link.errors_of("journal") is link.JOURNAL_ERRORS and link.errors_of("https") is link.ERRORS
    assert link.errors_of("syslog+tcp") is link.SYSLOG_ERRORS and set(link.JOURNAL_ERRORS) == set(link.ERRORS)
    failing = dict(json.loads(json.dumps(s)), failing={"since": s["written"], "tries": 2, "error": "late",
                                                       "status": None})
    said = link.judge(failing, clock.t)[2][-1]
    assert "late (the entries were not handed to the journal within the bound)" in said and "answer" not in said
    for word in ("connect", "write"):   # the journal's own words: no collector, no connection
        assert "collector" not in link.JOURNAL_ERRORS[word] and "journal" in link.JOURNAL_ERRORS[word]
    out = io.StringIO()
    assert forward.status("j", home=home, out=out, clock=clock) == 0 and "to the journal" in out.getvalue()
    for change in (lambda d: d["destination"].update(host="127.0.0.1"), lambda d: d["destination"].update(port=1),
                   lambda d: d.update(framing=None), lambda d: d.pop("facility"), lambda d: d.update(facility=24),
                   lambda d: d.update(delivery="written"), lambda d: d.update(plain=True),
                   lambda d: d.update(shape="hec")):
        bad = json.loads(json.dumps(s))
        change(bad)
        assert link.state_problem(bad), bad
        assert link.judge(bad, clock.t)[:2] == (3, "UNREADABLE")
    h = jfwd(tmp_path, path, forward.JOURNAL, clock=clock, facility="4")
    with pytest.raises(forward.UsageError, match="another facility is another name"):
        h.resume()


# --- E2 (W-2): one entry a line, by the native protocol -------------------------------------------------------
def test_e2_journal_field_is_key_value_or_key_its_length_little_endian_and_the_value():
    assert forward.journal_field(b"KEY", b"value") == b"KEY=value\n"
    assert forward.journal_field(b"KEY", b"a\nb") == b"KEY\n" + b"\x03\x00\x00\x00\x00\x00\x00\x00" + b"a\nb\n"
    fields, keys, problem = parse(forward.journal_field(b"A", b"1\n2") + forward.journal_field(b"B", b"x=y"))
    assert problem is None and keys == [b"A", b"B"] and fields == {b"A": b"1\n2", b"B": b"x=y"}


def test_e2_no_event_makes_building_an_entry_raise_and_message_is_always_the_line():
    base = obj_of(tf.lines(1)[0])
    made = [dict(base, kind="k" * 257), dict(base, kind="k" * 256), dict(base, kind="a\nb"), dict(base, id="\ud800"),
            dict(base, time=5), dict(base, watch="w"), dict(base, severity=["high"]), dict(base, kind=None),
            dict(base, id="\x85"), dict(base, watch={"host": "h\tx"})]
    for raw in tf.odd_rows():
        made.append(obj_of(raw))
    for obj in made + [tf.Raising(base), None, [], "x"]:
        raw = (json.dumps(dict(obj) if isinstance(obj, dict) else {"v": obj}, separators=(",", ":")) +
               "\n").encode("ascii")
        entry = forward.journal_entry(raw, obj)
        fields, _, problem = parse(entry)
        assert problem is None and fields[b"MESSAGE"] == raw[:-1]
        if isinstance(obj, tf.Raising):
            assert fields == {b"MESSAGE": raw[:-1], b"PRIORITY": b"4", b"SYSLOG_IDENTIFIER": b"raqib",
                              b"SYSLOG_FACILITY": b"13"}
        else:
            assert fields == expected_fields(raw, obj), obj
    assert b"RAQIB_KIND" not in parse(forward.journal_entry(b"{}\n", made[0]))[0]
    assert parse(forward.journal_entry(b"{}\n", made[1]))[0][b"RAQIB_KIND"] == b"k" * 256
    assert parse(forward.journal_entry(b"{}\n", base, 3))[0][b"SYSLOG_FACILITY"] == b"3"


@needs_dgram
def test_e2_every_line_is_one_entry_its_message_the_line_byte_for_byte_in_order(tmp_path, journals):
    rows = tf.severities() + tf.odd_rows() + tf.lines(40)
    path = tf.write(tmp_path / "e.jsonl", rows + [b"not json\n"])
    j = journals()
    f = jfwd(tmp_path, path, j.path)
    assert f.run(once=True) == 0 and f.offset == os.path.getsize(path) and f.skipped == 1
    j.stop()
    assert j.problems == [] and j.messages() == [r[:-1] for r in rows]
    assert [e["fields"] for e in j.entries] == [expected_fields(r, obj_of(r)) for r in rows]
    assert [(obj_of(r)["severity"], e["fields"][b"PRIORITY"]) for r, e in zip(rows, j.entries[:6])] == [
        ("high", b"2"), ("medium", b"4"), ("low", b"5"), ("hole", b"4"), ("info", b"6"), ("info", b"6")]
    assert all(e["how"] == "datagram" and e["keys"][0] == b"MESSAGE" for e in j.entries)
    if j.entries[0]["pid"] is not None:   # the sender as the journal's trusted _PID would say it
        assert {e["pid"] for e in j.entries} == {os.getpid()}
    s = tf.state(tmp_path, "j")
    assert s["delivery"] == "sent" and s["sent"] == len(rows) and s["failing"] is None and s["facility"] == 13


# --- E3 (W-3): an entry too long for a datagram is a sealed memory file ---------------------------------------
@needs_memfd
def test_e3_a_line_of_300_kib_is_handed_whole_as_a_sealed_memory_file_by_the_stand_ins_own_limit(tmp_path,
                                                                                                journals):
    j = journals()
    limit = limit_of(os.path.dirname(j.path))
    big = tf.lines(1, 2, size=300 * 1024)[0]
    first = tf.lines(1)[0]
    fits = len(forward.journal_entry(first, obj_of(first)))
    under = tf.lines(1, 3, size=max(0, min(limit, 400 * 1024) - fits - 64))[0]   # an entry just under the limit
    rows = [first, big, under]
    path = tf.write(tmp_path / "e.jsonl", rows)
    f = jfwd(tmp_path, path, j.path)
    assert f.run(once=True) == 0 and f.refused == 0 and f.offset == os.path.getsize(path)
    j.stop()
    assert j.problems == [] and j.messages() == [r[:-1] for r in rows]
    for e, raw in zip(j.entries, rows):
        entry = forward.journal_entry(raw, obj_of(raw))
        assert e["length"] == len(entry) and e["fields"] == expected_fields(raw, obj_of(raw))
        assert e["how"] == ("memfd" if len(entry) > limit else "datagram"), (len(entry), limit)
        if e["how"] == "memfd":
            assert e["seals"] is None or e["seals"] & 15 == 15   # seal, shrink, grow, write
    assert len(forward.journal_entry(big, obj_of(big))) > limit or limit >= 300 * 1024


@needs_memfd
@pytest.mark.parametrize("how", ["no memory file", "the seal fails", "the send fails"])
def test_e3_with_no_memory_file_or_a_failed_one_it_is_a_failed_write_never_a_cut_never_a_pass(tmp_path, journals,
                                                                                               monkeypatch, how):
    j = journals()
    limit = limit_of(os.path.dirname(j.path))
    big = tf.lines(1, 2, size=300 * 1024)[0]
    if len(forward.journal_entry(big, obj_of(big))) <= limit:
        pytest.skip("this system takes a datagram of %d bytes: the entry of 300 KiB is one" % limit)
    if how == "no memory file":
        monkeypatch.delattr(os, "memfd_create")
    elif how == "the seal fails":
        class NoSeal:
            @staticmethod
            def fcntl(*a):
                raise OSError(22, "made-up: no seal")
        monkeypatch.setattr(forward, "fcntl", NoSeal)
    else:
        real = forward.array.array   # forward's own reference only: a descriptor no process has
        monkeypatch.setattr(forward, "array", type("NoFd", (), {"array": staticmethod(lambda *a: real("i", [-1]))}))
    path = tf.write(tmp_path / "e.jsonl", [tf.lines(1)[0], big])
    f = jfwd(tmp_path, path, j.path)
    assert f.run(once=True) == 1
    j.stop()
    s = tf.state(tmp_path, "j")
    assert s["failing"]["error"] == "write" and s["sent"] == 0 and s["cursor"]["offset"] == 0 and f.refused == 0
    assert all(m == tf.lines(1)[0][:-1] for m in j.messages())   # the first line (the batch sent again); no cut


# --- E4 (W-4): sent, and paced ----------------------------------------------------------------------------------
@needs_dgram
def test_e4_1000_lines_ask_the_injected_wait_for_at_least_four_seconds_at_most_250_lines_a_second(tmp_path,
                                                                                                  journals):
    assert forward.JOURNAL_PACE == 250
    rows = tf.lines(1000)
    path = tf.write(tmp_path / "e.jsonl", rows)
    j = journals()
    clock = tf.Clock()
    f = jfwd(tmp_path, path, j.path, clock=clock)
    assert f.run(once=True) == 0 and f.sent == 1000
    j.stop()
    assert j.problems == [] and j.messages() == [r[:-1] for r in rows]
    assert len(clock.waits) == 10 and sum(clock.waits) >= 1000 / 250.0 - 1e-6
    assert all(0 < w <= 100 / 250.0 + 1e-6 for w in clock.waits), clock.waits


@needs_dgram
def test_e4_stop_during_the_pace_ends_the_wait_at_once_and_the_batch_sent_stays_passed(tmp_path, journals):
    rows = tf.lines(300)
    path = tf.write(tmp_path / "e.jsonl", rows)
    j = journals()
    clock = tf.Clock()
    f = jfwd(tmp_path, path, j.path, clock=clock)
    clock.then = lambda c: f.stop() or True   # Stop comes during the first wait
    assert f.run(once=True) == 1
    j.stop()
    assert len(clock.waits) == 1 and f.offset == sum(len(r) for r in rows[:100])
    assert j.messages() == [r[:-1] for r in rows[:100]]
    s = tf.state(tmp_path, "j")
    assert s["sent"] == 100 and s["cursor"]["offset"] == f.offset and s["failing"] is None


# --- E5 (W-5): no journal is a collector that is down; not Linux is a usage error -----------------------------
@needs_dgram
def test_e5_no_socket_or_a_path_that_is_no_socket_is_failing_connect_and_when_it_appears_no_line_is_lost(
        tmp_path, journals):
    folder = short_folder()
    try:
        where = os.path.join(folder, "j")
        rows = tf.lines(30)
        path = tf.write(tmp_path / "e.jsonl", rows)
        for make in (lambda: None, lambda: open(where, "wb").close()):   # nothing there; a file, no socket
            make()
            f = jfwd(tmp_path, path, where)
            assert f.run(once=True) == 1
            s = tf.state(tmp_path, "j")
            assert s["failing"]["error"] == "connect" and s["sent"] == 0 and s["cursor"]["offset"] == 0
            assert "connect" in f.out.getvalue()
        os.remove(where)
        clock = tf.Clock()
        g = jfwd(tmp_path, path, where, clock=clock)
        box = {}

        def then(c):
            if len(c.waits) == 2:   # J-10: tried again; the journal's socket appears during the second wait
                box["j"] = journals(where)
            return g.offset == os.path.getsize(path)   # Stop once every line is passed
        clock.then = then
        assert g.run() == 0
        assert [round(w) for w in clock.waits[:2]] == [1, 2]
        box["j"].stop()
        assert box["j"].messages() == [r[:-1] for r in rows] and box["j"].problems == []
        s = tf.state(tmp_path, "j")
        assert s["failing"] is None and s["sent"] == 30 and s["behind"] == 0
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_e5_on_a_system_that_is_not_linux_journal_is_exit_2_saying_so(tmp_path, capsys, monkeypatch):
    path = tf.write(tmp_path / "e.jsonl", tf.lines(2))
    for platform in ("win32", "darwin", "freebsd14"):
        with pytest.raises(forward.UsageError, match="journal: is Linux's"):
            jfwd(tmp_path, path, forward.JOURNAL, platform=platform)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    real = forward.Forwarder
    monkeypatch.setattr(forward, "Forwarder", lambda *a, **k: real(*a, platform="win32", **k))
    capsys.readouterr()
    assert cli.main(["forward", path, "--to", "journal:", "--name", "j", "--once"], out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert "journal: is Linux's" in err and "win32" in err


# --- E8 (W-0, W-4, W-7): what the documents say ----------------------------------------------------------------
def test_e8_the_threat_model_forward_md_and_the_guide_say_the_journal():
    threat = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    spec = (ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8")
    flat = " ".join(threat.split())
    assert "`raqib watch` and the window write under ~/.raqib and nowhere else" in flat
    assert "`raqib forward --to journal:` hands the events to the system's journal because a person ran it" in flat
    assert "whoever reads the journal" in flat
    # X-7: said whole - any user's process can write them, and only the pid tells the forwarder from an agent
    assert "Any local process of any user - the watched agent is one - can write entries that say raqib" in flat
    assert "differs from the forwarder only in `_PID`" in flat and "is a lead, not a proof" in flat
    assert "a watched agent in the forwarder's own session may use it up" in flat
    assert "may drop entries over its own rate limit" in flat and "unseen by the forwarder" in flat
    assert "M10." not in threat
    flat = " ".join(spec.split())
    for text in ("--to journal:", "MESSAGE", "PRIORITY", "SYSLOG_IDENTIFIER", "SYSLOG_FACILITY", "RAQIB_ID",
                 "RAQIB_KIND", "RAQIB_HOST", "RAQIB_TIME", "sealed memory file", "at most 250 lines a second",
                 "`sent`", "Suppressed", "No journal", "{\"scheme\": \"journal\"}"):
        assert text in flat, text
    assert "(`journal:`, Linux only" in guide and "at most 250 lines a second" in " ".join(guide.split())


# --- E9: ASCII, and no real journal -----------------------------------------------------------------------------
def test_e9_the_new_code_is_ascii_and_the_journal_of_every_test_here_is_a_folder_of_its_own():
    for rel in ("raqib/forward.py", "raqib/link.py", "tests/test_forward_journal.py", "tools/rig/forward_run.py",
                "tools/rig/check.py"):
        (ROOT / rel).read_bytes().decode("ascii")
    assert forward.JOURNAL.startswith(tempfile.gettempdir()) or "rqj-" in forward.JOURNAL   # the autouse fixture's
    assert sys.modules["raqib.forward"] is forward


# --- X (the Table's rulings on the review of a3bb1bc) -----------------------------------------------------------
@needs_dgram
def test_x4_an_entry_the_journal_would_not_take_halves_the_batch_so_its_neighbours_are_not_handed_again(
        tmp_path, journals, monkeypatch):
    j = journals()
    limit = limit_of(os.path.dirname(j.path))
    big = tf.lines(1, 3, size=300 * 1024)[0]
    if len(forward.journal_entry(big, obj_of(big))) <= limit:
        pytest.skip("this system takes a datagram of %d bytes: the entry of 300 KiB is one" % limit)
    monkeypatch.delattr(os, "memfd_create")   # the long entry cannot be handed: `write`, at every try
    first = tf.lines(2)
    path = tf.write(tmp_path / "e.jsonl", first + [big])
    f = jfwd(tmp_path, path, j.path)
    assert f.step() == "failed" and f.failing["error"] == "write" and f.size == 1   # three lines: halved to one
    for _ in range(8):   # the two before it pass, one by one or by two as the batch grows and is halved again
        if f.sent == 2:
            break
        f.step()
    assert f.sent == 2
    for _ in range(4):
        assert f.step() == "failed" and f.failing["error"] == "write"   # the long one, alone, at every try
    j.stop()
    got = j.messages()
    # its neighbours were handed a few times while the batch was halved, then never again (4 tries more)
    assert 2 <= got.count(first[0][:-1]) <= 3 and 2 <= got.count(first[1][:-1]) <= 3
    assert len(got) == got.count(first[0][:-1]) + got.count(first[1][:-1])   # and no part of the long one
    assert f.sent == 2 and f.refused == 0                                             # and nothing passed by
