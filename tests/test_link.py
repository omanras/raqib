"""raqib/link.py: the forwarder's state read and judged with no network (ADR-0011 Amendment R-1, R-4).

Every bound has a positive and a negative: a state read and one that is not, 64 names and 65, 1 MiB and more.
No sleeps; no wall clock (every `now` is given); only loopback and documentation addresses.
"""
from __future__ import annotations

import ast
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from raqib import forward, link

ROOT = Path(__file__).resolve().parent.parent
NOW = 1_800_000_000.0

MOVED_VALUES = ("SCHEMA", "KEYS", "LATER", "SYSLOG_KEYS", "NAME", "SYSLOG", "DIR_NAME", "ERRORS", "SYSLOG_ERRORS",
                "STATUS_RULE", "SHAPES", "SCHEMES", "DELIVERY", "DELIVERIES", "DELIVERY_OF", "FACILITIES",
                "FRAMINGS", "HEAD_MAX", "SHA")
MOVED_FUNCTIONS = ("forward_dir", "state_path", "seconds_of", "where", "state_problem", "_state_problem", "_count",
                   "_instant", "judge")
ROW_KEYS = {"name", "path", "code", "word", "lines", "refused", "state"}


def a_state(name, written=NOW - 1, **change):
    s = {"schema": "raqib-forward/1", "name": name, "pid": 4242, "written": forward.iso(written),
         "destination": {"scheme": "https", "host": "192.0.2.10", "port": 8088, "path": "/collect"},
         "shape": "raqib", "delivery": "acknowledged", "plain": False, "file": "/home/u/.raqib/host/events.jsonl",
         "cursor": {"offset": 0, "line_sha256": None}, "from": {"start": "start", "offset": 0}, "beat": 60,
         "sent": 7, "skipped": 0, "refused": {"count": 2, "ids": ["r1:2", "r1:3"]}, "restarts": 0,
         "last_id": "r1:9", "last_ok": forward.iso(written), "behind": 0, "failing": None,
         "head": {"length": 0, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
         "in_question": {"count": 0, "since": None}}
    s.update(change)
    return s


def folder_of(home):
    d = Path(link.forward_dir(str(home)))
    d.mkdir(parents=True, exist_ok=True)
    return d


def put(home, name, data):
    path = folder_of(home) / (name + ".json")
    path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode("ascii"))
    return path


def each_word(home):
    """A folder with a state of each word (OK, FAILING, BEHIND, SILENT, UNREADABLE twice) and names no forwarder
    has, which are not read."""
    put(home, "ok", a_state("ok"))
    put(home, "failing", a_state("failing", failing={"since": forward.iso(NOW - 30), "tries": 3, "error": "connect",
                                                     "status": None}))
    put(home, "behind", a_state("behind", behind=100, last_ok=None, last_id=None))
    put(home, "silent", a_state("silent", written=NOW - 500))
    put(home, "broken", b"{not json")
    put(home, "other", {"schema": "raqib-forward/0"})
    d = folder_of(home)
    for stray in ("UPPER.json", "a.txt", ".json", "x" * 33 + ".json", "ok.json.tmp"):
        (d / stray).write_bytes(b"{}")
    return ["behind", "broken", "failing", "ok", "other", "silent"]


def built(rows):
    """What `--status` writes, built from read's rows alone."""
    return "".join("raqib forward %s: %s (exit %d); refused %s\n" % (
        r["name"], r["word"], r["code"], "unknown" if r["refused"] is None else "%d" % r["refused"]) +
        "".join("  %s\n" % line for line in r["lines"]) for r in rows)


def status_before(name=None, home=None, out=None, clock=None):
    """raqib/forward.py's `status` as it was before link.read (its body unchanged, the names taken from link),
    the reference for E4's byte for byte. It is unbounded, so it is used with at most 64 states."""
    folder = link.forward_dir(home)
    if name:
        forward.check_name(name)
        names = [name]
    else:
        try:
            names = sorted(n[:-5] for n in os.listdir(folder) if n.endswith(".json") and link.NAME.match(n[:-5]))
        except OSError:
            names = []
    if not names:
        out.write("raqib forward --status: no forwarder has written a state in %s: silent (exit 3)\n" % folder)
        return 3
    worst, now = 0, clock()
    for n in names:
        refused = "unknown"
        try:
            with open(link.state_path(n, home), "rb") as f:
                state = json.loads(f.read().decode("ascii"))
        except FileNotFoundError:
            code, word, lines = 3, "SILENT", ["no state: %s (it never ran, or not here)" % link.state_path(n, home)]
        except Exception:
            code, word, lines = 3, "UNREADABLE", ["the state %s cannot be read" % link.state_path(n, home)]
        else:
            code, word, lines = link.judge(state, now)
            try:
                refused = "%d" % state["refused"]["count"] if code != 3 or word != "UNREADABLE" else "unknown"
            except Exception:
                pass
        out.write("raqib forward %s: %s (exit %d); refused %s\n" % (n, word, code, refused))
        for line in lines:
            out.write("  %s\n" % line)
        worst = code if (code == 3 or worst != 3 and code > worst) else worst
    return worst


def said(fn, name, home):
    out = io.StringIO()
    code = fn(name, home=str(home), out=out, clock=lambda: NOW)
    return code, out.getvalue()


# --- E1 (R-1): one statement of each, in link ----------------------------------------------------------------

def test_e1_forward_takes_every_name_of_the_state_from_link_and_each_is_the_same_object():
    for name in MOVED_VALUES + MOVED_FUNCTIONS:
        assert hasattr(link, name), name
        assert getattr(forward, name) is getattr(link, name), name
    for name in MOVED_FUNCTIONS:
        assert getattr(link, name).__module__ == "raqib.link", name
    assert forward.check_name("a-1") == "a-1"   # stays the forwarder's: it raises its UsageError
    with pytest.raises(forward.UsageError):
        forward.check_name("../x")


def test_e1_forward_py_defines_none_of_them_a_second_time_and_link_py_defines_each_once():
    def defined(path):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = []
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
                names.append(n.name)
            elif isinstance(n, ast.Assign):
                names += [t.id for t in n.targets if isinstance(t, ast.Name)]
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name):
                names.append(n.target.id)
        return names
    fwd, lnk = defined(ROOT / "raqib" / "forward.py"), defined(ROOT / "raqib" / "link.py")
    for name in MOVED_VALUES + MOVED_FUNCTIONS:
        assert name not in fwd, name
        assert lnk.count(name) == 1, name
    text = (ROOT / "raqib" / "forward.py").read_text(encoding="utf-8")
    for second in ("def judge", "def state_problem", "def _state_problem", '"connect": "no connection',
                   "STATUS_RULE = ", "ERRORS = ", "SCHEMA = "):
        assert second not in text, second
    assert "def judge(state, now):" in (ROOT / "raqib" / "link.py").read_text(encoding="utf-8")
    # the negative: the check sees a definition where there is one
    assert "status" in fwd and "check_name" in fwd and "check_name" not in lnk


# --- E2 (R-1): no network, nothing of the forwarder ------------------------------------------------------------

def imports_of(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out, dynamic = [], []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            base = "." * n.level + (n.module or "")
            out += [base] + ["%s.%s" % (base, a.name) for a in n.names]
        elif isinstance(n, ast.Call) and ast.unparse(n.func).split(".")[-1] in ("import_module", "__import__"):
            dynamic.append(ast.unparse(n))
    return out, dynamic


def test_e2_link_imports_the_standard_library_with_no_network_and_of_raqib_only_host():
    net = {"socket", "ssl", "http", "urllib", "socketserver", "ftplib", "smtplib", "asyncio", "selectors",
           "xmlrpc", "imaplib", "poplib", "telnetlib", "webbrowser", "requests", "httpx", "aiohttp"}
    names, dynamic = imports_of(ROOT / "raqib" / "link.py")
    assert names and not dynamic
    for m in names:
        assert not m.startswith("."), m   # no relative import
        top = m.split(".")[0]
        assert top not in net, m
        if top == "raqib":
            assert m in ("raqib", "raqib.host"), m
        else:
            assert top in sys.stdlib_module_names, m
        assert not {"forward", "cli", "app"} & set(m.split(".")), m
    # the negative: the same check finds the forwarder's network
    fnames, _ = imports_of(ROOT / "raqib" / "forward.py")
    assert {"socket", "ssl", "http.client"} <= set(fnames)


def test_e2_importing_link_in_a_fresh_interpreter_imports_no_forwarder_and_no_command_line():
    code = ("import sys, raqib.link; print(sorted(m for m in sys.modules if m in ('raqib.forward', 'raqib.cli',"
            " 'raqib.app')))")
    got = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert got.returncode == 0 and got.stdout.decode("ascii").strip() == "[]", got.stderr
    code = "import sys, raqib.forward; print('raqib.link' in sys.modules)"   # the negative: forward does take it
    got = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert got.returncode == 0 and got.stdout.decode("ascii").strip() == "True", got.stderr


# --- E3 (R-1, R-4): read and worst -----------------------------------------------------------------------------

def test_e3_read_gives_one_row_for_each_state_of_a_forwarders_name_sorted_and_judged_by_judge(tmp_path):
    home = tmp_path / "home"
    names = each_word(home)
    rows = link.read(home=str(home), now=NOW)
    assert isinstance(rows, list) and rows.rest == 0
    assert [r["name"] for r in rows] == names   # in order of name; UPPER, a.txt, .json, 33 letters not read
    words = {r["name"]: (r["code"], r["word"]) for r in rows}
    assert words == {"ok": (0, "OK"), "failing": (1, "FAILING"), "behind": (1, "BEHIND"), "silent": (3, "SILENT"),
                     "broken": (3, "UNREADABLE"), "other": (3, "UNREADABLE")}
    for r in rows:
        assert set(r) == ROW_KEYS and r["path"] == link.state_path(r["name"], str(home))
        if r["name"] == "broken":
            assert r["lines"] == ["the state %s cannot be read" % r["path"]] and r["state"] is None
            assert r["refused"] is None
            continue
        state = json.loads(Path(r["path"]).read_bytes().decode("ascii"))
        assert (r["code"], r["word"], r["lines"]) == link.judge(state, NOW)
        if r["word"] == "UNREADABLE":   # not what a forwarder writes: no count known, no state given
            assert r["refused"] is None and r["state"] is None
        else:
            assert r["refused"] == 2 and r["state"] == state


def test_e3_read_with_a_name_gives_that_one_and_a_missing_file_is_silent(tmp_path):
    home = tmp_path / "home"
    each_word(home)
    assert [(r["name"], r["word"]) for r in link.read(str(home), NOW, "ok")] == [("ok", "OK")]
    gone = link.read(str(home), NOW, "gone")
    path = link.state_path("gone", str(home))
    assert gone == [{"name": "gone", "path": path, "code": 3, "word": "SILENT",
                     "lines": ["no state: %s (it never ran, or not here)" % path], "refused": None, "state": None}]
    for bad in ("../ok", "UPPER", "", "x" * 33, None, 7):   # no forwarder's name: no row, no path built
        assert link.read(str(home), NOW, bad) == ([] if bad is not None else link.read(str(home), NOW))


def test_e3_worst_is_3_over_1_over_0_and_no_row_is_3():
    rows = lambda *codes: [{"code": c} for c in codes]
    assert link.worst([]) == 3
    assert link.worst(rows(0)) == 0 and link.worst(rows(0, 0)) == 0
    assert link.worst(rows(0, 1)) == 1 and link.worst(rows(1, 0)) == 1
    assert link.worst(rows(1, 3, 0)) == 3 and link.worst(rows(3, 1)) == 3 and link.worst(rows(0, 1, 3)) == 3


def test_e3_read_with_no_state_at_all_is_no_row_and_its_worst_is_3(tmp_path):
    assert link.read(str(tmp_path / "none"), NOW) == []   # no folder
    folder_of(tmp_path / "empty")
    rows = link.read(str(tmp_path / "empty"), NOW)
    assert rows == [] and rows.rest == 0 and link.worst(rows) == 3


# --- E4 (R-1): status says what it said, built on read ---------------------------------------------------------

def test_e4_status_writes_byte_for_byte_the_lines_built_from_reads_rows_and_what_it_wrote_before(tmp_path):
    home = tmp_path / "home"
    names = each_word(home)
    for name in [None] + names + ["gone"]:
        code, text = said(forward.status, name, home)
        rows = link.read(str(home), NOW, name)
        assert text == built(rows) and code == link.worst(rows), name
        assert (code, text) == said(status_before, name, home), name
    empty = tmp_path / "empty"
    folder_of(empty)
    for where in (empty, tmp_path / "nowhere"):   # no state at all; no folder at all
        code, text = said(forward.status, None, where)
        assert link.read(str(where), NOW) == [] and code == 3
        assert text == ("raqib forward --status: no forwarder has written a state in %s: silent (exit 3)\n"
                        % link.forward_dir(str(where)))
        assert (code, text) == said(status_before, None, where)
    with pytest.raises(forward.UsageError):   # a name no forwarder has is a usage error, as it was
        said(forward.status, "../x", home)


# --- E5 (R-4): the bounds ---------------------------------------------------------------------------------------

def test_e5_64_states_are_all_read_and_65_are_64_rows_and_one_further_line(tmp_path):
    home = tmp_path / "home"
    for i in range(64):
        put(home, "s%02d" % i, a_state("s%02d" % i))
    rows = link.read(str(home), NOW)
    assert len(rows) == 64 and rows.rest == 0
    code, text = said(forward.status, None, home)
    assert (code, text) == (0, built(rows)) == said(status_before, None, home)   # the negative: no further line
    put(home, "s64", a_state("s64", written=NOW - 500))   # the 65th, last by name: counted, not read
    rows = link.read(str(home), NOW)
    assert [r["name"] for r in rows] == ["s%02d" % i for i in range(64)] and rows.rest == 1
    code, text = said(forward.status, None, home)
    further = ("raqib forward --status: 1 more state(s) in %s not read: at most 64 are read, in order of name;"
               " what is not read is not calm (exit 3)\n" % link.forward_dir(str(home)))
    assert text == built(rows) + further and code == link.worst(rows) == 3   # S-1: as the old status said of it
    assert said(status_before, None, home)[0] == 3 and link.worst(list(rows)) == 0   # a copy has lost the count
    assert "s64" not in text
    put(home, "a0", a_state("a0"))   # a name before the others by order: it is read, s63 and s64 are counted
    rows = link.read(str(home), NOW)
    assert rows[0]["name"] == "a0" and rows[-1]["name"] == "s62" and rows.rest == 2
    assert link.read(str(home), NOW, "s64")[0]["word"] == "SILENT"   # by its name it is read


def test_e5_a_state_longer_than_1_mib_is_unreadable_said_and_never_read_whole(tmp_path, monkeypatch):
    home = tmp_path / "home"
    body = json.dumps(a_state("edge")).encode("ascii")
    put(home, "edge", body + b" " * (link.STATE_MAX - len(body)))   # 1 MiB exactly: read and judged
    put(home, "long", body + b" " * (link.STATE_MAX + 1 - len(body)))   # one byte more
    with open(folder_of(home) / "huge.json", "wb") as f:   # 64 MiB, sparse where the system can
        f.truncate(64 * link.STATE_MAX)
    asked, real = [], os.fdopen

    class Watched:
        def __init__(self, f):
            self.f = f

        def read(self, n=-1):
            asked.append(n)
            return self.f.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.f.close()

    monkeypatch.setattr(link.os, "fdopen", lambda fd, mode: Watched(real(fd, mode)))
    rows = {r["name"]: r for r in link.read(str(home), NOW)}
    monkeypatch.undo()
    assert len(asked) == 3 and all(0 < n <= link.STATE_MAX + 1 for n in asked), asked
    assert (rows["edge"]["code"], rows["edge"]["word"]) == (0, "OK")
    for name in ("long", "huge"):
        r = rows[name]
        assert (r["code"], r["word"], r["refused"], r["state"]) == (3, "UNREADABLE", None, None)
        assert r["lines"] == ["the state %s cannot be read: it is longer than 1 MiB and is not read" % r["path"]]


def test_e5_a_folder_that_cannot_be_listed_is_no_row_and_never_raises(tmp_path, monkeypatch):
    home = tmp_path / "home"
    Path(link.forward_dir(str(home))).parent.mkdir(parents=True)
    Path(link.forward_dir(str(home))).write_bytes(b"a file where the folder is")
    rows = link.read(str(home), NOW)
    assert rows == [] and "cannot be listed (NotADirectoryError)" in rows.problem and link.worst(rows) == 3
    code, text = said(forward.status, None, home)
    assert code == 3 and "cannot be listed" in text and "nothing is known of the forwarders" in text
    assert "no forwarder has written a state" not in text   # S-2: not looked for is not "none"
    home2 = tmp_path / "home2"
    put(home2, "ok", a_state("ok"))
    assert [r["word"] for r in link.read(str(home2), NOW)] == ["OK"]   # the negative: listed, read

    def refused(path):
        raise PermissionError(13, "Permission denied", path)
    monkeypatch.setattr(link.os, "scandir", refused)
    rows = link.read(str(home2), NOW)
    assert rows == [] and "cannot be listed (PermissionError)" in rows.problem and link.worst(rows) == 3
    assert said(forward.status, None, home2)[0] == 3

    class Broken:   # a listing that fails part way
        def __init__(self, path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def __iter__(self):
            raise OSError(5, "Input/output error")
    monkeypatch.setattr(link.os, "scandir", Broken)
    assert link.read(str(home2), NOW) == []


def test_s4_a_link_to_nothing_is_unreadable_and_what_is_no_regular_file_is_never_opened(tmp_path, monkeypatch):
    home = tmp_path / "home"
    put(home, "ok", a_state("ok"))
    try:
        os.symlink(str(tmp_path / "nothing"), str(folder_of(home) / "gone.json"))
    except (OSError, NotImplementedError):
        pytest.skip("this system makes no symbolic link here")
    (folder_of(home) / "dir.json").mkdir()
    opened, real = [], os.open
    monkeypatch.setattr(link.os, "open", lambda path, *a: opened.append(os.path.basename(path)) or real(path, *a))
    rows = {r["name"]: r for r in link.read(str(home), NOW)}
    assert rows["gone"]["word"] == "UNREADABLE" and rows["gone"]["lines"] == [
        "the state %s cannot be read" % rows["gone"]["path"]]   # not "no state": something is there
    assert rows["dir"]["word"] == "UNREADABLE" and rows["ok"]["word"] == "OK"
    assert opened == ["ok.json"]   # the type is asked before the open
    assert link.read(str(home), NOW, "absent")[0]["word"] == "SILENT"   # the negative: nothing there at all


def test_e5_a_directory_not_ascii_not_json_and_json_nested_deep_are_unreadable_rows_and_none_raises(tmp_path):
    home = tmp_path / "home"
    put(home, "ok", a_state("ok"))
    (folder_of(home) / "dir.json").mkdir()
    latin = a_state("latin", file="/home/" + chr(0xe9) + "/e.jsonl")   # a letter no ASCII has
    put(home, "latin", json.dumps(latin, ensure_ascii=False).encode("utf-8"))
    put(home, "text", b"not json at all")
    put(home, "empty", b"")
    put(home, "deep", b"[" * 200000 + b"]" * 200000)   # past what the reader takes
    nested = [[]]
    for _ in range(400):
        nested = [nested]
    put(home, "nested", a_state("nested", file=nested))   # taken by the reader, not what a forwarder writes
    put(home, "list", b"[1, 2, 3]")
    rows = {r["name"]: r for r in link.read(str(home), NOW)}
    assert sorted(rows) == ["deep", "dir", "empty", "latin", "list", "nested", "ok", "text"]
    assert (rows["ok"]["code"], rows["ok"]["word"]) == (0, "OK")   # one forwarder's failure is its own
    for name in ("deep", "dir", "empty", "latin", "list", "nested", "text"):
        r = rows[name]
        assert (r["code"], r["word"], r["refused"], r["state"]) == (3, "UNREADABLE", None, None), name
    for name in ("deep", "dir", "empty", "latin", "text"):
        assert rows[name]["lines"] == ["the state %s cannot be read" % rows[name]["path"]], name
    assert rows["nested"]["lines"] == ["not what a forwarder writes: file is not a text"]
    code, text = said(forward.status, None, home)
    assert code == 3 and (code, text) == said(status_before, None, home)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="a named pipe is a POSIX file")
def test_e5_a_state_that_is_a_pipe_is_unreadable_and_never_waited_on(tmp_path):
    home = tmp_path / "home"
    put(home, "ok", a_state("ok"))
    os.mkfifo(str(folder_of(home) / "pipe.json"))   # no writer: an open that waits would wait for ever
    code = ("import sys; from raqib import link; rows = link.read(sys.argv[1], %r);"
            " print(' '.join('%%s=%%s' %% (r['name'], r['word']) for r in rows))" % NOW)
    got = subprocess.run([sys.executable, "-c", code, str(home)], cwd=str(ROOT), stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=60)
    assert got.returncode == 0 and got.stdout.decode("ascii").split() == ["ok=OK", "pipe=UNREADABLE"], got.stderr


# --- E6 (R-1): said, ASCII, documentation addresses only -------------------------------------------------------

def test_e6_forward_md_says_the_states_reader_and_its_judgement_are_link_py_with_no_network():
    flat = " ".join((ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8").split())
    assert ("The state's reader and its judgement are raqib/link.py's, which imports nothing of the network and"
            " nothing of the forwarder: `raqib forward --status` and the window read and judge a state by it, one"
            " judgement for both (ADR-0011 R-1).") in flat
    assert flat.count("raqib/link.py") == 1


def test_e6_link_and_its_tests_are_ascii_and_name_only_loopback_and_documentation_addresses():
    import re
    for path in (ROOT / "raqib" / "link.py", Path(__file__)):
        text = path.read_bytes().decode("ascii")
        for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
            assert ip.startswith(("127.", "192.0.2.", "198.51.100.", "203.0.113.")), (path.name, ip)
