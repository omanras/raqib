"""M12.1p (ADR-0013 Amendment C, AC-1): `raqib watch --host --no-page` - the host watch without its page.

E1 the start binds and listens on nothing and starts no page thread; E2 the loop says no page line and opens
nothing, and a default run (with its page) says every line it said before this task, word for word; E3 the state
file and the registry row say null for url and port and every reader the watch calls takes it; E4 the command
line; E5 the guide's sentence; E6 the files stay ASCII and host.py imports no socket of its own."""
import ast
import errno
import io
import json
import os
import re
import socket
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover, host, ui, watch  # noqa: E402
from raqib.rules import engine  # noqa: E402

sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import make as host_fixtures  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
NO_PAGE_LINE = "raqib watch --host: no page is served (--no-page): no port is opened\n"
NULL_PORT = {"requested": None, "used": None, "warning": None}
GUIDE_SENTENCE = ("`--no-page` serves no page: the watch opens no port and nothing listens on one, no page is opened"
                  " in a browser, and its report and its events file are unchanged (ADR-0013 Amendment C, AC-1).")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def inv(name):
    return host_fixtures.inventory(name, CATALOG)


def start(home, out=None, **kw):
    """host.start as the CLI's watch would call it, on a fixture's inventory, with no notification and the
    events naming a fixed host (no real name in a test's words)."""
    kw.setdefault("no_open", True)
    kw.setdefault("environ", {})
    return host.start(CATALOG, RULES, every=10, no_notify=True, out=out or io.StringIO(), err=io.StringIO(),
                      home=str(home), reader=lambda: inv("linux"), platform="test", event_host="test-host",
                      tracing=lambda: host.OffTracing(), **kw)


def run_to_stop(running):
    """The window's way out: a Stop set before the loop; the first tick reads round 1 and the loop ends."""
    stop = watch.Stop()
    try:
        stop.set("the window's Stop")
        crash = host.loop(running, stop)
        text, code = host.conclude(running, crash)
    finally:
        host.close(running)
    return crash, text, code


def fail_if_called(name, calls):
    def fail(*args, **kwargs):
        calls.append(name)
        pytest.fail("%s was called by a watch with no page" % name)
    return fail


def free(port):
    """Whether this test can bind and listen on 127.0.0.1:port itself (no SO_REUSEADDR: a listener there refuses)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        s.listen(1)
        return True
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", None), errno.EACCES):
            return False
        raise
    finally:
        s.close()


def lines(text):
    return [line for line in text.split("\n") if line]


# --- E1: the start opens no listener ------------------------------------------------------------------------

def test_e1_the_start_with_no_page_binds_listens_and_serves_nothing(_home, monkeypatch):
    before = free(watch.DEFAULT_PORT)
    assert before, "port %d is taken by another process before the start: free it to run this test" % (
        watch.DEFAULT_PORT)
    calls, sockets = [], []
    out = io.StringIO()
    with monkeypatch.context() as m:
        m.setattr(watch, "_serve", fail_if_called("watch._serve", calls))
        m.setattr(ui, "make_server", fail_if_called("ui.make_server", calls))
        m.setattr(socket.socket, "bind", lambda self, *a: sockets.append(("bind", a)) or pytest.fail("bind"))
        m.setattr(socket.socket, "listen", lambda self, *a: sockets.append(("listen", a)) or pytest.fail("listen"))
        running = start(_home, out=out, no_page=True)
        try:
            assert calls == [] and sockets == []
            assert "raqib-host-page" not in [t.name for t in threading.enumerate()]
            assert running.server is None and running.thread is None and running.no_page is True
            w = running.watcher
            assert w.url is None and w.port == NULL_PORT
            said = out.getvalue()
            assert said.count(NO_PAGE_LINE) == 1 and said.count("no page is served") == 1
            assert "127.0.0.1" not in said and "page http" not in said
        except BaseException:
            host.close(running)
            raise
    try:
        assert free(watch.DEFAULT_PORT), "the default port %d is taken after the start" % watch.DEFAULT_PORT
    finally:
        crash, text, code = run_to_stop(running)
    assert crash is None and code == 0 and "RESULT: CLEAN (exit 0" in text


def test_e1_the_no_page_line_follows_the_starts_holes_and_comes_once(_home):
    out = io.StringIO()
    running = start(_home, out=out, no_page=True)
    crash, text, code = run_to_stop(running)
    said = lines(out.getvalue())
    holes = [i for i, line in enumerate(said) if line.startswith("raqib watch --host: hole: ")]
    at = said.index(NO_PAGE_LINE.rstrip("\n"))
    assert holes and at == holes[-1] + 1 and said.count(NO_PAGE_LINE.rstrip("\n")) == 1


# --- E2: the loop without a page; a default run as before ----------------------------------------------------

def test_e2_the_loop_with_no_page_says_no_page_line_opens_nothing_and_closes_no_server(_home, monkeypatch):
    calls = []
    monkeypatch.setattr(watch, "open_page", fail_if_called("watch.open_page", calls))
    out = io.StringIO()
    running = start(_home, out=out, no_page=True, no_open=False, environ={})   # the default would open it
    running.watcher.port = dict(NULL_PORT, warning="a warning the loop must not look for")
    crash, text, code = run_to_stop(running)
    said = out.getvalue()
    assert crash is None and calls == [] and code == 0
    assert not [line for line in lines(said) if line.startswith("raqib watch --host: page")]
    assert "WARNING" not in said and "a warning the loop must not look for" not in said
    assert "stopped (the window's Stop)" in said and running.server is None
    host.close(running)   # twice is harmless: no server to shut down, nothing raised


def test_e2_the_loop_with_no_page_and_ci_set_says_nothing_of_a_page(_home):
    out = io.StringIO()
    running = start(_home, out=out, no_page=True, no_open=False, environ={"CI": "true"})
    run_to_stop(running)
    assert "page not opened" not in out.getvalue() and "CI is set" not in out.getvalue()


# The start's and the loop's lines of a default run (a page, --no-open, the window's Stop), word for word as they
# were before M12.1p (HOME: the test's home; PORT: the port the page took; the round lines are the tick's).
DEFAULT_HEAD = [
    "raqib watch --host: the host, not a name (ADR-0007); nothing is installed, no project is touched (no"
    " --attach-hooks)",
    "raqib watch --host: sources: the host's own record of every tree (no Sysmon channel here (test: the os source"
    " is Windows only)) (the watch's own check at its start)",
    "raqib watch --host: a round every 10 s (the homes only (no live reader here)), the reader's deadline 20 s;"
    " until Ctrl-C",
    "raqib watch --host: record HOME/.raqib/host/rounds.jsonl",
    "raqib watch --host: state HOME/.raqib/host/rounds.jsonl.watch.json",
    "raqib watch --host: events HOME/.raqib/host/events.jsonl (raqib-event/1, one line appended for each thing new"
    " or changed; a heartbeat every 60 s; nothing is sent)",
    "raqib watch --host: events: host test-host (--event-host)",
    "raqib watch --host: notifications: off (--no-notify)",
    "raqib watch --host: rhythm: RHYTHM at 3 cycles (talk to one destination, a child within 30 s) in 10 rounds"
    " (HOST-RHYTHM.yaml)",
    "raqib watch --host: suspect: off (no --suspect): no model is asked, nothing leaves the machine",
    "raqib watch --host: rules overlay: not loaded (the catalog as its YAMLs declare it)",
    "raqib watch --host: rules: no rule off",
]
DEFAULT_TAIL = [
    "raqib watch --host: page http://127.0.0.1:PORT/ (read-only, reloads every 5 s; Stop ends the watch)",
    "raqib watch --host: page not opened (--no-open)",
]


def said_as_held(out, home, running):
    port = running.server.server_address[1]
    text = out.getvalue().replace(str(home), "HOME").replace(":%d/" % port, ":PORT/")
    return [line.replace("\\", "/") if " record " in line or " state " in line or " events " in line else line
            for line in lines(text)]


def test_e2_a_default_run_says_every_line_it_said_before_word_for_word(_home):
    out = io.StringIO()
    running = start(_home, out=out)
    holes = ["raqib watch --host: hole: %s" % host._safe(n) for n in running.watcher.notes]
    crash, text, code = run_to_stop(running)
    said = said_as_held(out, _home, running)
    rounds = [line for line in said if line.startswith("[")]
    assert [line for line in said if not line.startswith("[")] == (
        DEFAULT_HEAD + holes + DEFAULT_TAIL + ["raqib watch --host: stopped (the window's Stop)"])
    assert rounds and all(" round 1: " in line for line in rounds) and crash is None and code == 0
    assert holes and holes[0].startswith("raqib watch --host: hole: HOST-RHYTHM (M7.4) sees only what the rounds")
    assert running.no_page is False and running.watcher.url.startswith("http://127.0.0.1:")


def test_e2_a_default_run_opens_its_page_says_a_port_warning_and_closes_its_server(_home, monkeypatch):
    opened = []
    monkeypatch.setattr(watch, "open_page", lambda url, environ=None, **kw: opened.append(url))
    serve = watch._serve

    def warned(page, port, routes=None, refresh=None):
        server, record = serve(page, port, routes=routes, refresh=refresh)
        return server, dict(record, warning="port %s on 127.0.0.1 is not available (test)" % port)
    monkeypatch.setattr(watch, "_serve", warned)
    out = io.StringIO()
    running = start(_home, out=out, no_open=False, environ={}, port=0)
    assert running.thread.name == "raqib-host-page" and running.thread.is_alive()
    crash, text, code = run_to_stop(running)
    said = lines(out.getvalue())
    url = running.watcher.url
    assert opened == [url] and url == "http://127.0.0.1:%d/" % running.server.server_address[1]
    at = said.index("raqib watch --host: WARNING: port 0 on 127.0.0.1 is not available (test)")
    assert said[at + 1] == "raqib watch --host: page %s (read-only, reloads every 5 s; Stop ends the watch)" % url
    assert not [line for line in said if "page not opened" in line]
    running.thread.join(10)
    assert not running.thread.is_alive() and running.server.socket.fileno() == -1   # shut down and closed


def test_e2_a_default_run_under_ci_says_the_page_is_not_opened(_home, monkeypatch):
    monkeypatch.setattr(watch, "open_page", fail_if_called("watch.open_page", []))
    out = io.StringIO()
    running = start(_home, out=out, no_open=False, environ={"CI": "true"}, port=0)
    run_to_stop(running)
    assert "raqib watch --host: page not opened (CI is set)\n" in out.getvalue()


# --- E3: url and port are null wherever the watch writes them; its readers take a null ----------------------

def own_rows(home, running):
    data = json.loads(Path(watch.registry_path(str(home))).read_text(encoding="utf-8"))
    own = running.watcher.own()
    return [r for r in data["watches"] if (r.get("pid"), r.get("trace"), r.get("started")) == own]


def test_e3_the_state_and_the_registry_row_say_null_and_the_readers_take_it(_home):
    running = start(_home, no_page=True)
    w = running.watcher
    try:
        state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
        assert "url" in state and state["url"] is None and state["port"] == NULL_PORT
        (row,) = own_rows(_home, running)
        assert "url" in row and row["url"] is None and "port" in row and row["port"] is None
        page = w.page()   # its page data builder, called by the test: text, from a null url and port
        assert isinstance(page, str) and page.startswith("<!doctype html>") and "127.0.0.1" not in page
        judged = ui.judge_row(row, w.wall(), 30, alive=lambda pid: True)   # the registry's reader, on its row
        assert judged["link"] is None and judged["port"] is None
        watches = ui.read_watches(watch.registry_path(str(_home)), w.wall(), 30)   # its own row not skipped
        assert [r["link"] for r in watches["rows"]] == [None]
        assert ui.band_items(state) and ui.status(state)[0] == "WATCHING"
    finally:
        crash, text, code = run_to_stop(running)
    assert crash is None and code == 0
    state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert state["url"] is None and state["port"] == NULL_PORT and state["finished"]
    (row,) = own_rows(_home, running)
    assert row["url"] is None and row["port"] is None and row["status"] == "finished"


def test_e3_the_report_and_the_events_file_are_the_same_with_and_without_a_page(_home, tmp_path):
    texts, kinds = [], []
    for no_page in (False, True):
        home = tmp_path / ("page" if not no_page else "nopage")
        home.mkdir()
        running = start(home, no_page=no_page, port=0)
        crash, text, code = run_to_stop(running)
        texts.append(re.sub(r"\d", "0", text.replace(str(home), "HOME")))
        events = Path(running.watcher.events_path).read_text(encoding="ascii")
        kinds.append([json.loads(line).get("kind") for line in events.splitlines()])
    assert texts[0] == texts[1] and kinds[0] == kinds[1] and kinds[0]


# --- E4: the command line -------------------------------------------------------------------------------------

def test_e4_watch_host_no_page_reaches_host_command_with_no_page(monkeypatch):
    seen = []
    monkeypatch.setattr(host, "command", lambda catalog, rules, **kw: seen.append(kw) or 0)
    assert cli.main(["watch", "--host", "--no-page", "--rounds", "1", "--no-notify"], out=io.StringIO()) == 0
    assert cli.main(["watch", "--host", "--rounds", "1", "--no-notify"], out=io.StringIO()) == 0
    assert [kw["no_page"] for kw in seen] == [True, False] and seen[0]["port"] is None
    assert [kw["refresh"] for kw in seen] == [None, None]   # AC-13: --refresh not given is None, not 5


def test_e4_without_no_page_a_host_page_still_reloads_every_5_s_by_default(_home, monkeypatch):
    """AC-13: watch's --refresh defaults to None; the start reads None as ui.REFRESH_DEFAULT, 5 s. The CLI's own
    run of `raqib watch --host` (the real host.command, loop and close) on a fixture's inventory."""
    import inspect
    real, runs = host.start, []

    def start_on_a_fixture(*args, **kw):
        bound = inspect.signature(real).bind(*args, **kw)
        bound.arguments.update(reader=lambda: inv("linux"), platform="test", event_host="test-host",
                               tracing=lambda: host.OffTracing())
        runs.append(real(*bound.args, **bound.kwargs))
        return runs[-1]
    monkeypatch.setattr(host, "start", start_on_a_fixture)
    assert ui.REFRESH_DEFAULT == 5 and cli._parser().parse_args(["watch", "--host"]).refresh is None
    assert cli._parser().parse_args(["watch", "--host", "--refresh", "5"]).refresh == 5
    out = io.StringIO()
    assert cli.main(["watch", "--host", "--rounds", "1", "--no-notify", "--no-open", "--port", "0"], out=out) == 0
    (running,) = runs
    w = running.watcher
    assert running.no_page is False and w.refresh == 5 and running.server is not None
    said = out.getvalue()
    assert "raqib watch --host: page %s (read-only, reloads every 5 s; Ctrl-C ends the watch)\n" % w.url in said
    assert json.loads(Path(w.state_path).read_text(encoding="ascii"))["refresh_seconds"] == 5
    assert "no page is served" not in said


@pytest.mark.parametrize("argv,message", [
    (["watch", "--no-page"], "--no-page is --host's"),
    (["watch", "my-project", "--no-page"], "--no-page is --host's"),
    (["watch", "--host", "--no-page", "--port", "8765"], "--no-page serves no page and opens no port: --port"
                                                          " does not apply with it"),
    (["watch", "--host", "--no-page", "--port", "0"], "--port does not apply with it"),
    (["watch", "--host", "--no-page", "--refresh", "9"], "--no-page serves no page, so nothing reloads: --refresh"
                                                          " does not apply with it"),
    (["watch", "--host", "--no-page", "--refresh", "5"], "--refresh does not apply with it"),   # AC-13: the default's
    (["watch", "--host", "--refresh", "5", "--no-page"], "--refresh does not apply with it"),   # in either order
])
def test_e4_no_page_usage_errors_exit_2_and_say_why(argv, message, capsys, monkeypatch):
    monkeypatch.setattr(host, "command", fail_if_called("host.command", []))
    monkeypatch.setattr(watch, "command", fail_if_called("watch.command", []))
    assert cli.main(argv, out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert message in err and err.count("\n") == 1


def test_e4_raqib_app_is_not_given_the_option_and_the_usage_and_the_help_name_it(capsys):
    assert cli.main(["app", "--no-page"], out=io.StringIO()) == 2
    assert "unrecognized arguments: --no-page" in capsys.readouterr().err
    p = cli._parser()
    sub = next(a for a in p._actions if a.__class__.__name__ == "_SubParsersAction")
    assert not [a for a in sub.choices["app"]._actions if "--no-page" in a.option_strings]
    (option,) = [a for a in sub.choices["watch"]._actions if "--no-page" in a.option_strings]
    assert option.help.startswith("--host: serve no page: no port is opened") and option.default is False
    (usage,) = [line for line in cli.__doc__.split("\n") if line.startswith("  watch --host [")]
    assert usage.endswith(" [--no-page]")


# --- E5: the guide ---------------------------------------------------------------------------------------------

def test_e5_the_guide_says_what_no_page_does_where_watch_hosts_options_are_told():
    guide = (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8")
    part = guide.split("\n## Watch the host\n", 1)[1].split("\n## ", 1)[0]
    paragraphs = [" ".join(p.split()) for p in part.split("\n\n")]
    (told,) = [p for p in paragraphs if GUIDE_SENTENCE in p]
    assert told.startswith("`--attach-hooks`") and told.endswith(" " + GUIDE_SENTENCE)   # the options' paragraph
    assert " ".join(guide.split()).count("`--no-page`") == 1


# --- E6: ASCII, and no socket of host.py's own --------------------------------------------------------------------

def test_e6_the_files_are_ascii_and_host_py_imports_no_socket_or_server():
    for name in ("raqib/host.py", "raqib/cli.py", "tests/test_host_nopage.py", "tests/test_readme_top.py"):
        (ROOT / name).read_bytes().decode("ascii")
    tree = ast.parse((ROOT / "raqib" / "host.py").read_text(encoding="ascii"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    assert not names & {"socket", "socketserver", "http", "ssl", "asyncio", "selectors"}, names
