"""M6.2 dashboard v2: exit criteria E1-E6 (HANDOFF.md) under ADR-0005
Amendment I (docs/review/2026-11-03-M6.2-ruling.md, I-1..I-12). Every
behaviour added has a test here (D-8, I-12), hostile strings included.

No test shows a real notification or opens a browser: notifiers get a fake
runner or are off, and watch runs with --no-open --no-notify.
"""
import ast
import datetime
import io
import json
import os
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover, notify, report, ui, watch  # noqa: E402
from raqib.rules import engine, trace  # noqa: E402

WINDOWS = os.name == "nt"
FIXTURES = ROOT / "tests" / "fixtures"
CATALOG = ROOT / "raqib" / "rules" / "catalog"
RULES = engine.load_catalog(CATALOG)
BLOCKED = FIXTURES / "blocked-calls-claude-code-2.1.301.log"
DISCOVER_LINUX = FIXTURES / "discover" / "linux"
START = datetime.datetime(2026, 11, 2, 12, 0, 0, tzinfo=datetime.timezone.utc)
PROJECT = "/work/demo-proj"
EXPECTED_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'")
# Every hostile shape of E6 in one string: markup, a javascript: URL, an ANSI
# sequence, the RTL override U+202E and NUL.
HOSTILE = ('<script>alert(1)</script>"><img src=x onerror=alert(2)><a href="javascript:alert(3)">x</a>'
           "\x1b[2J" + chr(0x202E) + "gpj.exe\x00end")
HREF = re.compile(r'href="([^"]*)"')
SAFE_HREF = re.compile(r"#L\d+|#(top|discover|watches)|/|/discover|http://127\.0\.0\.1:\d{1,5}/")


# --- helpers ---------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """Every test gets its own HOME, so ~/.raqib (traces, tmp, watches.json) is in tmp_path."""
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    monkeypatch.delenv("RAQIB_GAP_SECONDS", raising=False)
    return path


class FakeRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, env, timeout, wait=True):
        self.calls.append(Path(argv[-1]).read_text(encoding="ascii").split("\n")[0])
        return 0, None


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def make_notifier(runner=None, **kw):
    kw.setdefault("environ", {})
    kw.setdefault("platform", "linux")
    kw.setdefault("isfile", lambda p: True)
    kw.setdefault("stderr", io.StringIO())
    return notify.Notifier(PROJECT, runner=runner or FakeRunner(), **kw)


def make_watch(tmp_path, gap=5, runner=None, notifier=None, state_path=None, name="raqib.log.jsonl"):
    path = tmp_path / "traces" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    clock = Clock()
    notifier = notifier or make_notifier(runner)
    w = watch.Watch(PROJECT, str(path), lambda records: cli.run_rules(records, RULES, {}, gap), RULES, gap, notifier,
                    out=io.StringIO(), err=io.StringIO(), clock=clock, started=START, state_path=state_path,
                    wall=lambda: START.timestamp() + clock.t - 1000.0)   # J-5: wall time follows the fake clock
    return w, path, clock


def ts(seconds):
    return (START + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def rec(seq, phase, at, session="s-dash", tool="Bash", **extra):
    line = {"ts": ts(at), "seq": seq, "session_id": session, "phase": phase, "tool": tool, "cwd": "/work/demo-proj"}
    if phase in ("pre", "post"):
        line.update(input_sha256="0" * 64, input_meta=extra.pop("input_meta", {"command_head": "ls"}))
    if phase == "post":
        line.update(output_sha256="1" * 64, ok=True,
                    output_meta=extra.pop("output_meta", {"scan": "full", "secret_kinds": []}))
    line.update(extra)
    return json.dumps(line)


def secret_call(seq, at, session="s-dash"):
    return [rec(seq, "pre", at, session, input_meta={"command_head": "cat"}),
            rec(seq, "post", at + 1, session, input_meta={"command_head": "cat"},
                output_meta={"scan": "full", "secret_kinds": ["aws_access_key_id"]})]


def append(path, data):
    with open(path, "ab") as f:
        f.write(data if isinstance(data, bytes) else ("\n".join(data) + "\n").encode("utf-8"))


def fetch(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8")


def serve(page, routes=None, refresh=None):
    server = ui.make_server(page, 0, routes=routes, refresh=refresh)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


def assert_inert(page):
    """E6: nothing the agent wrote is markup, a link, or a control character."""
    low = page.lower()
    assert "<script" not in low and "<img" not in low and "<a href=\"javascript" not in low
    assert chr(0x202E) not in page and "\x00" not in page and "\x1b" not in page
    assert all(c == "\n" or c.isprintable() for c in page)
    for href in HREF.findall(page):
        assert SAFE_HREF.fullmatch(href), href


def blocked_report(path=BLOCKED, extra_findings=(), extra_alarms=()):
    numbered, problems = trace.read_numbered(str(path))
    records = [r for _, r in numbered]
    found, notes = cli.run_rules(records, RULES, {}, 60)
    rep = report.build(str(path), numbered, problems, found + list(extra_findings), notes,
                       report.rule_table(RULES), "rules", extra_alarms=extra_alarms)
    return rep, numbered, problems


def inventory():
    texts, holes = discover.read_dir(str(DISCOVER_LINUX))
    return discover.run(texts, discover.load_catalog(discover.CATALOG), holes=holes)


def write_discover(directory, inv=None, age=None, now=None):
    path = Path(directory) / "discover.json"
    path.write_text(json.dumps(inv if inv is not None else inventory(), indent=2, sort_keys=True,
                               ensure_ascii=True) + "\n", encoding="ascii")
    if age is not None:
        moment = (now - datetime.timedelta(seconds=age)).timestamp()
        os.utime(path, (moment, moment))
    return path


def run_watch(monkeypatch, argv, actions=()):
    """`raqib watch` with a fake poll wait: each wait runs the next action
    with the page server; when none is left, Ctrl-C."""
    servers = []
    real = ui.make_server

    def make(page, port, **kw):
        server = real(page, port, **kw)
        servers.append(server)
        return server
    monkeypatch.setattr(ui, "make_server", make)
    queue = list(actions)

    def fake_sleep(seconds):
        if not queue:
            raise KeyboardInterrupt
        queue.pop(0)(servers[0])
    monkeypatch.setattr(watch, "_sleep", fake_sleep)
    out = io.StringIO()
    code = cli.main([str(a) for a in argv], out=out)
    return code, out.getvalue()


def project_files(proj):
    return sorted(p.relative_to(proj).as_posix() for p in proj.rglob("*") if p.is_file())


# --- E1, I-1: no script, the CSP as it was, a meta refresh ----------------------------------

def test_e1_the_csp_is_byte_identical_and_no_page_has_a_script(tmp_path):
    assert ui.CSP == EXPECTED_CSP
    meta = '<meta http-equiv="Content-Security-Policy" content="%s">' % EXPECTED_CSP
    w, path, clock = make_watch(tmp_path)
    append(path, secret_call(1, 0))
    w.step()
    write_discover(path.parent, now=w.wall())
    rep, numbered, problems = blocked_report()
    pages = [w.page(), w.discover_page(), ui.render(rep, numbered, problems), ui.render(rep, numbered, problems,
                                                                                         refresh=5),
             ui.error_page("x", 5), ui.discover_page(str(tmp_path / "none.json"), 5)]
    for page in pages:
        assert page.count(meta) == 1 and "<script" not in page.lower()
        assert "@import" not in page and "url(" not in page and " src=" not in page
    server, base = serve(w.page, {ui.DISCOVER_ROUTE: w.discover_page}, refresh=5)
    try:
        for route in ("/", ui.DISCOVER_ROUTE):
            status, headers, body = fetch(base + route)
            assert status == 200 and headers["Content-Security-Policy"] == EXPECTED_CSP
            assert headers["X-Content-Type-Options"] == "nosniff" and headers["Cache-Control"] == "no-store"
            assert "<script" not in body.lower() and '<meta http-equiv="refresh" content="5">' in body
        assert fetch(base + "/etc/passwd")[0] == 404 and fetch(base + "/discover/x")[0] == 404
    finally:
        server.shutdown()
        server.server_close()

    def broken():
        raise RuntimeError("<script>gone</script>")
    server, base = serve(broken, {ui.DISCOVER_ROUTE: broken}, refresh=7)
    try:
        for route in ("/", ui.DISCOVER_ROUTE):                                    # an error page keeps reloading
            status, headers, body = fetch(base + route)
            assert status == 500 and headers["Content-Security-Policy"] == EXPECTED_CSP
            assert '<meta http-equiv="refresh" content="7">' in body and "<script" not in body
    finally:
        server.shutdown()
        server.server_close()


def test_i1_a_served_page_reloads_every_n_seconds_and_a_static_file_never():
    rep, numbered, problems = blocked_report()
    static = ui.render(rep, numbered, problems)
    assert 'http-equiv="refresh"' not in static
    assert '<meta http-equiv="refresh" content="7">' in ui.render(rep, numbered, problems, refresh=7)
    assert '<meta http-equiv="refresh" content="3600">' in ui.render(rep, numbered, problems, refresh=3600)
    assert '<meta http-equiv="refresh" content="9">' in ui.error_page("boom", 9)    # it goes when the cause does
    assert 'http-equiv="refresh"' not in ui.error_page("boom")
    with pytest.raises(ValueError):
        ui.render(rep, numbered, problems, refresh=0)


@pytest.mark.parametrize("value", ["0", "3601", "1.5", "-1", "+5", " 5", "5 ", "abc", "", "0x10", chr(0x665),
                                   "99999", True, 0, 3601])
def test_i1_refresh_outside_1_to_3600_is_refused(value):
    with pytest.raises(ValueError):
        ui.check_refresh(value)


@pytest.mark.parametrize("value", ["1", "5", "3600", 7, "0005"])
def test_i1_refresh_whole_numbers_from_1_to_3600(value):
    assert ui.check_refresh(value) == int(value)


@pytest.mark.parametrize("argv", [
    ["watch", ".", "--refresh", "0"], ["watch", ".", "--refresh", "3601"], ["watch", ".", "--refresh", "2.5"],
    ["watch", ".", "--refresh", "x"], ["ui", BLOCKED, "--serve", "--refresh", "0"],
    ["ui", BLOCKED, "--refresh", "5"], ["ui", BLOCKED, "-o", "x.html", "--refresh", "5"],
], ids=["watch-0", "watch-3601", "watch-fraction", "watch-word", "serve-0", "static", "static-out"])
def test_i1_a_bad_refresh_is_a_usage_error(argv, monkeypatch):
    monkeypatch.setattr(watch, "command", lambda *a, **k: pytest.fail("watch ran"))
    monkeypatch.setattr(ui, "make_server", lambda *a, **k: pytest.fail("a server was made"))
    assert cli.main([str(a) for a in argv], out=io.StringIO()) == 2


def test_i1_ui_serve_reloads_every_refresh_seconds_default_5(monkeypatch):
    served = []

    class FakeServer:
        server_address = ("127.0.0.1", 4321)

        def __init__(self, page, kw):
            self.page, self.kw = page, kw

        def serve_forever(self):
            served.append((self.page(), self.kw))
            raise KeyboardInterrupt

        def server_close(self):
            pass
    monkeypatch.setattr(ui, "make_server", lambda page, port, **kw: FakeServer(page, kw))
    assert cli.main(["ui", str(BLOCKED), "--serve", "--port", "0"], out=io.StringIO()) == 0
    assert cli.main(["ui", str(BLOCKED), "--serve", "--port", "0", "--refresh", "11"], out=io.StringIO()) == 0
    (page5, kw5), (page11, kw11) = served
    assert '<meta http-equiv="refresh" content="5">' in page5 and kw5 == {"refresh": 5}
    assert '<meta http-equiv="refresh" content="11">' in page11 and kw11 == {"refresh": 11}


def test_i1_watch_passes_refresh_to_its_page(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    pages = []

    def look(server):
        pages.append(fetch("http://127.0.0.1:%d/" % server.server_address[1])[2])
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0", "--refresh", "9"],
                          [look])
    assert '<meta http-equiv="refresh" content="9">' in pages[0] and "reloads every 9 s" in out
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"], [look])
    assert '<meta http-equiv="refresh" content="5">' in pages[1] and "this page reloads every 5 s" in pages[1]
    assert json.loads(Path(watch.default_trace(os.path.normpath(str(proj))) + ".watch.json").read_text(
        encoding="ascii"))["refresh_seconds"] == 5


# --- E2, I-2, I-3: the band ------------------------------------------------------------------

def base_state(tmp_path):
    w, path, clock = make_watch(tmp_path)
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1), rec(2, "post", 2)])
    w.step()
    return w.state(clock())


def test_i3_the_state_words_in_their_order(tmp_path):
    state = base_state(tmp_path)
    assert ui.status(state)[:2] == ("WATCHING", "clean")
    window = {"epoch": 0, "since": "2026-11-02T12:00:00.000Z", "opened": "x", "closed": None, "after": "after line 3",
              "seconds": None, "closed_by_line": None}
    gone = {"line": 3, "seq": 3, "session_id": "s", "at": "2026-11-02T12:00:00.000Z"}
    cases = [
        (dict(state, agent_gone=gone), "AGENT GONE"),
        (dict(state, agent_gone=gone, silence=[window]), "SILENT for 0 s"),          # SILENT > AGENT GONE
        (dict(state, silence=[window], capture={"failed": "line 2 is a marker"}), "CAPTURE FAILED"),
        (dict(state, heartbeat_age_seconds=3600), "CAPTURE FAILED"),                  # stale: C-4 in the detail
        (dict(state, finished="2026-11-02T12:00:09.000Z", capture={"failed": "x"}), "FINISHED"),
        (dict(state, finished="t", status="crashed", error="RuntimeError: x"), "FINISHED"),
        (dict(state, silence=[dict(window, epoch=7)]), "WATCHING"),                   # a window of gone content
    ]
    for case, word in cases:
        assert ui.status(case)[0] == word, (case, ui.status(case))
    assert ui.status(cases[3][0])[2].startswith("CRASHED or stuck: no heartbeat for 3600 s")
    assert ui.status(cases[5][0])[1:] == ("alarm", "CRASHED: RuntimeError: x")
    assert ui.status(cases[2][0])[2] == "line 2 is a marker; the next good line clears it"


def test_i2_after_a_session_end_no_window_opens_until_the_next_line(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, gap=5, runner=runner)
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "stop", 1, tool="-"), rec(3, "session_end", 2, tool="-")])
    w.step()
    clock.t += 60
    w.step()
    assert w.windows == [] and "Raqib: SILENCE-LIVE open" not in runner.calls
    word, level, detail = w.status_word()
    assert (word, level) == ("AGENT GONE", "incomplete")
    assert "session s-dash, line 3, seq 3" in detail and "no silence window opens until the next line" in detail
    assert json.loads(Path(w.state_path).read_text(encoding="ascii"))["agent_gone"]["line"] == 3
    append(path, [rec(4, "session_start", 70, tool="-")])                      # the next session: WATCHING
    clock.t += 1
    w.step()
    assert w.status_word()[0] == "WATCHING" and w.agent_gone() is None
    clock.t += 6
    w.step()                                                                     # and silence counts again
    assert w.status_word()[0] == "SILENT for 6 s" and runner.calls.count("Raqib: SILENCE-LIVE open") == 1


def test_i2_an_open_window_closes_on_the_end_line(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, gap=5, runner=runner)
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "stop", 1, tool="-")])
    w.step()
    clock.t += 6
    w.step()
    assert w.status_word()[0] == "SILENT for 6 s"
    append(path, [rec(3, "session_end", 7, tool="-")])
    clock.t += 1
    w.step()
    assert (w.windows[0]["closed_by_line"], w.windows[0]["notice_closed"]) == (3, "sent")
    clock.t += 60
    w.step()
    assert len(w.windows) == 1 and w.status_word()[0] == "AGENT GONE"
    assert [c for c in runner.calls if "LIVE" in c] == ["Raqib: SILENCE-LIVE open", "Raqib: SILENCE-LIVE closed"]


def test_i2_a_line_after_the_end_that_is_not_a_record_is_a_line(tmp_path):
    w, path, clock = make_watch(tmp_path, gap=5)
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "session_end", 1, tool="-"), "{torn"])
    w.step()
    assert w.agent_gone() is None
    clock.t += 6
    w.step()
    assert w.status_word()[0] == "SILENT for 6 s"


def test_i3_a_marker_fails_capture_until_the_next_good_record(tmp_path):
    w, path, clock = make_watch(tmp_path)
    append(path, [rec(1, "session_start", 0, tool="-"), "RAQIB-SILENCE: capture failed event=PreToolUse"])
    w.step()
    word, level, detail = w.status_word()
    assert (word, level) == ("CAPTURE FAILED", "alarm")
    assert detail == ("line 2 of the trace is a RAQIB-SILENCE marker: an event was not captured; the next good line"
                      " clears it")
    append(path, b"{torn\n")                                                     # not a good line: it holds
    clock.t += 1
    w.step()
    assert w.status_word()[0] == "CAPTURE FAILED"
    append(path, [rec(3, "pre", 3)])
    clock.t += 1
    w.step()
    word, level, detail = w.status_word()
    assert (word, level) == ("WATCHING", "clean")
    assert detail == "4 lines in this trace content; capture recovered at seq 3 (line 4, 2026-11-02T12:00:02.000Z)"
    capture = json.loads(Path(w.state_path).read_text(encoding="ascii"))["capture"]
    assert capture["failed"] is None and capture["recovered"] == {"seq": 3, "line": 4,
                                                                   "at": "2026-11-02T12:00:02.000Z"}


def test_i3_hooks_missing_or_foreign_at_start_fail_capture_and_knock_once(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    w.hooks_at_start(True, "settings.json: installed for all 6 events")
    assert w.status_word()[0] == "WATCHING" and w.holes == []
    w.hooks_at_start(False, "settings.json: foreign for Stop")
    assert w.status_word()[:2] == ("CAPTURE FAILED", "alarm")
    assert "hooks missing or foreign at start: settings.json: foreign for Stop" in w.status_word()[2]
    assert [h["kind"] for h in w.holes] == ["capture-failed"] and runner.calls == ["Raqib: RAQIB-SILENCE"]
    w.hooks_at_start(False, "again")                                             # one hole, one knock
    assert len(w.holes) == 1 and len(runner.calls) == 1
    append(path, [rec(1, "session_start", 0, tool="-")])
    w.step()
    assert w.status_word()[0] == "WATCHING" and "capture recovered at seq 1" in w.status_word()[2]


def test_i3_watch_runs_doctors_hook_check_after_the_install(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"])
    st = json.loads(Path(watch.default_trace(os.path.normpath(str(proj))) + ".watch.json").read_text(encoding="ascii"))
    assert st["capture"]["hooks"]["ok"] is True and "installed for all 6 events" in st["capture"]["hooks"]["detail"]
    # disableAllHooks: doctor's check says so; one capture hole, the band CAPTURE FAILED.
    other = tmp_path / "off"
    (other / ".claude").mkdir(parents=True)
    (other / ".claude" / "settings.json").write_text('{"disableAllHooks": true}\n', encoding="utf-8")
    pages = []
    code, out = run_watch(monkeypatch, ["watch", other, "--no-open", "--no-notify", "--port", "0"],
                          [lambda server: pages.append(fetch("http://127.0.0.1:%d/" % server.server_address[1])[2])])
    st = json.loads(Path(watch.default_trace(os.path.normpath(str(other))) + ".watch.json").read_text(encoding="ascii"))
    assert st["capture"]["hooks"]["ok"] is False and "disableAllHooks is true" in st["capture"]["hooks"]["detail"]
    assert [h["kind"] for h in st["holes"]] == ["capture-failed"]
    assert '<span class="badge state alarm">CAPTURE FAILED</span>' in pages[0]
    assert "hooks disabled" in pages[0] and "disableAllHooks is true" in pages[0]          # J-9


def test_e2_the_band_says_notifications_on_or_off_the_trace_and_the_last_line_time(tmp_path):
    w, path, clock = make_watch(tmp_path, notifier=make_notifier(isfile=lambda p: p in ("/bin/notify-send", "/bin/sh")))
    page = w.page()
    assert "notifications: on (notify-send)" in page and "no line read yet (watching since 2026-11-02T12:00:00.000Z)" \
        in page
    assert "trace <code>%s</code>" % ui._text(str(path)) in page
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1)])
    clock.t += 2
    w.step()
    page = w.page()
    # J-12: the record's ts and the read time, each labelled
    assert "last line 2 (seq 2): record ts 2026-11-02T12:00:01.000Z, read at 2026-11-02T12:00:02.000Z" in page
    band = page[page.index('<div class="band">'):page.index("</div>", page.index('<div class="band">'))]
    assert band.index("WATCHING") < band.index("notifications: on") < band.index("trace <code>")
    off, _, _ = make_watch(tmp_path, notifier=make_notifier(enabled=False, reason="--no-notify"), name="b.jsonl")
    assert "notifications: off (--no-notify)" in off.page()
    term, _, _ = make_watch(tmp_path, notifier=make_notifier(isfile=lambda p: False), name="c.jsonl")
    assert "notifications: on, terminal bell and stderr only" in term.page()


def test_i4_the_page_is_built_from_memory_and_an_unwritable_watch_json_is_a_hole_in_the_band(tmp_path):
    w, path, clock = make_watch(tmp_path, gap=5)
    append(path, [rec(1, "session_start", 0, tool="-")])
    w.step()
    clock.t += 6
    w.step()
    forged = dict(json.loads(Path(w.state_path).read_text(encoding="ascii")), silence=[], status="watching")
    Path(w.state_path).write_text(json.dumps(forged), encoding="ascii")        # the agent rewrites the file
    assert "SILENT for 6 s" in w.page()                                          # the page reads memory
    lost, lpath, lclock = make_watch(tmp_path, state_path=str(tmp_path / "missing" / "x.watch.json"),
                                     name="lost.jsonl")
    lost.step()
    assert lost.state_error and "cannot write" in lost.state_error
    page = lost.page()
    assert "watch.json cannot be written: cannot write %s" % ui._text(str(tmp_path / "missing" / "x.watch.json")) \
        in page and '<span class="badge alarm">watch.json cannot be written' in page


# --- E3, I-9, I-10: one builder, alarms, findings by severity, the timeline -------------------

def finding(rule, severity, seq=2):
    return {"rule_id": rule, "severity": severity, "session_id": "b3744113-5956-4e40-915a-91c245a2ece7",
            "cited_seq": [seq], "summary": "made for the test", "ts": None, "kind": "signature", "class": "NET"}


def test_i9_findings_by_severity_empty_groups_hidden_unknown_last(tmp_path):
    rep, numbered, problems = blocked_report(extra_findings=[finding("X-LOW", "low"), finding("X-ODD", "critical"),
                                                             finding("X-ODD2", "<b>urgent</b>")])
    page = ui.render(rep, numbered, problems)
    groups = re.findall(r"<h3>(\w+) \((\d+)\)</h3>", page)
    assert [g for g, _ in groups] == ["high", "low", "other"]                    # no medium: hidden
    assert dict(groups)["other"] == "2" and "never dropped (I-9)" in page
    assert page.index("<h3>high") < page.index("X-LOW") < page.index("<h3>other") < page.index("X-ODD")
    assert "&lt;b&gt;urgent&lt;/b&gt;" in page and "<b>urgent" not in page
    assert ui.severity_groups([]) == []


def test_i9_one_builder_band_alarms_findings_timeline_in_that_order(tmp_path):
    w, path, clock = make_watch(tmp_path, gap=5)
    append(path, [rec(1, "session_start", 0, tool="-")] + secret_call(2, 1) + ["RAQIB-SILENCE: lost one"])
    w.step()
    clock.t += 6
    w.step()
    page = w.page()
    order = [page.index(x) for x in ('<div class="band">', "<h2>Alarms", "<h2>Findings", "<h2>Timeline",
                                     '<h2 id="watches">', "<h2>Suspicion", "<h2>Rules (")]
    assert order == sorted(order)
    alarms = page[page.index("<h2>Alarms"):page.index("<h2>Findings")]
    kinds = re.findall(r'<div class="card"><span class="tag">([a-z-]+)</span>', alarms)
    assert kinds[0] == "capture-failed" and "silence-window" in kinds and "trace-problem" in kinds
    assert ui.alarm_order([{"kind": "silence-window"}, {"kind": "no-kind"}, {"kind": "capture-failed"}]) == [
        {"kind": "capture-failed"}, {"kind": "silence-window"}, {"kind": "no-kind"}]


def test_i9_raqib_ui_uses_the_same_builder_without_band_refresh_or_watches(tmp_path):
    out = tmp_path / "view.html"
    assert cli.main(["ui", str(BLOCKED), "-o", str(out)], out=io.StringIO()) == 1
    page = out.read_text(encoding="utf-8")
    assert "<h3>high (" in page and 'class="band"' not in page and 'http-equiv="refresh"' not in page
    assert 'id="watches"' not in page and 'class="nav"' not in page
    assert page.index("<h2>Alarms") < page.index("<h2>Findings") < page.index("<h2>Timeline") < page.index(
        "<h2>Suspicion")


def test_i10_closed_windows_lighter_before_their_line_the_open_one_marked(tmp_path):
    w, path, clock = make_watch(tmp_path, gap=5)
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1), rec(2, "post", 2)])
    w.step()
    clock.t += 6
    w.step()                                                                     # opens
    append(path, [rec(3, "pre", 7), rec(3, "post", 8)])
    clock.t += 1
    w.step()                                                                     # closed by line 4
    clock.t += 8
    w.step()                                                                     # a second one, open
    page = w.page()
    rows = re.findall(r"<tr (?:class|id)=\"([^\"]+)\"", page)
    closed = rows.index("band live")
    assert rows[closed + 1] == "L4" and rows[-1] == "band live open"
    assert '<span class="tag">OPEN</span> live silence (raqib watch), open: no line read since 2026-11-02T12:00:07.000Z' \
        in page and "8.0 s so far" in page
    assert "live silence (raqib watch), closed: no line from 2026-11-02T12:00:00.000Z to 2026-11-02T12:00:07.000Z" \
           " (7.0 s; limit 5 s) after line 3, seq 2; closed by line 4" in page
    assert "tr.band.live td" in page and "tr.band.live.open td" in page          # lighter, and marked
    # A truncation starts new content: the old windows stay in the alarms, not in the new timeline.
    path.write_text(rec(1, "session_start", 30, session="s-new", tool="-") + "\n", encoding="utf-8")
    clock.t += 1
    w.step()
    page = w.page()
    assert "band live" not in page and page.count("silence-window") == 2


# --- E4, I-5..I-7: the registry ----------------------------------------------------------------

def registry_rows(home):
    return json.loads((home / ".raqib" / "watches.json").read_text(encoding="ascii"))["watches"]


def test_e4_each_watch_is_a_row_of_home_raqib_watches_json_never_removed(tmp_path, monkeypatch, _home):
    proj = tmp_path / "proj"
    proj.mkdir()
    pages = []

    def look(server):
        pages.append(fetch("http://127.0.0.1:%d/" % server.server_address[1])[2])
        rows = registry_rows(_home)
        assert rows[-1]["status"] == "watching" and rows[-1]["finished"] is None
        assert rows[-1]["port"] == server.server_address[1]
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"], [look])
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"], [look])
    rows = registry_rows(_home)
    trace_path = watch.default_trace(os.path.normpath(str(proj)))
    assert len(rows) == 2 and all(r["status"] == "finished" and r["finished"] for r in rows)
    for r in rows:
        assert (r["pid"], r["project"], r["trace"], r["state"]) == (os.getpid(), os.path.normpath(str(proj)),
                                                                    trace_path, trace_path + ".watch.json")
        assert isinstance(r["port"], int) and r["notes"] == []
    assert "raqib watch: registry %s" % (_home / ".raqib" / "watches.json") in out
    assert project_files(proj) == [".claude/settings.json"]                      # nothing in the project
    assert not (_home / ".raqib" / "watches.json.lock").exists()
    # The second page shows the first watch as a GONE row, not dropped: it ended, and the same
    # trace's watch.json is the second watch's now (one process here, so the pid alone cannot tell).
    assert '<span class="tag">GONE</span> its watch.json belongs to another watch now' in pages[1]
    assert "registry row" in pages[1]


def test_i5_a_stale_lock_is_broken_after_10_s_with_a_note_in_the_row(tmp_path, _home):
    path = _home / ".raqib" / "watches.json"
    path.parent.mkdir(parents=True)
    lock = Path(str(path) + ".lock")
    lock.write_text("pid 1\n")
    old = lock.stat().st_mtime - 11
    os.utime(lock, (old, old))
    w, _, _ = make_watch(tmp_path)
    assert w.register(watch.Registry(str(path))) is None
    (row,) = registry_rows(_home)
    assert len(row["notes"]) == 1 and re.fullmatch(
        r"the registry lock .+watches\.json\.lock was 1\d\.\d s old, more than 10 s: broken by pid \d+", row["notes"][0])
    assert not lock.exists() and w.registry_state["note"] == row["notes"][0]


def test_i5_a_young_lock_is_waited_for_and_a_held_one_is_a_hole(tmp_path, _home):
    path = _home / ".raqib" / "watches.json"
    path.parent.mkdir(parents=True)
    lock = Path(str(path) + ".lock")
    lock.write_text("pid 1\n")
    now = [lock.stat().st_mtime]
    sleeps = []

    def sleep(seconds):                     # each wait is one second on the fake wall clock
        sleeps.append(seconds)
        now[0] += 1.0
    registry = watch.Registry(str(path), wall=lambda: now[0], sleep=sleep)
    assert registry.change(lambda rows, note: rows.append({"pid": 1}))[1] is None
    assert len(sleeps) == 11 and registry.read()[0]["watches"] == [{"pid": 1}]  # broken only once older than 10 s

    def busy(seconds):                      # a writer that keeps the lock young
        now[0] += 1.0
        os.utime(lock, (now[0], now[0]))
    lock.write_text("pid 2\n")
    os.utime(lock, (now[0], now[0]))
    w, _, _ = make_watch(tmp_path)
    hole = w.register(watch.Registry(str(path), wall=lambda: now[0], sleep=busy))
    assert hole.startswith("the registry %s was not written (registered): the registry lock" % path)
    assert "was not let go within 11 s" in hole and [h["kind"] for h in w.holes] == ["registry"]
    assert w.holes[0]["notice"] == "not knocked: the registry is not capture"
    assert registry.read()[0]["watches"] == [{"pid": 1}]


@pytest.mark.parametrize("text", [b"not json{", b"[]", b'{"watches": "x"}', b"\xff\xfe", b'{"raqib_watches": 1}'],
                         ids=["not-json", "list", "watches-not-a-list", "not-utf8", "no-watches"])
def test_i5_a_corrupt_registry_is_left_as_it_is_and_is_a_hole(tmp_path, _home, text):
    path = _home / ".raqib" / "watches.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(text)
    w, _, _ = make_watch(tmp_path)
    hole = w.register(watch.Registry(str(path)))
    assert hole and "it is left as it is, and this watch is not in it (I-5)" in hole
    assert path.read_bytes() == text and not Path(str(path) + ".lock").exists()
    page = w.page()
    assert page.count("registry hole") >= 1 and "this watch (from memory)" in page   # its own row from memory
    assert "it is left as it is" in page


@pytest.mark.skipif(WINDOWS or not hasattr(os, "mkfifo"), reason="needs a FIFO")
def test_i5_a_fifo_or_a_directory_as_registry_never_holds_the_watch(tmp_path, _home):
    path = _home / ".raqib" / "watches.json"
    path.parent.mkdir(parents=True)
    os.mkfifo(path)                                     # opened, it would block until a writer came
    w, _, _ = make_watch(tmp_path)
    hole = w.register(watch.Registry(str(path)))
    assert hole == ("the registry %s is not a regular file: it is left as it is, and this watch is not in it (I-5)"
                    % path)
    assert "is not a regular file; it is left as it is (I-5)" in w.page()
    os.remove(path)
    path.mkdir()
    assert "is not a regular file" in w.register(watch.Registry(str(path)))


def write_state(path, heartbeat, status="watching", pid=4242, started=None, **extra):
    Path(path).write_text(json.dumps(dict({"status": status, "heartbeat": heartbeat, "pid": pid, "started": started},
                                          **extra)), encoding="ascii")


def test_i5_gone_rows_are_never_pruned_and_are_shown_gone(tmp_path, _home):
    path = _home / ".raqib" / "watches.json"
    registry = watch.Registry(str(path))
    for n in (1, 2):
        registry.change(lambda rows, note, n=n: rows.append({"pid": 2 ** 31 - n, "project": "/p%d" % n, "port": 9000 + n,
                                                             "trace": str(tmp_path / ("t%d" % n)),
                                                             "started": "s", "status": "finished"}))
    w, _, clock = make_watch(tmp_path)
    w.register(registry)
    w.finish()
    w.unregister()
    rows = registry_rows(_home)
    assert [r["project"] for r in rows] == ["/p1", "/p2", PROJECT] and rows[2]["status"] == "finished"
    info = ui.read_watches(str(path), START, 1.5, own=w.own())
    assert [r["project"] for r in info["rows"]] == ["/p1", "/p2"] and not any(r["alive"] for r in info["rows"])
    assert all("pid %d is gone" % r["pid"] in r["why"] for r in info["rows"])


def test_i6_alive_needs_the_pid_and_a_fresh_heartbeat(tmp_path):
    now = START
    state = tmp_path / "t.watch.json"
    row = {"pid": 4242, "project": "/p", "port": 8800, "trace": str(tmp_path / "t")}
    write_state(state, "2026-11-02T11:59:59.000Z")                              # 1 s old
    alive = ui.judge_row(row, now, 1.5, alive=lambda pid: True)
    assert alive["alive"] and alive["why"] == "" and alive["watch_status"] == "watching"
    assert alive["state"] == str(state) and alive["link"] == "http://127.0.0.1:8800/"
    gone = ui.judge_row(row, now, 1.5, alive=lambda pid: False)
    assert not gone["alive"] and gone["why"] == "pid 4242 is gone"
    write_state(state, "2026-11-02T11:59:58.000Z")                              # 2 s old: stale
    stale = ui.judge_row(row, now, 1.5, alive=lambda pid: True)
    assert stale["why"] == "no heartbeat for 2.0 s (ALIVE needs one younger than 1.5 s)"
    both = ui.judge_row(row, now, 1.5, alive=lambda pid: False)
    assert both["why"] == "pid 4242 is gone; no heartbeat for 2.0 s (ALIVE needs one younger than 1.5 s)"
    assert ui.judge_row(row, now, 1.5, alive=lambda pid: None)["why"].startswith("pid 4242 cannot be checked")
    write_state(state, "2026-11-02T12:00:09.000Z")
    assert "in the future" in ui.judge_row(row, now, 1.5, alive=lambda pid: True)["why"]
    write_state(state, "2026-11-02T11:59:59.000Z", pid=777, started="2026-11-02T11:00:00.000Z")
    assert ui.judge_row(row, now, 1.5, alive=lambda pid: True)["why"] == (
        'its watch.json belongs to another watch now (pid 777, started "2026-11-02T11:00:00.000Z")')
    state.unlink()
    assert ui.judge_row(row, now, 1.5, alive=lambda pid: True)["why"] == "its watch.json is gone, so no heartbeat"
    state.write_text("[1]", encoding="ascii")
    assert "not an object" in ui.judge_row(row, now, 1.5, alive=lambda pid: True)["why"]
    bad = ui.judge_row(dict(row, pid=True), now, 1.5, alive=lambda pid: pytest.fail("checked"))
    assert bad["why"].startswith("pid true is not a process number")
    assert watch.HEARTBEATS_FRESH * watch.POLL_SECONDS == 1.5


@pytest.mark.parametrize("pid", [0, -1, -12, True, False, "12", 12.0, None, 2 ** 31, [1]])
def test_i6_an_invalid_pid_is_never_checked(pid):
    assert ui.pid_alive(pid, platform="linux", kill=lambda *a: pytest.fail("kill was called")) is False
    assert ui.pid_alive(pid, platform="win32", kernel32=object()) is False


def test_i6_posix_checks_with_signal_0_only():
    calls = []

    def kill(pid, sig):
        calls.append((pid, sig))
        if pid == 2:
            raise ProcessLookupError
        if pid == 3:
            raise PermissionError
        if pid == 4:
            raise OSError("odd")
    assert [ui.pid_alive(p, platform="linux", kill=kill) for p in (1, 2, 3, 4)] == [True, False, True, None]
    assert calls == [(1, 0), (2, 0), (3, 0), (4, 0)]


@pytest.mark.skipif(WINDOWS, reason="the POSIX check")
def test_i6_posix_real_pids():
    assert ui.pid_alive(os.getpid()) is True
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    assert ui.pid_alive(child.pid) is False


class FakeKernel32:
    def __init__(self, open_result, code):
        self.open_result, self.code, self.closed, self.opened = open_result, code, [], []

    def open_process(self, pid):
        self.opened.append(pid)
        return self.open_result

    def exit_code(self, handle):
        return self.code

    def close(self, handle):
        self.closed.append(handle)


def test_i6_windows_checks_by_openprocess_and_never_os_kill(monkeypatch):
    monkeypatch.setattr(os, "kill", lambda *a: pytest.fail("os.kill on Windows sends CTRL_C_EVENT"))
    cases = [((7, 0), ui.STILL_ACTIVE, True), ((7, 0), 0, False), ((7, 0), None, None),
             ((None, ui.ERROR_ACCESS_DENIED), None, True), ((None, 87), None, False)]
    for open_result, code, expected in cases:
        api = FakeKernel32(open_result, code)
        assert ui.pid_alive(4242, platform="win32", kernel32=api) is expected
        assert api.opened == [4242] and api.closed == ([7] if open_result[0] else [])


@pytest.mark.skipif(WINDOWS, reason="off Windows there is no kernel32")
def test_i6_a_windows_check_without_kernel32_cannot_tell():
    assert ui.pid_alive(os.getpid(), platform="win32") is None


@pytest.mark.skipif(not WINDOWS, reason="the real Windows check")
def test_i6_windows_real_pids():
    assert ui.pid_alive(os.getpid()) is True
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    assert ui.pid_alive(child.pid) is False


def test_i6_ui_signals_nothing_kill_0_only_and_ctypes_queries_only():
    tree = ast.parse((ROOT / "raqib" / "ui.py").read_text(encoding="utf-8"))
    banned = ("killpg", "terminate", "TerminateProcess", "GenerateConsoleCtrlEvent", "send_signal", "system",
              "popen", "Popen", "startfile", "urlopen", "create_connection", "execv", "spawnv", "posix_spawn")
    kills, kernel = [], set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + [node.module or ""] if isinstance(node, ast.ImportFrom) else [
                a.name for a in node.names]
            assert not {n.split(".")[0] for n in names} & {"subprocess", "signal", "socket", "urllib", "webbrowser"}
        if isinstance(node, ast.Call):
            f = node.func
            called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            assert called not in banned, called
            if called == "kill":
                kills.append(node)
            if isinstance(f, ast.Attribute) and ast.unparse(f.value) in ("k", "self.k"):
                kernel.add(f.attr)
    assert len(kills) == 1 and isinstance(kills[0].args[1], ast.Constant) and kills[0].args[1].value == 0
    assert kernel == {"OpenProcess", "GetExitCodeProcess", "CloseHandle"}


@pytest.mark.parametrize("port", [0, -1, 65536, True, 1.5, "8765", "javascript:alert(1)", None, [8765]])
def test_i7_no_link_but_from_a_whole_number_port(port):
    assert ui.port_url(port) is None


def test_i7_links_are_127_0_0_1_port_only_and_the_registry_is_said_to_be_forgeable(tmp_path, _home):
    assert ui.port_url(1) == "http://127.0.0.1:1/" and ui.port_url(65535) == "http://127.0.0.1:65535/"
    path = _home / ".raqib" / "watches.json"
    registry = watch.Registry(str(path))
    w, _, _ = make_watch(tmp_path)
    alive = tmp_path / "alive.jsonl"
    write_state(str(alive) + ".watch.json", ui._iso(w.wall()), pid=os.getpid(), started="s1")
    registry.change(lambda rows, note: rows.extend([
        {"pid": os.getpid(), "project": "/alive", "port": 8765, "trace": str(alive), "started": "s1",
         "url": "http://evil.example/"},
        {"pid": 2 ** 31 - 1, "project": "/ok", "port": 8766, "trace": "/t1", "url": "http://evil.example/"},
        {"pid": 2 ** 31 - 2, "project": "/bad", "port": "javascript:alert(1)", "trace": "/t2",
         "url": "javascript:alert(1)"},
        {"pid": 2 ** 31 - 3, "project": "/host", "port": 8767, "trace": "/t3", "url": "http://10.0.0.1:8767/"}]))
    w.register(registry)
    page = w.page()
    hrefs = HREF.findall(page)
    assert "http://127.0.0.1:8765/" in hrefs                                     # the ALIVE row is linked
    # J-10: a GONE row's port is text, never a link.
    assert "http://127.0.0.1:8766/" not in hrefs and "http://127.0.0.1:8767/" not in hrefs
    assert "port 8766 (not linked: GONE)" in page and "port 8767 (not linked: GONE)" in page
    assert not [h for h in hrefs if "evil" in h or "javascript" in h or "10.0.0.1" in h]
    assert "port javascript:alert(1) is not a whole number from 1 to 65535" in page
    assert ui._text(ui.FORGEABLE) in page and ui.PID_REUSE in page
    assert_inert(page)


# --- E5, I-8: the discover tab -------------------------------------------------------------------

def test_e5_get_discover_shows_candidates_holes_cited_lines_and_age(tmp_path):
    w, path, clock = make_watch(tmp_path)
    w.step()
    inv = inventory()
    write_discover(path.parent, inv, age=30, now=w.wall())
    server, base = serve(w.page, {ui.DISCOVER_ROUTE: w.discover_page}, refresh=5)
    try:
        status, headers, page = fetch(base + "/")
        assert status == 200 and '<a href="/discover">discover</a>' in page
        status, headers, tab = fetch(base + "/discover")
        assert status == 200 and headers["Content-Security-Policy"] == EXPECTED_CSP
        head = urllib.request.Request(base + "/discover", method="HEAD")
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(head, timeout=10) as resp:
            assert resp.status == 200 and resp.read() == b"" and resp.headers["Content-Security-Policy"] == EXPECTED_CSP
    finally:
        server.shutdown()
        server.server_close()
    assert '<meta http-equiv="refresh" content="5">' in tab and "30.0 s ago" in tab and "not live" in tab
    assert "<h3>Candidates (%d)</h3>" % len(inv["candidates"]) in tab
    for c in inv["candidates"]:
        assert '<span class="tag">%s</span> pid %d' % (c["id"], c["pid"]) in tab
    assert "<h3>Holes (A3) (%d)</h3>" % len(inv["holes"]) in tab
    assert all(ui._text(h) in tab for h in inv["holes"])
    cited = {(x["src"], x["line"]) for c in inv["candidates"] for x in c["cites"]}
    assert cited and all("<tr><td>%s</td><td>%d</td>" % key in tab for key in cited)
    assert re.search(r"<h3>Cited lines \(A5\) \(\d+\)</h3>", tab)
    assert ui.DISCOVER_ACTS_SHOWN == discover.ACTS_SHOWN


def test_i8_no_discover_json_no_tab_link(tmp_path):
    w, path, clock = make_watch(tmp_path)
    page = w.page()
    assert 'href="/discover"' not in page
    tab = w.discover_page()
    assert "No inventory: there is no discover.json next to the trace" in tab and "ALARM" not in tab


@pytest.mark.parametrize("content, why", [
    (b"not json", "is not JSON"), (b"[]", "is not an inventory: not a JSON object"),
    (b'{"candidates": {}, "holes": []}', "candidates is not a list"),
    (b'{"holes": "x"}', "candidates and holes are not a list"), (b"\xff", "is not UTF-8"),
    (b"[" * 100000 + b"]" * 100000, "is not JSON"), ("dir", "is not a regular file"), ("big", "more than the 64")],
    ids=["not-json", "list", "candidates-dict", "no-candidates", "not-utf8", "deep", "directory", "too-big"])
def test_i8_an_unreadable_or_malformed_discover_json_is_an_alarm_on_the_tab(tmp_path, monkeypatch, content, why):
    w, path, clock = make_watch(tmp_path)
    target = path.parent / "discover.json"
    if content == "dir":
        target.mkdir()
    elif content == "big":
        monkeypatch.setattr(ui, "READ_MAX", 64)
        target.write_bytes(json.dumps(inventory()).encode())
    else:
        target.write_bytes(content)
    tab = w.discover_page()
    assert '<span class="badge alarm">ALARM</span> the inventory' in tab and "it cannot be shown (A3)" in tab
    assert why in tab and 'href="/discover"' in w.page()


@pytest.mark.skipif(WINDOWS or not hasattr(os, "mkfifo"), reason="needs a FIFO")
def test_i8_a_fifo_is_never_opened(tmp_path):
    w, path, clock = make_watch(tmp_path)
    os.mkfifo(path.parent / "discover.json")
    assert "is not a regular file" in w.discover_page()                         # and the page did not block


def test_i8_static_raqib_ui_shows_discover_only_when_the_file_is_next_to_the_trace(tmp_path):
    local = tmp_path / "t" / "trace.jsonl"
    local.parent.mkdir()
    local.write_bytes(BLOCKED.read_bytes())
    out = tmp_path / "view.html"
    cli.main(["ui", str(local), "-o", str(out)], out=io.StringIO())
    page = out.read_text(encoding="utf-8")
    assert 'id="discover"' not in page and 'href="#discover"' not in page and 'class="nav"' not in page
    write_discover(local.parent)
    cli.main(["ui", str(local), "-o", str(out)], out=io.StringIO())
    page = out.read_text(encoding="utf-8")
    assert '<h2 id="discover">Discover</h2>' in page and '<a href="#discover">discover</a>' in page
    assert '<a href="#top">trace</a>' in page and '<h1 id="top">' in page and "<h3>Candidates (" in page
    assert page.index("<h2>Rules (") < page.index('<h2 id="discover">')


# --- E6, I-11: hostile strings from the trace, the registry and the inventory -------------------

def test_e6_every_value_is_escaped_and_control_characters_become_question_marks(tmp_path, _home):
    w, path, clock = make_watch(tmp_path, gap=5)
    append(path, [rec(1, "session_start", 0, session=HOSTILE, tool=HOSTILE, cwd=HOSTILE),
                  rec(2, "pre", 1, session=HOSTILE, tool=HOSTILE, input_meta={"path": HOSTILE})])
    w.step()
    clock.t += 6
    w.step()
    w.scope = HOSTILE
    w.port = {"requested": 1, "used": 8765, "warning": HOSTILE}
    registry = watch.Registry(str(_home / ".raqib" / "watches.json"))
    registry.change(lambda rows, note: rows.append({"pid": HOSTILE, "project": HOSTILE, "port": HOSTILE,
                                                    "trace": HOSTILE, "state": HOSTILE, "started": HOSTILE,
                                                    "status": HOSTILE, "notes": [HOSTILE, 7]}))
    w.register(registry)
    inv = inventory()
    inv["candidates"][0].update(image=HOSTILE, cwd=HOSTILE, exe=HOSTILE, id=HOSTILE)
    inv["candidates"][0]["cites"][0]["text"] = HOSTILE
    inv["candidates"][0]["acts"] = [{"pid": HOSTILE, "how": "file-write", "path": HOSTILE, "cites": [
        {"src": HOSTILE, "line": HOSTILE, "text": HOSTILE}]}]
    inv["holes"].append(HOSTILE)
    inv["alarms"].append(HOSTILE)
    inv["result"] = HOSTILE
    write_discover(path.parent, inv)
    for page in (w.page(), w.discover_page()):
        assert_inert(page)
        # I-11: replaced by "?", not stripped: ESC, U+202E and NUL each leave a mark (A5).
        assert "?[2J?gpj.exe?end" in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img" in page
    crashed = dict(w.state(clock()), finished="x", status="crashed", error=HOSTILE)
    assert_inert(ui.render(*blocked_report(), refresh=5, live={"state": crashed, "watches": None, "own": None}))
    rep, numbered, problems = blocked_report()
    static = ui.render(rep, numbered, problems, band=[("alarm", HOSTILE)])
    assert_inert(static)


def test_e6_hostile_discover_cites_never_become_links(tmp_path):
    inv = {"candidates": [{"id": "C1", "pid": 1, "cites": [{"src": 'x" href="javascript:alert(1)', "line": 1,
                                                            "text": "<a href=javascript:alert(2)>"}]}],
           "holes": ['<a href="javascript:alert(3)">'], "result": "alarm", "exit": 1}
    path = write_discover(tmp_path, inv)
    tab = ui.discover_page(str(path), 5)
    assert_inert(tab) is None and "javascript:alert" in tab                     # shown as text only
    assert all(SAFE_HREF.fullmatch(h) for h in HREF.findall(tab))


# --- REDO 2: ADR-0005 Amendment J (docs/review/2026-11-03-M6.2-redo-ruling.md), each with a test -------------

def test_j2_a_start_time_failure_is_not_cleared_by_history_only_by_a_live_record(tmp_path):
    w, path, clock = make_watch(tmp_path)
    path.write_text("\n".join([rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1), rec(2, "post", 2)]) + "\n",
                    encoding="utf-8")
    w = watch.Watch(PROJECT, str(path), w.evaluate, RULES, 5, make_notifier(), out=io.StringIO(), err=io.StringIO(),
                    clock=clock, started=START, wall=lambda: START.timestamp() + clock.t - 1000.0)
    w.hooks_at_start(False, "settings.json: disableAllHooks is true", ["disabled"])
    w.step()                                                                     # three good records, all history
    assert w.history_line == 3 and w.status_word()[0] == "CAPTURE FAILED"
    assert "hooks disabled at start" in w.status_word()[2]
    append(path, [rec(3, "pre", 5)])                                             # a live good record
    clock.t += 1
    w.step()
    assert w.status_word()[0] == "WATCHING" and "capture recovered at seq 3 (line 4" in w.status_word()[2]


def test_j2_watch_of_an_existing_trace_with_disabled_hooks_stays_capture_failed(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.json").write_text('{"disableAllHooks": true}\n', encoding="utf-8")
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj))))
    trace_path.parent.mkdir(parents=True)
    trace_path.write_text("\n".join([rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1), rec(2, "post", 2)])
                          + "\n", encoding="utf-8")
    pages = []

    def look(server):
        pages.append(fetch("http://127.0.0.1:%d/" % server.server_address[1])[2])
    run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"],
              [look, lambda server: append(trace_path, [rec(3, "pre", 9)]), look])
    assert '<span class="badge state alarm">CAPTURE FAILED</span>' in pages[0]   # history did not clear it
    assert '<span class="badge state clean">WATCHING</span>' in pages[1] and "capture recovered at seq 3" in pages[1]


def test_j3_agent_gone_needs_no_open_session(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, gap=5, runner=runner)
    append(path, [rec(1, "session_start", 0, session="a", tool="-"), rec(1, "session_start", 0, session="b", tool="-"),
                  rec(2, "session_end", 1, session="a", tool="-")])
    w.step()
    assert w.agent_gone() is None and w.open_sessions() == ["b"]              # b is still open
    clock.t += 6
    w.step()
    assert w.status_word()[0] == "SILENT for 6 s"                               # silence is judged for b
    append(path, [rec(2, "session_end", 7, session="b", tool="-")])
    clock.t += 1
    w.step()
    assert w.windows[0]["closed_by_line"] == 4 and w.status_word()[0] == "AGENT GONE"
    assert "no session is open" in w.status_word()[2] and w.state(clock())["open_sessions"] == []


def test_j4_the_registry_is_not_written_when_it_is_inside_the_project(tmp_path, monkeypatch, _home):
    pages = []

    def look(server):
        pages.append(fetch("http://127.0.0.1:%d/" % server.server_address[1])[2])
    log = tmp_path / "elsewhere" / "t.jsonl"
    code, out = run_watch(monkeypatch, ["watch", _home, "--log", log, "--no-open", "--no-notify", "--port", "0"],
                          [look])
    registry = _home / ".raqib" / "watches.json"
    assert not registry.exists() and not Path(str(registry) + ".lock").exists()
    why = "the registry %s is inside the project %s: it is not written (A4" % (registry, os.path.normpath(str(_home)))
    assert why in out and ui._text("registry: " + why) in pages[0]               # a hole in the band
    st = json.loads(Path(str(log) + ".watch.json").read_text(encoding="ascii"))
    assert st["registry"]["row"] == "not written" and [h["kind"] for h in st["holes"]] == ["registry"]


def test_j5_heartbeats_are_wall_time_and_step_seconds_is_the_last_steps_length(tmp_path):
    clock = Clock()
    path = tmp_path / "traces" / "raqib.log.jsonl"
    path.parent.mkdir(parents=True)

    def slow(records):                                  # the rules take 2 s
        clock.t += 2.0
        return cli.run_rules(records, RULES, {}, 5)
    w = watch.Watch(PROJECT, str(path), slow, RULES, 5, make_notifier(), out=io.StringIO(), err=io.StringIO(),
                    clock=clock, started=START, wall=lambda: 1800000000.0)
    append(path, [rec(1, "session_start", 0, tool="-")])
    w.step()
    st = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert st["step_seconds"] == 2.0 and st["heartbeat"] == "2027-01-15T08:00:00.000Z"   # time.time(), not START
    assert st["updated"] == "2027-01-15T08:00:00.000Z" and st["started"] == "2026-11-02T12:00:00.000Z"


@pytest.mark.parametrize("step, age, alive", [(None, 1.4, True), (None, 1.6, False), (2.0, 5.9, True),
                                              (2.0, 6.1, False), (20.0, 29.0, True), (20.0, 31.0, False),
                                              (float("inf"), 29.0, True), (True, 1.6, False), ("9", 1.6, False)])
def test_j5_alive_threshold_is_max_1_5_and_3_steps_capped_at_30(tmp_path, step, age, alive):
    state = tmp_path / "t.watch.json"
    extra = {} if step is None else {"step_seconds": step}
    write_state(state, ui._iso(START - datetime.timedelta(seconds=age)), pid=1, started="s", **extra)
    row = ui.judge_row({"pid": 1, "trace": str(tmp_path / "t"), "started": "s", "port": 8800}, START, 1.5,
                       alive=lambda pid: True)
    assert row["alive"] is alive, row


def test_j6_watch_json_carries_band_and_other_pages_show_it(tmp_path):
    w, path, clock = make_watch(tmp_path, gap=5)
    append(path, [rec(1, "session_start", 0, tool="-")])
    w.step()
    clock.t += 6
    w.step()
    assert json.loads(Path(w.state_path).read_text(encoding="ascii"))["band"] == "SILENT for 6 s"
    other = tmp_path / "o.jsonl"
    write_state(str(other) + ".watch.json", ui._iso(START), pid=1, started="s", band="AGENT GONE")
    row = ui.judge_row({"pid": 1, "trace": str(other), "started": "s"}, START, 1.5, alive=lambda pid: True)
    assert row["word"] == "AGENT GONE"
    write_state(str(other) + ".watch.json", ui._iso(START), pid=1, started="s")           # no band: the status
    assert ui.judge_row({"pid": 1, "trace": str(other), "started": "s"}, START, 1.5,
                        alive=lambda pid: True)["word"] == "watching"


@pytest.mark.parametrize("trace", ["\\\\server\\share\\t", "//server/share/t", "\\/server/t", "relative/t", "",
                                   "/tmp/a\x00b", 7, None] + ([] if WINDOWS else ["C:\\x\\t"]))
def test_j7_only_a_local_absolute_non_unc_watch_json_is_opened(tmp_path, monkeypatch, trace):
    opened = []
    monkeypatch.setattr(ui, "read_json", lambda path, limit=None: opened.append(path) or (None, None, None))
    row = ui.judge_row({"pid": 1, "trace": trace, "started": "s"}, START, 1.5, alive=lambda pid: True)
    assert opened == [] and not row["alive"] and "is not opened" in row["why"] and "no network, J-7" in row["why"]


def test_j7_a_local_trace_opens_only_its_own_watch_json(tmp_path, monkeypatch):
    opened = []
    real = ui.read_json
    monkeypatch.setattr(ui, "read_json", lambda path, limit=None: opened.append(path) or real(path, limit))
    ui.judge_row({"pid": 1, "trace": str(tmp_path / "t"), "state": "\\\\evil\\share\\x", "started": "s"}, START,
                 1.5, alive=lambda pid: True)
    assert opened == [str(tmp_path / "t") + ".watch.json"]                      # never the row's "state" field


def test_j7_at_most_64_rows_the_newest_the_rest_counted(tmp_path):
    path = tmp_path / "watches.json"
    rows = [{"pid": 2 ** 31 - 1, "project": "/p%d" % n, "trace": "/t%d" % n, "started": "s"} for n in range(70)]
    path.write_text(json.dumps({"raqib_watches": 1, "watches": rows}), encoding="ascii")
    info = ui.read_watches(str(path), START, 1.5, alive=lambda pid: False)
    assert len(info["rows"]) == 64 and info["more"] == 6 and info["rows"][0]["project"] == "/p6"
    page = "\n".join(ui._watches_section(None, None, info))
    assert "6 older rows of the registry are not shown (at most 64 are, J-7)" in page


def test_j8_every_hole_kind_first_in_its_order():
    kinds = ["no-kind", "watch-crashed", "silence-window", "trace-truncated", "state-unwritable", "trace-problem",
             "trace-unreadable", "capture-failed", "trace-missing", "registry"]
    assert [a["kind"] for a in ui.alarm_order([{"kind": k} for k in kinds])] == [
        "capture-failed", "trace-missing", "trace-unreadable", "trace-truncated", "state-unwritable", "watch-crashed",
        "no-kind", "silence-window", "trace-problem", "registry"]


def test_j9_the_hook_detail_names_disabled_missing_or_foreign(tmp_path):
    from raqib import doctor, install
    empty = tmp_path / "empty"
    empty.mkdir()
    assert watch.hook_kinds(doctor, install, str(empty)) == ["missing"]
    off = tmp_path / "off"
    (off / ".claude").mkdir(parents=True)
    (off / ".claude" / "settings.json").write_text('{"disableAllHooks": true}\n', encoding="utf-8")
    assert watch.hook_kinds(doctor, install, str(off))[0] == "disabled"
    other = tmp_path / "foreign"
    other.mkdir()
    install.install_project(str(other), log=str(tmp_path / "t.jsonl"), out=io.StringIO())
    settings = other / ".claude" / "settings.json"
    data = json.loads(settings.read_text(encoding="utf-8"))
    capture = install.capture_path()
    for groups in data["hooks"].values():
        for group in groups:
            for hook in group["hooks"]:
                hook["command"] = hook["command"].replace(capture, capture.replace("hooks", "hooks-of-another"))
    settings.write_text(json.dumps(data), encoding="utf-8")
    assert watch.hook_kinds(doctor, install, str(other)) == ["foreign"]
    w, _, _ = make_watch(tmp_path)
    w.hooks_at_start(False, "x", ["disabled", "missing"])
    assert w.status_word()[2].startswith("hooks disabled/missing at start: x")


def test_j11_a_dangling_discover_json_link_is_an_alarm_on_the_tab(tmp_path):
    w, path, clock = make_watch(tmp_path)
    try:
        os.symlink(str(tmp_path / "nowhere.json"), str(path.parent / "discover.json"))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not permitted here")
    tab = w.discover_page()
    assert '<span class="badge alarm">ALARM</span>' in tab and "it is a link to nothing" in tab
    assert 'href="/discover"' in w.page()


def test_j12_last_line_of_a_line_that_is_not_a_record(tmp_path):
    w, path, clock = make_watch(tmp_path)
    append(path, [rec(1, "session_start", 0, tool="-"), "{torn"])
    w.step()
    assert "last line 2 (seq None): record ts - (not a record), read at 2026-11-02T12:00:00.000Z" in w.page()


def test_j13_crashed_is_a_word_for_other_rows_and_rules_that_did_not_run_are_alarms(tmp_path):
    other = tmp_path / "o.jsonl"
    for status, age, word in (("crashed", 0, "CRASHED"), ("watching", 60, "CRASHED"), ("finished", 60, "FINISHED")):
        write_state(str(other) + ".watch.json", ui._iso(START - datetime.timedelta(seconds=age)), status=status,
                    pid=1, started="s", band="WATCHING")
        row = ui.judge_row({"pid": 1, "trace": str(other), "started": "s"}, START, 1.5, alive=lambda pid: True)
        assert row["word"] == word, (status, row)
    w, path, clock = make_watch(tmp_path)
    w.step()
    clock.t += watch.STALE_SECONDS + 1
    assert w.status_word()[0] == "CAPTURE FAILED"                               # never CRASHED in its own band
    rep, numbered, problems = blocked_report()
    page = ui.render(rep, numbered, problems)
    assert page.index("<h2>Alarms") < page.index("<h3>Rules that did not run") < page.index("<h2>Findings")


def test_j13_write_state_retries_three_times_50_ms_apart(tmp_path, monkeypatch):
    w, path, clock = make_watch(tmp_path)
    real, calls, waits = os.replace, [], []

    def flaky(src, dst, fail=2):
        calls.append(dst)
        if len(calls) <= flaky.fail:
            raise PermissionError(13, "in use by a reader")
        return real(src, dst)
    flaky.fail = 2
    monkeypatch.setattr(os, "replace", flaky)
    monkeypatch.setattr(watch, "_retry_sleep", waits.append)
    w.step()
    assert w.state_error is None and len(calls) == 3 and waits == [0.05, 0.05] and Path(w.state_path).exists()
    calls.clear(), waits.clear()
    flaky.fail = 99
    w.step()
    assert len(calls) == 4 and waits == [0.05] * 3 and "in use by a reader" in w.state_error
    assert not list(Path(w.state_path).parent.glob(".raqib-watch-*"))           # no temp file left behind


# --- J-14: the tests the review asked for ---------------------------------------------------------------------

def test_j14_unregister_restores_a_row_that_was_removed(tmp_path, _home):
    path = _home / ".raqib" / "watches.json"
    w, _, _ = make_watch(tmp_path)
    w.register(watch.Registry(str(path)))
    path.write_text('{"raqib_watches": 1, "watches": []}', encoding="ascii")    # someone removed the row
    w.finish()
    assert w.unregister() is None
    (row,) = registry_rows(_home)
    assert row["status"] == "finished" and row["notes"] == ["this row was not in the registry at the end: added again"]


def test_j14_the_registry_write_retries_while_a_reader_holds_it(tmp_path, monkeypatch, _home):
    path = _home / ".raqib" / "watches.json"
    real, calls = os.replace, []

    def flaky(src, dst):
        calls.append(dst)
        if len(calls) == 1:
            raise PermissionError(13, "in use")
        return real(src, dst)
    waits = []
    registry = watch.Registry(str(path), sleep=waits.append)
    monkeypatch.setattr(os, "replace", flaky)
    assert registry.change(lambda rows, note: rows.append({"pid": 1})) == (None, None)
    assert len(calls) == 2 and waits == [watch.LOCK_POLL_SECONDS] and registry.read()[0]["watches"] == [{"pid": 1}]


def test_j14_a_hook_check_that_throws_is_capture_failed(tmp_path, monkeypatch):
    from raqib import doctor
    proj = tmp_path / "proj"
    proj.mkdir()

    def boom(*a, **k):
        raise RuntimeError("settings exploded")
    monkeypatch.setattr(doctor, "check_hooks", boom)
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"])
    st = json.loads(Path(watch.default_trace(os.path.normpath(str(proj))) + ".watch.json").read_text(encoding="ascii"))
    assert st["capture"]["hooks"] == {"ok": False, "detail": "the hook check failed: RuntimeError: settings exploded",
                                      "kinds": ["unchecked"]}
    assert "RAQIB-SILENCE: hooks unchecked at start: the hook check failed: RuntimeError" in out
    assert st["band"] == "FINISHED" and st["capture"]["start"]["why"].startswith("hooks unchecked at start")


def test_j14_a_closed_window_whose_line_is_not_in_this_view(tmp_path):
    w, path, clock = make_watch(tmp_path)
    append(path, [rec(1, "session_start", 0, tool="-")])
    w.step()
    state = dict(w.state(clock()), silence=[{"epoch": 0, "since": "a", "closed": "b", "seconds": 3.0, "after": "x",
                                              "closed_by_line": 99}])
    rep, numbered, problems = w.report()
    page = ui.render(rep, numbered, problems, 5, refresh=5, live={"state": state, "watches": None, "own": None})
    assert "closed by line 99 (that line is not in this view)" in page


def test_j14_ui_serve_shows_discover_as_a_section(tmp_path, monkeypatch):
    local = tmp_path / "t" / "trace.jsonl"
    local.parent.mkdir()
    local.write_bytes(BLOCKED.read_bytes())
    write_discover(local.parent)
    served = []

    class FakeServer:
        server_address = ("127.0.0.1", 4321)

        def __init__(self, page):
            self.page = page

        def serve_forever(self):
            served.append(self.page())
            raise KeyboardInterrupt

        def server_close(self):
            pass
    monkeypatch.setattr(ui, "make_server", lambda page, port, **kw: FakeServer(page))
    assert cli.main(["ui", str(local), "--serve", "--port", "0"], out=io.StringIO()) == 0
    assert '<h2 id="discover">Discover</h2>' in served[0] and '<a href="#discover">discover</a>' in served[0]
    assert '<meta http-equiv="refresh" content="5">' in served[0]


def test_j14_nested_objects_in_registry_fields_are_text(tmp_path, _home):
    path = _home / ".raqib" / "watches.json"
    nested = {"a": [1, {"b": "<script>x</script>" + chr(0x202E)}], "c": None}
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"raqib_watches": 1, "watches": [
        {"pid": [1], "project": nested, "port": {"p": 8765}, "trace": nested, "started": nested, "status": nested,
         "notes": [nested, "ok note"]}]}), encoding="ascii")
    w, _, _ = make_watch(tmp_path)
    w.registry = watch.Registry(str(path))
    page = w.page()
    assert_inert(page)
    assert "&lt;script&gt;x&lt;/script&gt;?" in page and "note: ok note" in page and "pid [1] is not a process number" \
        in page
