"""M3.1 read-only web view: exit criteria E1-E4 (HANDOFF.md)."""
import io
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, report, ui  # noqa: E402
from raqib.rules import engine, silence, trace  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
BLOCKED = FIXTURES / "blocked-calls-claude-code-2.1.301.log"
FILE_TOOLS = FIXTURES / "file-tools-d7841d1-claude-code-2.1.301.log"
CATALOG = ROOT / "raqib" / "rules" / "catalog"


def raqib(*argv):
    out = io.StringIO()
    code = cli.main(list(map(str, argv)), out=out)
    return code, out.getvalue()


def page_for(path, suspicion=None, gap=silence.DEFAULT_GAP_SECONDS, context=None):
    numbered, problems = trace.read_numbered(path)
    records = [r for _, r in numbered]
    rules = engine.load_catalog(CATALOG)
    found = report.with_silence_class(silence.findings(records, gap))
    more, notes = engine.evaluate(rules, records, context or {})
    rep = report.build(str(path), numbered, problems, found + more, notes, report.rule_table(rules),
                       "rules", suspicion)
    return ui.render(rep, numbered, problems, gap), rep


def line(seq, phase, ts, session="s-ui", tool="Bash", **extra):
    rec = {"ts": ts, "seq": seq, "session_id": session, "phase": phase, "tool": tool, "cwd": "/work/app"}
    if phase in ("pre", "post"):
        rec.update(input_sha256="0" * 64, input_meta=extra.pop("input_meta", {"command_head": "ls"}))
    if phase == "post":
        rec.update(output_sha256="1" * 64, output_meta={"scan": "full", "secret_kinds": []}, ok=True)
    rec.update(extra)
    return json.dumps(rec)


def write_trace(tmp_path, rows):
    path = tmp_path / "trace.jsonl"
    path.write_text("\n".join(rows) + "\n")
    return path


# --- E1: one self-contained page with everything the report has ------------

def test_e1_page_of_the_real_blocked_calls_trace():
    page, rep = page_for(BLOCKED)
    assert page.startswith("<!doctype html>") and page.rstrip().endswith("</html>")
    assert 'class="badge alarm">ALARM' in page
    assert page.count('class="card"') == 2 and "SILENCE-HALF (SILENCE)" in page
    assert '<a href="#L2">line 2</a>' in page and '<a href="#L3">line 3</a>' in page
    assert all('<tr id="L%d"' % n in page for n in range(1, 8))
    assert "DRIFT-FILES</code> not-evaluated" in page and "SECRET-OUTPUT</code> partial" in page
    assert page.count("<tr><td>") == len(rep["rules"]) == 11


def test_e1_suspicion_lines_and_their_citations():
    susp = [{"kind": "suspicion", "session_id": "b3744113-5956-4e40-915a-91c245a2ece7", "window": [1, 6],
             "suspicion": 0.8, "reasons": ["two calls outside the project"], "cited_seq": [2, 3],
             "backend": "fake", "model": "canned", "ts": "2026-10-16T20:49:42.081Z"}]
    page, _ = page_for(BLOCKED, suspicion=susp)
    assert "Suspicion (1)" in page and "two calls outside the project" in page and "0.80" in page
    row = re.search(r'<tr id="L2".*?</tr>', page).group(0)
    assert "suspicion" in row and "SILENCE-HALF" in row


def test_e1_clean_page_and_post_fields():
    page, rep = page_for(FILE_TOOLS, context={"scope": ["."], "root": "/"})
    assert rep["result"] == "clean" and 'class="badge clean">CLEAN' in page
    assert "Findings (0)" in page and "Every rule ran on every line." in page
    assert "false failure" in page  # the failed Read: ok false, error_class failure
    assert "&quot;scan&quot;: &quot;full&quot;" in page


# --- E2: silence is drawn into the timeline --------------------------------

def test_e2_gap_half_open_and_corrupt_lines_are_bands(tmp_path):
    path = write_trace(tmp_path, [
        line(1, "session_start", "2026-10-16T10:00:00.000Z"),
        line(2, "pre", "2026-10-16T10:00:01.000Z"),
        line(2, "post", "2026-10-16T10:00:02.000Z"),
        "{not json",
        line(3, "pre", "2026-10-16T10:05:00.000Z"),
        line(4, "post", "2026-10-16T10:05:01.000Z"),
        line(1, "session_start", "2026-10-16T10:00:00.000Z", session="s-two"),
        line(2, "stop", "2026-10-16T10:00:03.000Z", session="s-two"),
    ])
    page, rep = page_for(path)
    bands = re.findall(r'<tr class="band"[^>]*><td colspan="10">(.*?)</td></tr>', page)
    assert bands == ["line 4 is corrupt: not JSON",
                     "session s-ui: no capture for 298.0s (limit 60s)",
                     "session s-ui: the trace ends at seq 4 without stop or session_end"]
    assert '<tr class="band" id="L4">' in page and '<a href="#L4">line 4</a>' in page
    row3 = re.search(r'<tr id="L5".*?</tr>', page).group(0)
    row4 = re.search(r'<tr id="L6".*?</tr>', page).group(0)
    assert "no post" in row3 and "SILENCE-HALF" in row3
    assert "no pre" in row4 and "SILENCE-OPEN" in row4
    assert page.index("298.0s") < page.index('<tr id="L5"')
    assert page.index('<tr id="L6"') < page.index("ends at seq 4") < page.index('<tr id="L7"')


def test_e2_the_gap_limit_follows_gap_seconds(tmp_path):
    path = write_trace(tmp_path, [line(1, "session_start", "2026-10-16T10:00:00.000Z"),
                                  line(2, "stop", "2026-10-16T10:03:00.000Z")])
    assert "no capture for 180.0s" in page_for(path)[0]
    assert "no capture for 180.0s" not in page_for(path, gap=600)[0]


def test_e2_an_empty_trace_is_an_alarm_page(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    page, _ = page_for(path)
    assert "ALARM" in page and "empty-trace" in page and "Timeline (0 lines)" in page


# --- E3: read-only and safe ------------------------------------------------

HOSTILE = '<script>alert(1)</script>"><img src=x onerror=alert(2)>' + chr(0x202E) + "gpj.exe\n"


def hostile_page(tmp_path):
    path = write_trace(tmp_path, [
        line(1, "session_start", "2026-10-16T10:00:00.000Z", session="<b>s</b>"),
        line(2, "pre", "2026-10-16T10:00:01.000Z", session="<b>s</b>", tool="Read",
             input_meta={"path": "/etc/" + HOSTILE}),
        line(2, "post", "2026-10-16T10:00:02.000Z", session="<b>s</b>", tool="Read",
             input_meta={"path": "/etc/" + HOSTILE}),
        line(3, "stop", "2026-10-16T10:00:03.000Z", session="<b>s</b>"),
    ])
    return page_for(path)


def test_e3_trace_values_are_escaped_and_printable(tmp_path):
    page, rep = hostile_page(tmp_path)
    assert rep["findings"] and "SCOPE-PATH" in page  # the hostile path is cited
    low = page.lower()
    assert "<script" not in low and "<img" not in low and "<b>" not in low
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "&lt;b&gt;s&lt;/b&gt;" in page
    assert chr(0x202E) not in page
    assert all(c == "\n" or c.isprintable() for c in page)


def test_e3_no_script_and_nothing_loaded(tmp_path):
    page, _ = hostile_page(tmp_path)
    assert '<meta http-equiv="Content-Security-Policy" content="default-src \'none\';' in page
    tags = re.findall(r"<[a-zA-Z][^>]*>", page)  # values are escaped, so these are the page's own
    assert {t.split()[0].strip("<>").lower() for t in tags} <= {
        "html", "head", "meta", "title", "style", "body", "main", "h1", "h2", "p", "span", "div",
        "ul", "li", "a", "code", "table", "thead", "tbody", "tr", "th", "td"}
    assert not [t for t in tags if re.search(r"\s(?:src|action|srcset|on[a-z]+)\s*=", t)]
    assert {h[0] for h in re.findall(r'href="(.)', page)} <= {"#"}
    assert "@import" not in page and "url(" not in page


def test_e3_long_values_are_bounded(tmp_path):
    path = write_trace(tmp_path, [line(1, "pre", "2026-10-16T10:00:01.000Z", tool="Read",
                                       input_meta={"path": "/work/app/" + "a" * 5000 + "/end"})])
    page, _ = page_for(path)
    assert "a" * (ui.CELL_MAX + 1) not in page and "/end" in page


@pytest.fixture
def server():
    calls = []

    def page():
        calls.append(1)
        return "<!doctype html><p>ok</p>"
    srv = ui.make_server(page, 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, calls
    srv.shutdown()
    srv.server_close()


def request(srv, method="GET", path="/", host=None):
    port = srv.server_address[1]
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), method=method)
    if host:
        req.add_header("Host", host)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), b""


def test_e3_serve_binds_localhost_and_answers_get_and_head(server):
    srv, calls = server
    assert srv.server_address[0] == "127.0.0.1"
    status, headers, body = request(srv)
    assert (status, body) == (200, b"<!doctype html><p>ok</p>")
    assert headers["Content-Security-Policy"] == ui.CSP and headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"
    status, _, body = request(srv, "HEAD")
    assert (status, body) == (200, b"")
    assert len(calls) == 2  # the page is rebuilt from the trace on every request


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def test_e3_serve_refuses_writes(server, method):
    status, headers, _ = request(server[0], method)
    assert status == 405 and headers["Allow"] == "GET, HEAD"
    assert server[1] == []


def test_e3_serve_refuses_other_paths_and_foreign_hosts(server):
    srv, calls = server
    assert request(srv, path="/etc/passwd")[0] == 404
    assert request(srv, host="evil.example:%d" % srv.server_address[1])[0] == 403
    assert request(srv, host="localhost:%d" % srv.server_address[1])[0] == 200
    assert calls == [1]


# --- E4: the CLI -----------------------------------------------------------

def test_e4_cli_writes_the_page_and_exits_like_report(tmp_path):
    out = tmp_path / "view.html"
    code, text = raqib("ui", BLOCKED, "-o", out)
    assert code == 1 and "(alarm)" in text
    assert out.read_text().startswith("<!doctype html>")
    assert raqib("report", BLOCKED)[0] == code
    code, text = raqib("ui", FILE_TOOLS)
    assert code == 3 and text.startswith("<!doctype html>")
    code, _ = raqib("ui", FILE_TOOLS, "--scope", ".", "--root", "/")
    assert code == 0


def test_e4_cli_serve(monkeypatch):
    served = {}

    class FakeServer:
        server_address = ("127.0.0.1", 4321)

        def serve_forever(self):
            served["page"] = served["make"]()
            raise KeyboardInterrupt

        def server_close(self):
            served["closed"] = True

    def make(page, port):
        served["make"], served["port"] = page, port
        return FakeServer()
    monkeypatch.setattr(ui, "make_server", make)
    code, text = raqib("ui", BLOCKED, "--serve", "--port", "0")
    assert code == 0 and "http://127.0.0.1:4321/" in text
    assert served["port"] == 0 and served["closed"] and "SILENCE-HALF" in served["page"]


@pytest.mark.parametrize("argv", [
    ["ui", BLOCKED, "--serve", "-o", "x.html"],
    ["ui", FIXTURES / "missing.log"],
    ["ui", BLOCKED, "--serve", "--port", "70000"],
], ids=["serve-and-out", "missing-trace", "bad-port"])
def test_e4_cli_usage_errors(argv):
    assert raqib(*argv)[0] == 2


def test_e4_render_is_pure():
    numbered, problems = trace.read_numbered(BLOCKED)
    _, rep = page_for(BLOCKED)
    before = json.dumps([numbered, problems, rep], sort_keys=True)
    ui.render(rep, numbered, problems)
    assert json.dumps([numbered, problems, rep], sort_keys=True) == before
