"""Read-only web view (M3.1): one static HTML page for one trace.

The page shows the result, the alarms, every finding with the trace lines it
cites (A5), the rules that did not run (A3), the suspicion lines, the rule
table (A6) and a timeline of every trace line in file order. Silence is drawn
into the timeline (A3): a band where a session went quiet for longer than
the gap limit, a "no post" mark on a pre that never completed (and the
reverse), a band where a started session ends without stop or session_end,
and a row for every corrupt line.

Safe by construction: the page has no script and loads nothing (a
Content-Security-Policy forbids both), and every value taken from the trace
is escaped and stripped of non-printable characters, because the watched
agent controls paths and other trace fields. serve() binds 127.0.0.1 only,
answers GET and HEAD, refuses a Host header that is not local, and never
writes (A4).
"""
from __future__ import annotations

import html
import json
import http.server

from raqib.rules import silence, trace

CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")
CELL_MAX = 400
RESULT_TEXT = {"alarm": "ALARM", "incomplete": "INCOMPLETE", "clean": "CLEAN"}

STYLE = """
:root { --bg: #ffffff; --fg: #1d1f21; --muted: #5f6368; --line: #d9dce0; --panel: #f6f7f9;
  --alarm: #b3261e; --alarm-bg: #fce8e6; --warn: #8a5a00; --warn-bg: #fef3d6;
  --ok: #1e6b34; --ok-bg: #e6f4ea; --flag-bg: #fff4e5; --band-bg: #fde7e9; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #15171a; --fg: #e3e5e8; --muted: #9aa0a6; --line: #33373c; --panel: #1e2125;
    --alarm: #f28b82; --alarm-bg: #3c1d1b; --warn: #fdd663; --warn-bg: #3a3016;
    --ok: #81c995; --ok-bg: #1b3324; --flag-bg: #33291a; --band-bg: #3a1e22; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 16px; background: var(--bg); color: var(--fg);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1200px; margin: 0 auto; }
h1 { font-size: 20px; margin: 0 0 4px; } h2 { font-size: 16px; margin: 28px 0 8px; }
code, td, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
.meta { color: var(--muted); overflow-wrap: anywhere; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-weight: 600; }
.alarm { color: var(--alarm); background: var(--alarm-bg); }
.incomplete { color: var(--warn); background: var(--warn-bg); }
.clean { color: var(--ok); background: var(--ok-bg); }
.card { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; margin: 8px 0;
  background: var(--panel); overflow-wrap: anywhere; }
.card .head { font-weight: 600; } .card ul { margin: 6px 0 0; padding-left: 18px; }
.empty { color: var(--muted); }
.scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--panel); position: sticky; top: 0; font-weight: 600; }
td.wrap { overflow-wrap: anywhere; min-width: 16ch; }
td.nowrap { white-space: nowrap; }
tr.flag td { background: var(--flag-bg); }
tr.band td { background: var(--band-bg); color: var(--alarm); font-weight: 600; }
tr:target td { outline: 2px solid var(--alarm); outline-offset: -2px; }
.tag { display: inline-block; padding: 0 6px; margin: 1px 2px 1px 0; border-radius: 4px; font-size: 11.5px;
  background: var(--alarm-bg); color: var(--alarm); white-space: nowrap; }
a { color: inherit; }
"""


def _text(value):
    """Escaped, printable, bounded text for any value from the trace."""
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False)
    text = "".join(c if c.isprintable() else "?" for c in text)
    if len(text) > CELL_MAX:
        keep = CELL_MAX - 3
        text = text[:keep // 2] + "..." + text[-(keep - keep // 2):]
    return html.escape(text, quote=True)


def _anchor(line):
    return "L%d" % line


def _timeline(numbered, problems, report, gap_seconds):
    """Rows of the timeline: trace lines, corrupt lines and silence bands."""
    marks = {}
    for f in report["findings"]:
        for seq in f["cited_seq"]:
            marks.setdefault((f["session_id"], seq), set()).add(f["rule_id"])
    for s in report["suspicion"]:
        for seq in s["cited_seq"]:
            marks.setdefault((s["session_id"], seq), set()).add("suspicion")
    counts = {}
    for _, rec in numbered:
        if rec.get("phase") in ("pre", "post"):
            entry = counts.setdefault((rec["session_id"], rec["seq"]), [0, 0])
            entry[0 if rec["phase"] == "pre" else 1] += 1
    last_seen = {}
    last_line = {}
    started = set()
    rows = []
    items = [(number, "rec", rec) for number, rec in numbered]
    items += [(p["line"], "problem", p) for p in problems]
    for number, kind, item in sorted(items, key=lambda x: x[0]):
        if kind == "problem":
            rows.append(("band", number, "line %d is corrupt: %s" % (number, item["reason"])))
            continue
        rec = item
        sid = rec["session_id"]
        t = trace.parse_ts(rec.get("ts"))
        if t is not None and sid in last_seen:
            gap = (t - last_seen[sid]).total_seconds()
            if gap > gap_seconds:
                rows.append(("band", None, "session %s: no capture for %.1fs (limit %gs)"
                             % (sid, gap, gap_seconds)))
        if t is not None:
            last_seen[sid] = t
        if rec.get("phase") == "session_start":
            started.add(sid)
        tags = sorted(marks.get((sid, rec["seq"]), ()))
        pres, posts = counts.get((sid, rec["seq"]), (0, 0))
        if rec.get("phase") == "pre" and pres > posts:
            tags.append("no post")
        if rec.get("phase") == "post" and posts > pres:
            tags.append("no pre")
        rows.append(("rec", number, rec, tags))
        last_line[sid] = (len(rows), rec)
    for sid, (position, rec) in sorted(last_line.items(), key=lambda x: x[1][0], reverse=True):
        if sid in started and rec.get("phase") not in silence.CLOSING:
            rows.insert(position, ("band", None, "session %s: the trace ends at seq %s without stop or"
                                                 " session_end" % (sid, rec["seq"])))
    return rows


def render(report, numbered, problems, gap_seconds=silence.DEFAULT_GAP_SECONDS):
    """The whole page as a string."""
    lines_by_seq = {}
    for number, rec in numbered:
        lines_by_seq.setdefault((rec["session_id"], rec["seq"]), []).append(number)
    out = ["<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           '<meta http-equiv="Content-Security-Policy" content="%s">' % CSP,
           '<meta name="referrer" content="no-referrer">',
           "<title>Raqib trace view</title>", "<style>%s</style>" % STYLE, "</head>", "<body><main>"]
    result = report["result"]
    out.append("<h1>Raqib trace view</h1>")
    out.append('<p class="meta">%s &middot; %d records &middot; %d sessions &middot; findings: %s</p>'
               % (_text(report["trace"]), report["records"], len(report["sessions"]),
                  _text(report["findings_source"])))
    out.append('<p><span class="badge %s">%s</span> <span class="meta">exit %d</span></p>'
               % (result, RESULT_TEXT[result], report["exit"]))

    out.append("<h2>Alarms (%d)</h2>" % len(report["alarms"]))
    if report["alarms"]:
        for a in report["alarms"]:
            where = ' <a href="#%s">line %d</a>' % (_anchor(a["line"]), a["line"]) if "line" in a else ""
            out.append('<div class="card"><span class="tag">%s</span>%s %s</div>'
                       % (_text(a["kind"]), where, _text(a["detail"])))
    else:
        out.append('<p class="empty">None.</p>')

    def cited(item):
        parts = []
        for cite in item["cites"]:
            for line in cite["lines"]:
                parts.append('<li><a href="#%s">line %d</a> <code>%s</code></li>'
                             % (_anchor(line["line"]), line["line"], _text(line["text"])))
            if not cite["lines"]:
                parts.append("<li>seq %d: <span class=\"tag\">no line in the trace</span></li>" % cite["seq"])
        return "<ul>%s</ul>" % "".join(parts)

    out.append("<h2>Findings (%d)</h2>" % len(report["findings"]))
    if report["findings"]:
        for f in report["findings"]:
            out.append('<div class="card"><div class="head"><span class="tag">%s</span> %s (%s) '
                       '<span class="meta">session %s, seq %s</span></div><div>%s</div>%s</div>'
                       % (_text(f["severity"]), _text(f["rule_id"]), _text(f.get("class", "-")),
                          _text(f["session_id"]), _text(", ".join(map(str, f["cited_seq"]))),
                          _text(f["summary"]), cited(f)))
    else:
        out.append('<p class="empty">None.</p>')

    out.append("<h2>Suspicion (%d)</h2>" % len(report["suspicion"]))
    out.append('<p class="meta">A model can raise suspicion; it can never clear anything (A2).</p>')
    for s in report["suspicion"]:
        out.append('<div class="card"><div class="head"><span class="tag">%s</span> %s/%s '
                   '<span class="meta">session %s, window seq %s to %s</span></div><ul>%s</ul>%s</div>'
                   % (_text("%.2f" % s["suspicion"]), _text(s.get("backend")), _text(s.get("model")),
                      _text(s["session_id"]), _text(s["window"][0]), _text(s["window"][1]),
                      "".join("<li>%s</li>" % _text(r) for r in s["reasons"]), cited(s)))

    out.append("<h2>Rules that did not run (%d)</h2>" % len(report["notes"]))
    if report["notes"]:
        out.append("<ul>%s</ul>" % "".join(
            "<li><code>%s</code> %s: %s</li>" % (_text(n["rule_id"]), _text(n["status"]), _text(n["detail"]))
            for n in report["notes"]))
    else:
        out.append('<p class="empty">Every rule ran on every line.</p>')

    out.append("<h2>Timeline (%d lines)</h2>" % (len(numbered) + len(problems)))
    out.append('<p class="meta">Red bands are silence: no capture for longer than %gs, a session that '
               'never closed, or a corrupt line. Highlighted rows are cited by a finding.</p>' % gap_seconds)
    out.append('<div class="scroll"><table><thead><tr><th>line</th><th>ts</th><th>session</th><th>seq</th>'
               "<th>phase</th><th>tool</th><th>input_meta</th><th>output_meta</th><th>ok</th>"
               "<th>marks</th></tr></thead><tbody>")
    for row in _timeline(numbered, problems, report, gap_seconds):
        if row[0] == "band":
            anchor = ' id="%s"' % _anchor(row[1]) if row[1] is not None else ""
            out.append('<tr class="band"%s><td colspan="10">%s</td></tr>' % (anchor, _text(row[2])))
            continue
        _, number, rec, tags = row
        ok = rec.get("ok")
        ok_text = "" if ok is None else ("true" if ok else "false " + str(rec.get("error_class", "")))
        out.append('<tr id="%s"%s><td>%d</td><td class="nowrap">%s</td><td class="wrap">%s</td><td>%s</td><td>%s</td>'
                   '<td>%s</td><td class="wrap">%s</td><td class="wrap">%s</td><td>%s</td><td>%s</td></tr>'
                   % (_anchor(number), ' class="flag"' if tags else "", number, _text(rec.get("ts", "-")),
                      _text(rec["session_id"]), _text(rec["seq"]), _text(rec.get("phase", "?")),
                      _text(rec.get("tool", "?")), _text(rec["input_meta"]) if rec.get("input_meta") else "",
                      _text(rec["output_meta"]) if rec.get("output_meta") else "", _text(ok_text),
                      "".join('<span class="tag">%s</span>' % _text(t) for t in tags)))
    out.append("</tbody></table></div>")

    out.append("<h2>Rules (%d)</h2>" % len(report["rules"]))
    out.append('<div class="scroll"><table><thead><tr><th>id</th><th>class</th><th>severity</th>'
               "<th>fp_budget</th><th>status</th><th>title</th></tr></thead><tbody>")
    for r in report["rules"]:
        out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"wrap\">%s</td></tr>"
                   % (_text(r["id"]), _text(r["class"]), _text(r["severity"]),
                      "-" if r["fp_budget"] is None else _text("%g" % r["fp_budget"]),
                      _text(r["status"]), _text(r["title"])))
    out.append("</tbody></table></div>")
    out.append('<p class="meta">Raqib: deterministic rules first; a model may raise suspicion, never acquit. '
               "This page is read-only and runs no script.</p>")
    out.append("</main></body></html>")
    return "\n".join(out) + "\n"


class _Handler(http.server.BaseHTTPRequestHandler):
    page = None  # a callable returning the page text
    port = None

    def _local_host(self):
        host = self.headers.get("Host", "")
        return host in ("127.0.0.1:%d" % self.port, "localhost:%d" % self.port)

    def _send(self, body_wanted):
        if not self._local_host():
            self.send_error(403, "Host must be 127.0.0.1 or localhost")
            return
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        body = self.page().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body_wanted:
            self.wfile.write(body)

    def do_GET(self):
        self._send(True)

    def do_HEAD(self):
        self._send(False)

    def _refuse(self):
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _refuse

    def log_message(self, format, *args):
        pass


def make_server(page, port=0):
    """An HTTP server on 127.0.0.1 that serves page() at / (port 0: any free port)."""
    handler = type("Handler", (_Handler,), {"page": staticmethod(page)})
    server = http.server.HTTPServer(("127.0.0.1", port), handler)
    handler.port = server.server_address[1]
    return server
