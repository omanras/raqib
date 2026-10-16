"""Report (M1.3): findings with the trace lines they cite (A5), every rule with
its fp_budget (A6), and every alarm or gap (A3). Pure: build() takes data and
returns a dict; render_text() turns it into text. The CLI does the I/O.

Result:
- "alarm"      (exit 1) any finding, an empty trace, a corrupt trace line, a
               rejected finding, or a citation with no line in the trace;
- "incomplete" (exit 3) no alarm, but some rule did not run, or it is unknown
               which rules ran;
- "clean"      (exit 0) none of the above.
"""
from __future__ import annotations

import json

from raqib.rules import engine

SILENCE_RULES = (
    ("SILENCE-GAP", "consecutive lines of a session more than RAQIB_GAP_SECONDS apart"),
    ("SILENCE-OPEN", "a started session whose last line is not a stop or session_end"),
    ("SILENCE-HALF", "a seq with more pre than post lines, or the reverse"),
    ("SILENCE-ORDER", "seq or ts going back: trace truncated, rotated or merged"),
)
EXIT = {"clean": 0, "alarm": 1, "incomplete": 3}
LINE_TEXT_MAX = 240


def rule_table(rules):
    """[{id, class, severity, fp_budget, status, title}] for the silence rules
    (Python, no declared budget yet) and the catalog rules."""
    table = [{"id": rid, "class": "SILENCE", "severity": "high", "fp_budget": None,
              "status": "active", "title": title} for rid, title in SILENCE_RULES]
    table += [{"id": r.id, "class": r.cls, "severity": r.severity, "fp_budget": r.fp_budget,
               "status": r.status, "title": r.title} for r in rules]
    return table


def with_silence_class(findings):
    """Silence findings carry class SILENCE like catalog findings carry theirs."""
    return [dict(f, **{"class": "SILENCE"}) if "class" not in f else dict(f) for f in findings]


def describe(rec):
    """One-line, bounded rendering of a trace record (hashes left out)."""
    parts = ["%s %s seq %s" % (rec.get("phase", "?"), rec.get("tool", "?"), rec.get("seq")),
             str(rec.get("ts", "-"))]
    for key in ("ok", "error_class"):
        if key in rec:
            parts.append("%s=%s" % (key, json.dumps(rec[key])))
    for key in ("input_meta", "output_meta"):
        if rec.get(key):
            parts.append("%s=%s" % (key, json.dumps(rec[key], sort_keys=True)))
    text = "  ".join(parts)
    text = "".join(c if c.isprintable() else "?" for c in text)
    if len(text) > LINE_TEXT_MAX:
        text = text[:LINE_TEXT_MAX - 3] + "..."
    return text


def build(trace_path, numbered, problems, findings, notes, rules, findings_source):
    """numbered: [(line number, record)]; problems: trace.parse problems;
    findings: dicts (from the engine or a findings file); notes: rule notes,
    or None when it is unknown which rules ran; rules: rule_table()."""
    index = {}
    sessions = []
    for number, rec in numbered:
        index.setdefault((rec["session_id"], rec["seq"]), []).append((number, rec))
        if rec["session_id"] not in sessions:
            sessions.append(rec["session_id"])
    alarms = []
    if not numbered:
        alarms.append({"kind": "empty-trace",
                       "detail": "the trace has no records; silence is an alarm (A3)"})
    for p in problems:
        alarms.append({"kind": "trace-problem", "line": p["line"], "detail": p["reason"]})
    items = []
    for f in findings:
        try:
            engine.check_finding(f)
        except engine.FindingError as exc:
            alarms.append({"kind": "rejected-finding", "detail": str(exc)})
            continue
        cites = []
        for seq in f["cited_seq"]:
            lines = index.get((f["session_id"], seq), [])
            if not lines:
                alarms.append({"kind": "missing-citation",
                               "detail": "%s cites session %s seq %d, which has no line in the trace"
                                         % (f["rule_id"], f["session_id"], seq)})
            cites.append({"seq": seq, "lines": [{"line": n, "text": describe(r)} for n, r in lines]})
        items.append(dict(f, cites=cites))
    if notes is None:
        notes = [{"rule_id": "*", "status": "unknown",
                  "detail": "no rule notes next to the findings file; which rules ran is unknown"}]
    if alarms or items:
        result = "alarm"
    elif any(n["status"] != "disabled" for n in notes):
        result = "incomplete"
    else:
        result = "clean"
    return {
        "trace": str(trace_path),
        "records": len(numbered),
        "sessions": sessions,
        "findings_source": findings_source,
        "findings": items,
        "alarms": alarms,
        "notes": notes,
        "rules": rules,
        "result": result,
        "exit": EXIT[result],
    }


def render_text(report):
    out = ["Raqib report",
           "trace: %s (%d records, %d sessions)" % (report["trace"], report["records"],
                                                   len(report["sessions"])),
           "findings: %s" % report["findings_source"], ""]
    out.append("ALARMS (A3, A5): %d" % len(report["alarms"]))
    for a in report["alarms"]:
        where = "line %d: " % a["line"] if "line" in a else ""
        out.append("  - %s: %s%s" % (a["kind"], where, a["detail"]))
    out.append("")
    out.append("FINDINGS: %d" % len(report["findings"]))
    for f in report["findings"]:
        out.append("  [%s] %s (%s) session %s seq %s" % (
            f["severity"], f["rule_id"], f.get("class", "?"), f["session_id"],
            ",".join(str(s) for s in f["cited_seq"])))
        out.append("      %s" % f["summary"])
        for c in f["cites"]:
            if not c["lines"]:
                out.append("      seq %d: NO LINE IN TRACE" % c["seq"])
            for ln in c["lines"]:
                out.append("      seq %d: line %d  %s" % (c["seq"], ln["line"], ln["text"]))
    out.append("")
    out.append("RULES THAT DID NOT RUN: %d" % len(report["notes"]))
    for n in report["notes"]:
        out.append("  - %s %s: %s" % (n["rule_id"], n["status"], n["detail"]))
    out.append("")
    out.append("RULES (A6 fp_budget): %d" % len(report["rules"]))
    out.append("  %-15s %-9s %-7s %-9s %s" % ("id", "class", "sev", "fp_budget", "status"))
    for r in report["rules"]:
        budget = "-" if r["fp_budget"] is None else "%g" % r["fp_budget"]
        out.append("  %-15s %-9s %-7s %-9s %s" % (r["id"], r["class"], r["severity"], budget, r["status"]))
    out.append("")
    out.append("RESULT: %s (exit %d)" % (report["result"].upper(), report["exit"]))
    return "\n".join(out) + "\n"
