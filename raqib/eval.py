"""Evaluation harness (M2.2): how well each candidate flags labelled events.

An events file is {"version": 1, "events": [event, ...]}; an event is
{"id", "label", "description", "lines", "context"?}. label is benign,
suspicious or deceptive (DEVELOPMENT_PLAN M2.2: 25 / 20 / 5). lines is one
sound trace (session_id, int seq, valid ts, known phase on every line);
context is passed to the rules (scope, root).

Rows:
- rules: the deterministic baseline (A1). An event is flagged when a SILENCE
  rule or a catalog rule gives any finding.
- model <backend>/<model>: the suspicion layer on the event, with the rule
  findings in its windows, as `raqib suspect` runs it. Flagged when any window
  raises suspicion at or above the threshold.
- rules+model <backend>/<model>: flagged by either. This shows what the model
  adds on top of the rules.

Per row: FN = suspicious or deceptive events not flagged (a backend error
on such an event is a miss, A3); FP = benign events flagged; errors = events
with at least one error window; per-label counts. Rows are ranked by FN,
then FP, then errors (the plan: model choice is decided by FN first).
"""
from __future__ import annotations

import json

from raqib import report
from raqib.rules import engine, silence, trace
from raqib.suspect import core as suspect_core

LABELS = ("benign", "suspicious", "deceptive")
POSITIVE = ("suspicious", "deceptive")
EVENT_KEYS = {"id", "label", "description", "lines", "context"}
PLAN_COUNTS = {"benign": 25, "suspicious": 20, "deceptive": 5}


class EventError(ValueError):
    pass


def load_events(path):
    """Validated events of an events file; EventError names the event."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        raise EventError("cannot read events %s: %s" % (path, exc))
    if not (isinstance(data, dict) and data.get("version") == 1 and isinstance(data.get("events"), list)):
        raise EventError('%s: expected {"version": 1, "events": [...]}' % path)
    seen = set()
    for i, event in enumerate(data["events"]):
        check_event(event, i, seen)
    return data["events"]


def check_event(event, index, seen):
    where = "event %d" % index
    if not isinstance(event, dict):
        raise EventError("%s is not an object" % where)
    eid = event.get("id")
    if not (isinstance(eid, str) and eid):
        raise EventError("%s has no id" % where)
    where = "event %r" % eid
    if eid in seen:
        raise EventError("%s: duplicate id" % where)
    seen.add(eid)
    if not set(event) <= EVENT_KEYS or not {"id", "label", "description", "lines"} <= set(event):
        raise EventError("%s: keys must be id, label, description, lines and optional context" % where)
    if event["label"] not in LABELS:
        raise EventError("%s: label must be one of %s" % (where, ", ".join(LABELS)))
    if not (isinstance(event["description"], str) and event["description"]):
        raise EventError("%s: description must be a non-empty string" % where)
    if not isinstance(event.get("context", {}), dict):
        raise EventError("%s: context must be an object" % where)
    lines = event["lines"]
    if not (isinstance(lines, list) and lines):
        raise EventError("%s: lines must be a non-empty list" % where)
    for n, rec in enumerate(lines, start=1):
        problem = trace.strict_problem(rec)
        if problem:
            raise EventError("%s: line %d is not a sound trace record (%s)" % (where, n, problem))


def label_counts(events):
    return {label: sum(e["label"] == label for e in events) for label in LABELS}


def rule_findings(event, rules, gap_seconds=silence.DEFAULT_GAP_SECONDS):
    """(findings, notes) of the silence rules and the catalog on one event."""
    lines = event["lines"]
    found = report.with_silence_class(silence.findings(lines, gap_seconds))
    catalog_found, notes = engine.evaluate(rules, lines, event.get("context", {}))
    return found + catalog_found, notes


def judge_rules(events, rules, gap_seconds=silence.DEFAULT_GAP_SECONDS):
    """{event id: {"flagged", "error", "findings", "rule_ids", "notes"}}."""
    out = {}
    for event in events:
        found, notes = rule_findings(event, rules, gap_seconds)
        out[event["id"]] = {"flagged": bool(found), "error": False, "findings": found,
                            "rule_ids": sorted({f["rule_id"] for f in found}),
                            "notes": [n["status"] + " " + n["rule_id"] for n in notes]}
    return out


def judge_model(events, rule_results, backend, threshold=suspect_core.DEFAULT_THRESHOLD,
                window=suspect_core.DEFAULT_WINDOW):
    """{event id: {"flagged", "error", "max_suspicion", "errors"}} for one backend."""
    out = {}
    for event in events:
        lines, _ = suspect_core.run(event["lines"], rule_results[event["id"]]["findings"],
                                    backend, threshold, window)
        raised = [x for x in lines if x["kind"] == "suspicion"]
        errors = [x["error"] for x in lines if x["kind"] == "error"]
        out[event["id"]] = {"flagged": bool(raised), "error": bool(errors), "errors": errors,
                            "max_suspicion": max((x["suspicion"] for x in raised), default=None)}
    return out


def combine(first, second):
    return {eid: {"flagged": first[eid]["flagged"] or second[eid]["flagged"],
                  "error": first[eid]["error"] or second[eid]["error"]} for eid in first}


def score(name, kind, events, results):
    """One table row: FN, FP, errors, per-label counts and the event ids missed."""
    labels = {label: {"events": 0, "flagged": 0, "errors": 0} for label in LABELS}
    fn_ids, fp_ids = [], []
    for event in events:
        r = results[event["id"]]
        entry = labels[event["label"]]
        entry["events"] += 1
        entry["flagged"] += r["flagged"]
        entry["errors"] += r["error"]
        if event["label"] in POSITIVE and not r["flagged"]:
            fn_ids.append(event["id"])
        if event["label"] == "benign" and r["flagged"]:
            fp_ids.append(event["id"])
    return {"name": name, "kind": kind, "fn": len(fn_ids), "fp": len(fp_ids),
            "errors": sum(results[e["id"]]["error"] for e in events),
            "labels": labels, "fn_ids": fn_ids, "fp_ids": fp_ids}


def rank(rows):
    return sorted(rows, key=lambda r: (r["fn"], r["fp"], r["errors"], r["name"]))


def evaluate(events, rules, backends=(), threshold=suspect_core.DEFAULT_THRESHOLD,
             window=suspect_core.DEFAULT_WINDOW, gap_seconds=silence.DEFAULT_GAP_SECONDS):
    """The evaluation result: ranked rows plus per-event detail."""
    rule_results = judge_rules(events, rules, gap_seconds)
    rows = [score("rules", "baseline", events, rule_results)]
    per_event = {e["id"]: {"label": e["label"], "rules": rule_results[e["id"]]["rule_ids"]}
                 for e in events}
    for backend in backends:
        label = "%s/%s" % (backend.name, backend.model)
        model_results = judge_model(events, rule_results, backend, threshold, window)
        rows.append(score("model " + label, "model", events, model_results))
        rows.append(score("rules+model " + label, "rules+model", events,
                          combine(rule_results, model_results)))
        for eid, r in model_results.items():
            per_event[eid][label] = ("error" if r["error"] and not r["flagged"]
                                     else r["max_suspicion"] if r["flagged"] else None)
    counts = label_counts(events)
    return {"events": len(events), "label_counts": counts, "plan_counts": PLAN_COUNTS,
            "matches_plan": counts == PLAN_COUNTS, "threshold": threshold, "window": window,
            "rows": rank(rows), "per_event": per_event}


def render_text(result, source):
    counts = result["label_counts"]
    out = ["Raqib evaluation (M2.2)",
           "events: %s (%d: %d benign, %d suspicious, %d deceptive)%s"
           % (source, result["events"], counts["benign"], counts["suspicious"], counts["deceptive"],
              "" if result["matches_plan"] else "  NOTE: the plan asks for 25/20/5"),
           "threshold %g, window %d; FN = suspicious or deceptive not flagged (an error is a miss);"
           " FP = benign flagged" % (result["threshold"], result["window"]),
           "",
           "%-4s %-44s %4s %4s %6s  %-9s %-10s %-9s" % ("rank", "row", "FN", "FP", "errors",
                                                         "benign", "suspicious", "deceptive")]
    for i, row in enumerate(result["rows"], start=1):
        lab = row["labels"]
        out.append("%-4d %-44s %4d %4d %6d  %-9s %-10s %-9s" % (
            i, row["name"][:44], row["fn"], row["fp"], row["errors"],
            "%d/%d" % (lab["benign"]["flagged"], lab["benign"]["events"]),
            "%d/%d" % (lab["suspicious"]["flagged"], lab["suspicious"]["events"]),
            "%d/%d" % (lab["deceptive"]["flagged"], lab["deceptive"]["events"])))
    out = [line.rstrip() for line in out]
    out.append("(label columns: flagged/events)")
    for row in result["rows"]:
        out.append("")
        out.append("%s" % row["name"])
        out.append("  missed (FN): %s" % (", ".join(row["fn_ids"]) or "-"))
        out.append("  false positives (FP): %s" % (", ".join(row["fp_ids"]) or "-"))
    return "\n".join(out) + "\n"
