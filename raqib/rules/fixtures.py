"""Fixture runner (M1.1): every rule is checked against its fixtures
(constitution A6, A7; ADR-0001 section 4).

A fixture file is one of:
- a JSON list of trace lines (*.json);
- a JSON object {"lines": [...], "context"?: {...}, "expect_seq"?: [int]}
  (*.json), for rules that need context such as a task scope, or positives
  that must cite particular seqs;
- a raw trace as capture writes it (*.log), e.g. a real Claude Code run.
Every line must be a sound trace record (session_id, int seq, valid ts, known
phase); a malformed fixture is an error, never a silent pass.

For each rule:
- every positive fixture must make it fire, citing every seq in expect_seq
  (else verdict "positive-missed");
- a negative fixture, or a file of the shared benign corpus, counts as
  measured only if the rule could judge every line of it with the context it
  needs; unmeasured files are reported, not counted as clean (A3);
- fp_rate = measured files on which it fired / measured files. An active
  rule above its fp_budget fails ("over-budget"): A6 says such a rule is
  disabled (status: disabled), not tuned live. A rule with no measured
  negative fails ("unmeasured"). A disabled rule is still measured.
"""
from __future__ import annotations

import glob
import json
import os

from raqib.rules import engine, trace

OBJECT_KEYS = {"lines", "context", "expect_seq"}


class FixtureError(ValueError):
    pass


def load_fixture(path):
    """Return (lines, context, expect_seq) for a fixture file."""
    path = str(path)
    if path.endswith(".log"):
        records, problems = trace.read(path)
        if problems:
            raise FixtureError("%s: trace problems %r" % (path, problems))
        return records, {}, None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        raise FixtureError("%s: %s" % (path, exc))
    expect = None
    if isinstance(data, list):
        lines, ctx = data, {}
    elif isinstance(data, dict) and "lines" in data and set(data) <= OBJECT_KEYS:
        lines, ctx, expect = data["lines"], data.get("context", {}), data.get("expect_seq")
        if not isinstance(lines, list) or not isinstance(ctx, dict):
            raise FixtureError("%s: lines must be a list and context a mapping" % path)
        if expect is not None and not (isinstance(expect, list) and expect
                                       and all(trace.is_seq(s) for s in expect)):
            raise FixtureError("%s: expect_seq must be a non-empty list of ints" % path)
    else:
        raise FixtureError("%s: a fixture is a list of trace lines or {lines, context?, expect_seq?}" % path)
    for i, rec in enumerate(lines):
        if not trace.is_record(rec) or trace.parse_ts(rec.get("ts")) is None \
                or rec.get("phase") not in trace.PHASES:
            raise FixtureError("%s: line %d is not a sound trace record: %r" % (path, i + 1, rec))
    return lines, ctx, expect


def benign_corpus(directory):
    """Sorted *.json and *.log files of a benign-trace directory."""
    directory = str(directory)
    return sorted(glob.glob(os.path.join(directory, "*.json")) +
                  glob.glob(os.path.join(directory, "*.log")))


def outcome(rule, path):
    """(fired, cited seqs, measured) of one rule on one fixture file."""
    lines, context, _ = load_fixture(path)
    if any(not engine.context_ok(context.get(k)) for k in rule.context_keys):
        return False, set(), False
    found, unknown = engine.judge(rule, lines, context)
    cited = {s for f in found for s in f["cited_seq"]}
    # A firing is a false positive on a negative whatever else was unknown.
    return bool(found), cited, bool(found) or not unknown


def fires(rule, path):
    return outcome(rule, path)[0]


def check_rule(rule, root, benign=()):
    """Run one rule on its fixtures (paths relative to root) and the benign corpus."""
    root = str(root)
    positives = []
    for p in rule.fixtures["positive"]:
        full = os.path.join(root, p)
        fired, cited, _ = outcome(rule, full)
        expect = load_fixture(full)[2] or []
        positives.append({"path": p, "fired": fired and set(expect) <= cited,
                          "missing_seq": sorted(set(expect) - cited)})
    negative_paths = [os.path.join(root, p) for p in rule.fixtures["negative"]] + list(benign)
    negatives = []
    for p in negative_paths:
        fired, _, measured = outcome(rule, p)
        negatives.append({"path": os.path.relpath(p, root), "fired": fired, "measured": measured})
    measured = [n for n in negatives if n["measured"]]
    fp_rate = sum(n["fired"] for n in measured) / len(measured) if measured else None
    if not all(p["fired"] for p in positives):
        verdict = "positive-missed"
    elif not measured:
        verdict = "unmeasured"
    elif rule.status == "disabled":
        verdict = "disabled"
    elif fp_rate > rule.fp_budget:
        verdict = "over-budget"
    else:
        verdict = "ok"
    return {
        "rule_id": rule.id,
        "status": rule.status,
        "fp_budget": rule.fp_budget,
        "fp_rate": fp_rate,
        "measured": len(measured),
        "unmeasured": len(negatives) - len(measured),
        "positives": positives,
        "negatives": negatives,
        "verdict": verdict,
    }


def check_catalog(rules, root, benign=()):
    return [check_rule(rule, root, benign) for rule in rules]
