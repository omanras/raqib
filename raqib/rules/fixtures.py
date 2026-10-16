"""Fixture runner (M1.1): every rule is checked against its fixtures
(constitution A6, A7; ADR-0001 section 4).

A fixture file is one of:
- a JSON list of trace lines (*.json);
- a JSON object {"context": {...}, "lines": [...]} (*.json), for rules that
  need context such as a task scope;
- a raw trace as capture writes it (*.log), e.g. a real Claude Code run.

For each rule:
- every positive fixture must make it fire (else verdict "positive-missed");
- every negative fixture, plus every file of the shared benign corpus, on
  which it fires counts as a false positive. fp_rate = fired / total;
- an active rule whose fp_rate is above its fp_budget fails ("over-budget"):
  A6 says such a rule is disabled (status: disabled), not tuned live. A
  disabled rule is still measured and reported ("disabled").
"""
from __future__ import annotations

import glob
import json
import os

from raqib.rules import engine, trace


class FixtureError(ValueError):
    pass


def load_fixture(path):
    """Return (lines, context) for a fixture file."""
    path = str(path)
    if path.endswith(".log"):
        records, problems = trace.read(path)
        if problems:
            raise FixtureError("%s: trace problems %r" % (path, problems))
        return records, {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        raise FixtureError("%s: %s" % (path, exc))
    if isinstance(data, list):
        return data, {}
    if isinstance(data, dict) and set(data) == {"context", "lines"} \
            and isinstance(data["lines"], list) and isinstance(data["context"], dict):
        return data["lines"], data["context"]
    raise FixtureError("%s: a fixture is a list of trace lines or {context, lines}" % path)


def benign_corpus(directory):
    """Sorted *.json and *.log files of a benign-trace directory."""
    directory = str(directory)
    return sorted(glob.glob(os.path.join(directory, "*.json")) +
                  glob.glob(os.path.join(directory, "*.log")))


def fires(rule, path):
    lines, context = load_fixture(path)
    return bool(engine.run_rule(rule, lines, context))


def check_rule(rule, root, benign=()):
    """Run one rule on its fixtures (paths relative to root) and the benign corpus."""
    root = str(root)
    positives = [{"path": p, "fired": fires(rule, os.path.join(root, p))}
                 for p in rule.fixtures["positive"]]
    negative_paths = [os.path.join(root, p) for p in rule.fixtures["negative"]] + list(benign)
    negatives = [{"path": os.path.relpath(p, root), "fired": fires(rule, p)} for p in negative_paths]
    fp_rate = sum(n["fired"] for n in negatives) / len(negatives)
    if not all(p["fired"] for p in positives):
        verdict = "positive-missed"
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
        "positives": positives,
        "negatives": negatives,
        "verdict": verdict,
    }


def check_catalog(rules, root, benign=()):
    return [check_rule(rule, root, benign) for rule in rules]
