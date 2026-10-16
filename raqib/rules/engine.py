"""Rule engine (M1.1): YAML rules (ADR-0001 section 4) evaluated by a pure
function. No rule consults a model (constitution A1).

A rule file holds one mapping:

    id: NET-TOOL                      # [A-Z][A-Z0-9]*(-[A-Z0-9]+)+, = file name
    title: Tool call reaches the network
    class: NET                        # SCOPE|NET|DESTRUCT|SECRET|SILENCE|DRIFT
    severity: medium                  # low|medium|high
    fp_budget: 0.1                    # expected false-positive rate, 0..1 (A6)
    status: active                    # optional: active (default) | disabled
    description: ...                  # optional, free text
    summary: "{tool} at seq {seq}"    # optional template; default: the title
    match: <node>                     # declarative, over trace fields
    aggregate: {distinct: input_meta.path, over: 3}   # optional
    fixtures: {positive: [path, ...], negative: [path, ...]}

A match node is {all: [node, ...]}, {any: [node, ...]}, {not: node}, or a
predicate {field: <dotted path>, <op>: <arg>} with exactly one op:

    eq / ne        scalar        equal / not equal (bool, number, str are distinct)
    in / not_in    [scalars]     one of / none of
    exists         true|false    the field is present and not null
    nonempty       true          a non-empty string, list or mapping
    regex          str           re.search on a string
    prefix         str           string starts with
    glob           str           fnmatch (case-sensitive) on a string
    outside        <field>       path not under the directory in that field
    outside_any    <context key> path not under any of context[key]

A predicate on a missing field is false, except `exists: false`. Paths are
POSIX: a relative path is joined to the line's cwd, `~` paths count as
absolute, and a path that cannot be placed makes the predicate false.

Without `aggregate`, every matching line gives one finding citing its seq
(once per session and seq). With `aggregate`, a session gives one finding
when more than `over` distinct values of `distinct` occur on matching lines;
it cites every matching seq.
"""
from __future__ import annotations

import fnmatch
import glob
import json
import os
import posixpath
import re

from raqib.rules import yamlite
from raqib.rules.trace import is_record, is_seq

CLASSES = ("SCOPE", "NET", "DESTRUCT", "SECRET", "SILENCE", "DRIFT")
SEVERITIES = ("low", "medium", "high")
STATUSES = ("active", "disabled")
REQUIRED = ("id", "title", "class", "severity", "fp_budget", "match", "fixtures")
OPTIONAL = ("status", "description", "summary", "aggregate")
RULE_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\Z")
FIELD = re.compile(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*\Z")
CONTEXT_KEY = re.compile(r"[a-z_][a-z0-9_]*\Z")
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
OPS = ("eq", "ne", "in", "not_in", "exists", "nonempty", "regex", "prefix", "glob",
       "outside", "outside_any")
SUMMARY_VALUE_MAX = 80
MISSING = object()


class RuleError(ValueError):
    """A rule that cannot be loaded; the message names the file and field."""


class FindingError(ValueError):
    """A finding that breaks the format, e.g. no cited_seq (A5)."""


class Rule:
    """A validated, compiled rule. `doc` is the parsed YAML mapping."""

    def __init__(self, doc, source):
        self.doc = doc
        self.source = source
        self.id = doc["id"]
        self.title = doc["title"]
        self.cls = doc["class"]
        self.severity = doc["severity"]
        self.fp_budget = doc["fp_budget"]
        self.status = doc.get("status", "active")
        self.summary = doc.get("summary") or doc["title"]
        self.fixtures = doc["fixtures"]
        self.context_keys = set()
        self.match = _compile(doc["match"], "match", self)
        agg = doc.get("aggregate")
        self.aggregate = None
        if agg is not None:
            self.aggregate = (_getter(agg["distinct"]), agg["over"])

    def __repr__(self):
        return "Rule(%s)" % self.id


# --- loading ----------------------------------------------------------------

def load_rule(path):
    """Load and validate one rule file."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = yamlite.loads(f.read())
    except (OSError, UnicodeDecodeError) as exc:
        raise RuleError("%s: cannot read (%s)" % (path, exc))
    except yamlite.YamlError as exc:
        raise RuleError("%s: %s" % (path, exc))
    rule = compile_rule(doc, str(path))
    stem = os.path.splitext(os.path.basename(str(path)))[0]
    if stem != rule.id:
        raise RuleError("%s: id %r must equal the file name %r" % (path, rule.id, stem))
    return rule


def load_catalog(directory):
    """Load every *.yaml rule in a directory, sorted by id."""
    rules = [load_rule(p) for p in sorted(glob.glob(os.path.join(str(directory), "*.yaml")))]
    seen = set()
    for rule in rules:
        if rule.id in seen:
            raise RuleError("%s: duplicate rule id %s" % (rule.source, rule.id))
        seen.add(rule.id)
    return rules


def compile_rule(doc, source="<rule>"):
    """Validate a parsed rule mapping and compile its matcher."""
    def bad(field, msg):
        raise RuleError("%s: %s: %s" % (source, field, msg))

    if not isinstance(doc, dict):
        raise RuleError("%s: a rule file must hold a mapping" % source)
    for key in REQUIRED:
        if key not in doc:
            bad(key, "missing")
    for key in doc:
        if key not in REQUIRED and key not in OPTIONAL:
            bad(key, "unknown field")
    if not (isinstance(doc["id"], str) and RULE_ID.match(doc["id"])):
        bad("id", "must look like NET-TOOL ([A-Z][A-Z0-9]*(-[A-Z0-9]+)+)")
    for key in ("title", "description", "summary"):
        if key in doc and not (isinstance(doc[key], str) and doc[key].strip()):
            bad(key, "must be a non-empty string")
    if doc["class"] not in CLASSES:
        bad("class", "must be one of %s" % "|".join(CLASSES))
    if doc["severity"] not in SEVERITIES:
        bad("severity", "must be one of %s" % "|".join(SEVERITIES))
    budget = doc["fp_budget"]
    if not (isinstance(budget, (int, float)) and not isinstance(budget, bool) and 0 <= budget <= 1):
        bad("fp_budget", "must be a number from 0 to 1")
    if doc.get("status", "active") not in STATUSES:
        bad("status", "must be one of %s" % "|".join(STATUSES))
    fixtures = doc["fixtures"]
    if not isinstance(fixtures, dict) or set(fixtures) != {"positive", "negative"}:
        bad("fixtures", "must have exactly positive and negative")
    for kind in ("positive", "negative"):
        paths = fixtures[kind]
        if not (isinstance(paths, list) and paths):
            bad("fixtures.%s" % kind, "must be a non-empty list (every rule has both)")
        for p in paths:
            if not (isinstance(p, str) and p and not p.startswith("/")
                    and ".." not in p.split("/")):
                bad("fixtures.%s" % kind, "%r must be a relative path inside the repo" % (p,))
    agg = doc.get("aggregate")
    if agg is not None:
        if not isinstance(agg, dict) or set(agg) != {"distinct", "over"}:
            bad("aggregate", "must have exactly distinct and over")
        if not (isinstance(agg["distinct"], str) and FIELD.match(agg["distinct"])):
            bad("aggregate.distinct", "must be a field path")
        if not (isinstance(agg["over"], int) and not isinstance(agg["over"], bool) and agg["over"] >= 0):
            bad("aggregate.over", "must be an int >= 0")
    summary = doc.get("summary")
    if summary is not None:
        for name in PLACEHOLDER.findall(summary):
            if name not in ("seq", "count") and not FIELD.match(name):
                bad("summary", "bad placeholder {%s}" % name)
    try:
        return Rule(doc, source)
    except _NodeError as exc:
        raise RuleError("%s: %s" % (source, exc))


class _NodeError(ValueError):
    pass


def _compile(node, where, rule):
    if not isinstance(node, dict):
        raise _NodeError("%s: a match node must be a mapping" % where)
    keys = set(node)
    if keys in ({"all"}, {"any"}):
        (kind,) = keys
        items = node[kind]
        if not (isinstance(items, list) and items):
            raise _NodeError("%s.%s: must be a non-empty list" % (where, kind))
        parts = [_compile(n, "%s.%s[%d]" % (where, kind, i), rule) for i, n in enumerate(items)]
        if kind == "all":
            return lambda line, ctx: all(p(line, ctx) for p in parts)
        return lambda line, ctx: any(p(line, ctx) for p in parts)
    if keys == {"not"}:
        inner = _compile(node["not"], where + ".not", rule)
        return lambda line, ctx: not inner(line, ctx)
    if "field" in keys:
        return _predicate(node, where, rule)
    raise _NodeError("%s: unknown match node with keys %s" % (where, sorted(keys)))


def _scalar(value):
    return value is None or isinstance(value, (str, int, float, bool))


def _predicate(node, where, rule):
    field = node["field"]
    if not (isinstance(field, str) and FIELD.match(field)):
        raise _NodeError("%s.field: must be a dotted path like input_meta.path" % where)
    ops = [k for k in node if k != "field"]
    if len(ops) != 1 or ops[0] not in OPS:
        raise _NodeError("%s: a predicate needs field and exactly one of %s" % (where, ", ".join(OPS)))
    op = ops[0]
    arg = node[op]
    get = _getter(field)
    at = "%s.%s" % (where, op)

    if op in ("eq", "ne"):
        if not _scalar(arg):
            raise _NodeError("%s: must be a scalar" % at)
        if op == "eq":
            return lambda line, ctx: _same(get(line), arg)
        return lambda line, ctx: get(line) is not MISSING and not _same(get(line), arg)
    if op in ("in", "not_in"):
        if not (isinstance(arg, list) and arg and all(_scalar(a) for a in arg)):
            raise _NodeError("%s: must be a non-empty list of scalars" % at)
        if op == "in":
            return lambda line, ctx: any(_same(get(line), a) for a in arg)
        return lambda line, ctx: get(line) is not MISSING and not any(_same(get(line), a) for a in arg)
    if op == "exists":
        if not isinstance(arg, bool):
            raise _NodeError("%s: must be true or false" % at)
        return lambda line, ctx: (get(line) not in (MISSING, None)) == arg
    if op == "nonempty":
        if arg is not True:
            raise _NodeError("%s: must be true" % at)
        return lambda line, ctx: isinstance(get(line), (str, list, dict)) and len(get(line)) > 0
    if op in ("regex", "prefix", "glob"):
        if not isinstance(arg, str) or not arg:
            raise _NodeError("%s: must be a non-empty string" % at)
        if op == "regex":
            try:
                pattern = re.compile(arg)
            except re.error as exc:
                raise _NodeError("%s: bad regex (%s)" % (at, exc))
            return lambda line, ctx: isinstance(get(line), str) and bool(pattern.search(get(line)))
        if op == "prefix":
            return lambda line, ctx: isinstance(get(line), str) and get(line).startswith(arg)
        return lambda line, ctx: isinstance(get(line), str) and fnmatch.fnmatchcase(get(line), arg)
    if op == "outside":
        if not (isinstance(arg, str) and FIELD.match(arg)):
            raise _NodeError("%s: must name another field, e.g. cwd" % at)
        base = _getter(arg)

        def outside(line, ctx):
            path = _place(get(line), line.get("cwd"))
            root = _place(base(line), line.get("cwd"))
            return path is not None and root is not None and not _under(path, root)
        return outside
    # outside_any
    if not (isinstance(arg, str) and CONTEXT_KEY.match(arg)):
        raise _NodeError("%s: must name a context key, e.g. scope" % at)
    rule.context_keys.add(arg)

    def outside_any(line, ctx):
        path = _place(get(line), line.get("cwd"))
        roots = ctx.get(arg)
        if path is None or not isinstance(roots, list):
            return False
        placed = [_place(r, line.get("cwd")) for r in roots]
        if any(r is None for r in placed):
            return False
        return not any(_under(path, r) for r in placed)
    return outside_any


def _getter(field):
    parts = field.split(".")

    def get(line):
        value = line
        for part in parts:
            if not isinstance(value, dict) or part not in value:
                return MISSING
            value = value[part]
        return value
    return get


def _same(a, b):
    if a is MISSING:
        return False
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


def _place(path, cwd):
    """Absolute normalised POSIX path, or None if it cannot be placed."""
    if not isinstance(path, str) or not path:
        return None
    if not (path.startswith("/") or path.startswith("~")):
        if not (isinstance(cwd, str) and cwd.startswith("/")):
            return None
        path = cwd.rstrip("/") + "/" + path
    return posixpath.normpath(path)


def _under(path, root):
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root if root == "/" else root + "/")


# --- evaluation (pure) ------------------------------------------------------

def evaluate(rules, lines, context=None):
    """Return (findings, notes). Findings are ordered by session (first
    appearance), first cited seq, then rule_id. A rule that is disabled, or
    that needs a context key it was not given, is not run and gets a note:
    {"rule_id", "status": "disabled"|"not-evaluated", "detail"} (A3)."""
    context = context or {}
    records = [r for r in lines if is_record(r)]
    found = []
    notes = []
    for rule in rules:
        if rule.status == "disabled":
            notes.append({"rule_id": rule.id, "status": "disabled",
                          "detail": "status: disabled in %s (A6)" % rule.source})
            continue
        missing = sorted(k for k in rule.context_keys if k not in context)
        if missing:
            notes.append({"rule_id": rule.id, "status": "not-evaluated",
                          "detail": "needs context: %s" % ", ".join(missing)})
            continue
        found += run_rule(rule, records, context)
    order = {}
    for rec in records:
        order.setdefault(rec["session_id"], len(order))
    found.sort(key=lambda f: (order[f["session_id"]], f["cited_seq"][0], f["rule_id"]))
    return found, notes


def run_rule(rule, lines, context=None):
    """Findings of one rule over trace records, whatever its status."""
    context = context or {}
    records = [r for r in lines if is_record(r)]
    if rule.aggregate is None:
        out = []
        seen = set()
        for rec in records:
            key = (rec["session_id"], rec["seq"])
            if key not in seen and rule.match(rec, context):
                seen.add(key)
                out.append(_emit(rule, rec["session_id"], [rec["seq"]], rec.get("ts"),
                                 _render(rule.summary, rec, rec["seq"], 1)))
        return out
    get, over = rule.aggregate
    per_session = {}
    for rec in records:
        if rule.match(rec, context):
            value = get(rec)
            if value is MISSING or value is None:
                continue
            entry = per_session.setdefault(rec["session_id"], {"values": set(), "seqs": [], "last": rec})
            entry["values"].add(json.dumps(value, sort_keys=True))
            entry["seqs"].append(rec["seq"])
            entry["last"] = rec
    out = []
    for session_id, entry in per_session.items():
        count = len(entry["values"])
        if count > over:
            seqs = sorted(set(entry["seqs"]))
            out.append(_emit(rule, session_id, seqs, entry["last"].get("ts"),
                             _render(rule.summary, entry["last"], seqs[-1], count)))
    return out


def _emit(rule, session_id, cited_seq, ts, summary):
    finding = {
        "ts": ts,
        "rule_id": rule.id,
        "class": rule.cls,
        "severity": rule.severity,
        "session_id": session_id,
        "cited_seq": list(cited_seq),
        "summary": summary,
    }
    check_finding(finding)
    return finding


def check_finding(finding):
    """Reject a finding that cannot be traced back to trace lines (A5)."""
    cited = finding.get("cited_seq") if isinstance(finding, dict) else None
    if not (isinstance(cited, list) and cited and all(is_seq(s) for s in cited)):
        raise FindingError("finding without cited_seq is rejected (A5): %r" % (finding,))
    for key in ("rule_id", "severity", "session_id", "summary"):
        if not isinstance(finding.get(key), str) or not finding[key]:
            raise FindingError("finding has no %s: %r" % (key, finding))
    return finding


def _render(template, line, seq, count):
    def value(match):
        name = match.group(1)
        if name == "seq":
            return str(seq)
        if name == "count":
            return str(count)
        v = _getter(name)(line)
        if v is MISSING or v is None:
            return "-"
        text = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
        text = "".join(c if c.isprintable() else "?" for c in text)
        if len(text) > SUMMARY_VALUE_MAX:
            text = text[:SUMMARY_VALUE_MAX - 3] + "..."
        return text
    return PLACEHOLDER.sub(value, template)
