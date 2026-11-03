"""Rule engine (M1.1): YAML rules (ADR-0001 section 4) evaluated by a pure
function. No rule consults a model (constitution A1).

A rule file holds one mapping:

    id: NET-TOOL                      # [A-Z][A-Z0-9]*(-[A-Z0-9]+)+, = file name
    title: Tool call reaches the network   # no { or }
    class: NET                        # SCOPE|NET|DESTRUCT|SECRET|SILENCE|DRIFT
    kind: signature                   # signature|demand|anchor (ADR-0002)
    evasion: [python urllib, ...]     # signature only, and then required: the
                                      # known ways round it, one line each
    severity: medium                  # low|medium|high (SILENCE must be high, A3)
    fp_budget: 0.1                    # expected false-positive rate, 0 <= x < 1 (A6)
    status: active                    # optional: active (default) | disabled
    description: ...                  # optional, free text
    summary: "{tool} at seq {seq}"    # optional template; default: the title
    match: <node>                     # declarative, over trace fields
    aggregate: {distinct: input_meta.path, over: 3}   # optional, see below
    fixtures: {positive: [path, ...], negative: [path, ...]}

A match node is {all: [node, ...]}, {any: [node, ...]}, {not: node}, or a
predicate {field: <dotted path>, <op>: <arg>} with exactly one op:

    eq / ne        scalar        equal / not equal (bool, number, str are distinct)
    in / not_in    [scalars]     one of / none of
    has_any        [scalars]     a list holding at least one of (M4.2); a
                                 value that is not a list is unknown
    exists         true|false    the field is present and not null
    nonempty       true          a non-empty string, list or mapping
    regex          str           re.search on a string
    prefix         str           string starts with
    glob           str           fnmatch (case-sensitive) on a string
    outside        <field>       path not under the directory in that field
    outside_any    <context key> path not under any path of context[key]

Logic is three-valued (A3): a predicate that cannot judge a line, because a
field it reads is missing, a string test (regex, prefix, glob) meets a value
that is not a string, or a path cannot be placed, gives "unknown", not
false. `not unknown` is unknown; `all` is false if any part is false, else
unknown if any part is unknown; `any` is true if any part is true, else
unknown if any part is unknown. `exists` always judges. A rule fires only on
true. Lines a rule could not judge are counted and reported as a "partial"
note, so a quiet rule is never mistaken for a clean one. Write `exists: true`
in front of a predicate when a missing field should mean "does not apply".

ADR-0002: a signature matches the shape of a bad act and is cheap to evade,
so it must list its evasions; a demand requires evidence of an act and its
absence is the finding; an anchor measures against a record the agent does
not write. kind and evasion errors name the rule id and the field. Every
finding carries its rule's kind; check_finding rejects one without it
(NoKindError, B-3).

Paths are POSIX and normalised lexically (symlinks are not resolved): a
relative path is joined to the line's cwd (for outside_any: to context
"root" when given), and `~` paths count as absolute.

aggregate: {distinct: <field>, over: N, as: path?, cite: all|first?} gives
one finding per session when more than N distinct values of <field> occur on
matching lines. `as: path` compares placed, normalised paths. `cite: first`
cites the first line of each distinct value instead of every matching line.
"""
from __future__ import annotations

import fnmatch
import glob
import json
import os
import posixpath
import re

from raqib.rules import yamlite
from raqib.rules.trace import is_record, is_seq, parse_ts

CLASSES = ("SCOPE", "NET", "DESTRUCT", "SECRET", "SILENCE", "DRIFT")
SEVERITIES = ("low", "medium", "high")
STATUSES = ("active", "disabled")
KINDS = ("signature", "demand", "anchor")  # ADR-0002
REQUIRED = ("id", "title", "class", "severity", "fp_budget", "match", "fixtures")
OPTIONAL = ("status", "description", "summary", "aggregate")
# kind is required and evasion required iff kind is signature (ADR-0002);
# both are checked after the id, so their errors can name the rule.
KIND_FIELDS = ("kind", "evasion")
RULE_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\Z")
FIELD = re.compile(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*\Z")
CONTEXT_KEY = re.compile(r"[a-z_][a-z0-9_]*\Z")
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
OPS = ("eq", "ne", "in", "not_in", "has_any", "exists", "nonempty", "regex", "prefix", "glob",
       "outside", "outside_any")
SUMMARY_VALUE_MAX = 80
MISSING = object()
UNKNOWN = None


class RuleError(ValueError):
    """A rule that cannot be loaded; the message names the file and field."""


class FindingError(ValueError):
    """A finding that breaks the format, e.g. no cited_seq (A5)."""


class NoKindError(FindingError):
    """A finding that is sound but for its missing kind (ADR-0002 B-3):
    the report raises it as a no-kind alarm."""


class Rule:
    """A validated, compiled rule. `doc` is the parsed YAML mapping."""

    def __init__(self, doc, source):
        self.doc = doc
        self.source = source
        self.id = doc["id"]
        self.title = doc["title"]
        self.cls = doc["class"]
        self.kind = doc["kind"]
        self.evasion = tuple(doc.get("evasion", ()))
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
            self.aggregate = {"get": _getter(agg["distinct"]), "over": agg["over"],
                              "as": agg.get("as"), "cite": agg.get("cite", "all")}

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
    except RecursionError:
        raise RuleError("%s: nesting too deep" % path)
    rule = compile_rule(doc, str(path))
    stem = os.path.splitext(os.path.basename(str(path)))[0]
    if stem != rule.id:
        raise RuleError("%s: id %r must equal the file name %r" % (path, rule.id, stem))
    return rule


def load_catalog(directory):
    """Load every *.yaml rule in a directory, sorted by id. A missing or empty
    catalog, or a rule file with another extension, is an error: no rules
    must never look like no findings (A3)."""
    directory = str(directory)
    if not os.path.isdir(directory):
        raise RuleError("%s: rule catalog directory not found" % directory)
    names = sorted(os.listdir(directory))
    stray = [n for n in names if n.lower().endswith((".yml", ".yaml")) and not n.endswith(".yaml")]
    if stray:
        raise RuleError("%s: rule files must end in .yaml: %s" % (directory, ", ".join(stray)))
    rules = [load_rule(p) for p in sorted(glob.glob(os.path.join(directory, "*.yaml")))]
    if not rules:
        raise RuleError("%s: the rule catalog is empty" % directory)
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
        if key not in REQUIRED and key not in OPTIONAL and key not in KIND_FIELDS:
            bad(key, "unknown field")
    if not (isinstance(doc["id"], str) and RULE_ID.match(doc["id"])):
        bad("id", "must look like NET-TOOL ([A-Z][A-Z0-9]*(-[A-Z0-9]+)+)")
    check_kind(doc, source)
    for key in ("title", "description", "summary"):
        if key in doc and not (isinstance(doc[key], str) and doc[key].strip()):
            bad(key, "must be a non-empty string")
    if "{" in doc["title"] or "}" in doc["title"]:
        bad("title", "must not contain { or } (put placeholders in summary)")
    if doc["class"] not in CLASSES:
        bad("class", "must be one of %s" % "|".join(CLASSES))
    if doc["severity"] not in SEVERITIES:
        bad("severity", "must be one of %s" % "|".join(SEVERITIES))
    if doc["class"] == "SILENCE" and doc["severity"] != "high":
        bad("severity", "class SILENCE must be high (A3: silence is of the highest class)")
    budget = doc["fp_budget"]
    if not (isinstance(budget, (int, float)) and not isinstance(budget, bool) and 0 <= budget < 1):
        bad("fp_budget", "must be a number with 0 <= fp_budget < 1")
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
        if not isinstance(agg, dict) or not {"distinct", "over"} <= set(agg) \
                or not set(agg) <= {"distinct", "over", "as", "cite"}:
            bad("aggregate", "must have distinct and over, and optionally as and cite")
        if not (isinstance(agg["distinct"], str) and FIELD.match(agg["distinct"])):
            bad("aggregate.distinct", "must be a field path")
        if not (isinstance(agg["over"], int) and not isinstance(agg["over"], bool) and agg["over"] >= 0):
            bad("aggregate.over", "must be an int >= 0")
        if agg.get("as", "path") != "path":
            bad("aggregate.as", "must be path")
        if agg.get("cite", "all") not in ("all", "first"):
            bad("aggregate.cite", "must be all or first")
    summary = doc.get("summary")
    if summary is not None:
        for name in PLACEHOLDER.findall(summary):
            if name not in ("seq", "count") and not FIELD.match(name):
                bad("summary", "bad placeholder {%s}" % name)
    try:
        return Rule(doc, source)
    except _NodeError as exc:
        raise RuleError("%s: %s" % (source, exc))


def check_kind(doc, source="<rule>"):
    """ADR-0002: kind is one of KINDS; evasion, a non-empty list of one-line
    strings, is required when kind is signature (no signature has no
    evasion) and forbidden otherwise. doc["id"] must already be valid: every
    error names the rule and the field."""
    def bad(field, msg):
        raise RuleError("%s: rule %s: %s: %s" % (source, doc["id"], field, msg))

    if "kind" not in doc:
        bad("kind", "missing; every rule declares one of %s (ADR-0002)" % "|".join(KINDS))
    kind = doc["kind"]
    if not (isinstance(kind, str) and kind in KINDS):
        bad("kind", "must be one of %s, not %r" % ("|".join(KINDS), kind))
    if kind != "signature":
        if "evasion" in doc:
            bad("evasion", "only a signature lists evasions; kind %s must not have one (ADR-0002)" % kind)
        return
    if "evasion" not in doc:
        bad("evasion", "missing; a signature must list its known evasions, one line each"
                       " (ADR-0002: a signature with no listed evasion is invalid)")
    evasion = doc["evasion"]
    if not (isinstance(evasion, list) and evasion):
        bad("evasion", "must be a non-empty list of one-line strings, not %r" % (evasion,))
    for i, item in enumerate(evasion):
        if not (isinstance(item, str) and item.strip() and item.isprintable()):
            bad("evasion[%d]" % i, "must be a non-empty one-line string of printable characters, not %r"
                % (item,))


class _NodeError(ValueError):
    pass


def _all(values):
    if any(v is False for v in values):
        return False
    return UNKNOWN if any(v is UNKNOWN for v in values) else True


def _any(values):
    if any(v is True for v in values):
        return True
    return UNKNOWN if any(v is UNKNOWN for v in values) else False


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
        combine = _all if kind == "all" else _any
        return lambda line, ctx: combine([p(line, ctx) for p in parts])
    if keys == {"not"}:
        inner = _compile(node["not"], where + ".not", rule)

        def negate(line, ctx):
            v = inner(line, ctx)
            return UNKNOWN if v is UNKNOWN else not v
        return negate
    if "field" in keys:
        return _predicate(node, where, rule)
    raise _NodeError("%s: unknown match node with keys %s" % (where, sorted(keys)))


def _scalar(value):
    return value is None or isinstance(value, (str, int, float, bool))


def _known(fn):
    """Wrap fn(value) so a missing field gives UNKNOWN."""
    def pred(value):
        return UNKNOWN if value is MISSING else fn(value)
    return pred


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

    def on_value(fn):
        test = _known(fn)
        return lambda line, ctx: test(get(line))

    if op in ("eq", "ne"):
        if not _scalar(arg):
            raise _NodeError("%s: must be a scalar" % at)
        if op == "eq":
            return on_value(lambda v: _same(v, arg))
        return on_value(lambda v: not _same(v, arg))
    if op in ("in", "not_in"):
        if not (isinstance(arg, list) and arg and all(_scalar(a) for a in arg)):
            raise _NodeError("%s: must be a non-empty list of scalars" % at)
        if op == "in":
            return on_value(lambda v: any(_same(v, a) for a in arg))
        return on_value(lambda v: not any(_same(v, a) for a in arg))
    if op == "has_any":
        if not (isinstance(arg, list) and arg and all(_scalar(a) for a in arg)):
            raise _NodeError("%s: must be a non-empty list of scalars" % at)
        return on_value(lambda v: any(_same(x, a) for x in v for a in arg) if isinstance(v, list) else UNKNOWN)
    if op == "exists":
        if not isinstance(arg, bool):
            raise _NodeError("%s: must be true or false" % at)
        return lambda line, ctx: (get(line) not in (MISSING, None)) == arg
    if op == "nonempty":
        if arg is not True:
            raise _NodeError("%s: must be true" % at)
        return on_value(lambda v: isinstance(v, (str, list, dict)) and len(v) > 0)
    if op in ("regex", "prefix", "glob"):
        if not isinstance(arg, str) or not arg:
            raise _NodeError("%s: must be a non-empty string" % at)
        if op == "regex":
            try:
                pattern = re.compile(arg)
            except re.error as exc:
                raise _NodeError("%s: bad regex (%s)" % (at, exc))
            return on_value(lambda v: bool(pattern.search(v)) if isinstance(v, str) else UNKNOWN)
        if op == "prefix":
            return on_value(lambda v: v.startswith(arg) if isinstance(v, str) else UNKNOWN)
        return on_value(lambda v: fnmatch.fnmatchcase(v, arg) if isinstance(v, str) else UNKNOWN)
    if op == "outside":
        if not (isinstance(arg, str) and FIELD.match(arg)):
            raise _NodeError("%s: must name another field, e.g. cwd" % at)
        base = _getter(arg)

        def outside(line, ctx):
            path = _place(get(line), line.get("cwd"))
            root = _place(base(line), line.get("cwd"))
            if path is None or root is None:
                return UNKNOWN
            return not _under(path, root)
        return outside
    # outside_any
    if not (isinstance(arg, str) and CONTEXT_KEY.match(arg)):
        raise _NodeError("%s: must name a context key, e.g. scope" % at)
    rule.context_keys.add(arg)

    def outside_any(line, ctx):
        anchor = ctx.get("root") or line.get("cwd")
        path = _place(get(line), line.get("cwd"))
        roots = ctx.get(arg)
        if path is None or not context_ok(roots):
            return UNKNOWN
        placed = [_place(r, anchor) for r in roots]
        if any(r is None for r in placed):
            return UNKNOWN
        return not any(_under(path, r) for r in placed)
    return outside_any


def context_ok(value):
    """A context path list: a non-empty list of non-empty strings."""
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) and v for v in value)


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
    placed = posixpath.normpath(path)
    if placed.startswith("//"):
        placed = "/" + placed.lstrip("/")
    if not (placed.startswith("/") or placed.startswith("~")):
        return None
    return placed


def _under(path, root):
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root if root == "/" else root + "/")


# --- evaluation (pure) ------------------------------------------------------

def evaluate(rules, lines, context=None):
    """Return (findings, notes). Findings are ordered by session (first
    appearance), first cited seq, then rule_id. Nothing goes unreported (A3):
    a rule that is disabled, lacks the context it needs or gets an unusable
    context is not run; a rule that could not judge some lines is "partial";
    lines without session_id or int seq are "skipped-lines". Each gets a note
    {"rule_id", "status", "detail"}."""
    context = context or {}
    records = [r for r in lines if is_record(r)]
    skipped = len(lines) - len(records)
    found = []
    notes = []
    if skipped:
        notes.append({"rule_id": "*", "status": "skipped-lines",
                      "detail": "%d line(s) without session_id or int seq were not evaluated" % skipped})
    if "root" in context and not (isinstance(context["root"], str) and context["root"].startswith("/")):
        notes.append({"rule_id": "*", "status": "bad-context",
                      "detail": "context root must be an absolute path; scope paths fall back to each line's cwd"})
        context = {k: v for k, v in context.items() if k != "root"}
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
        unusable = sorted(k for k in rule.context_keys if not context_ok(context[k]))
        if unusable:
            notes.append({"rule_id": rule.id, "status": "not-evaluated",
                          "detail": "context %s must be a non-empty list of paths" % ", ".join(unusable)})
            continue
        rule_found, unknown = judge(rule, records, context)
        found += rule_found
        if unknown:
            shown = ", ".join("%s:%d" % u for u in unknown[:5]) + (" ..." if len(unknown) > 5 else "")
            notes.append({"rule_id": rule.id, "status": "partial",
                          "detail": "could not judge %d line(s) (session:seq %s): a field it reads is "
                                    "missing or a path cannot be placed" % (len(unknown), shown)})
    order = {}
    for rec in records:
        order.setdefault(rec["session_id"], len(order))
    found.sort(key=lambda f: (order[f["session_id"]], f["cited_seq"][0], f["rule_id"]))
    return found, notes


def run_rule(rule, lines, context=None):
    """Findings of one rule over trace records, whatever its status."""
    return judge(rule, lines, context)[0]


def judge(rule, lines, context=None):
    """(findings, unknown) for one rule, whatever its status. unknown lists
    (session_id, seq) of lines the rule could not judge."""
    context = context or {}
    records = [r for r in lines if is_record(r)]
    last_ts = {}
    unknown = []
    if rule.aggregate is None:
        out = []
        seen = set()
        for rec in records:
            ts = _ts(rec, last_ts)
            key = (rec["session_id"], rec["seq"])
            result = rule.match(rec, context)
            if result is UNKNOWN:
                unknown.append(key)
            elif result and key not in seen:
                seen.add(key)
                out.append(_emit(rule, rec["session_id"], [rec["seq"]], ts,
                                 _render(rule.summary, rec, rec["seq"], 1)))
        return out, unknown
    agg = rule.aggregate
    per_session = {}
    for rec in records:
        ts = _ts(rec, last_ts)
        result = rule.match(rec, context)
        if result is UNKNOWN:
            unknown.append((rec["session_id"], rec["seq"]))
            continue
        if not result:
            continue
        value = agg["get"](rec)
        if agg["as"] == "path":
            value = _place(value, rec.get("cwd")) if value is not MISSING else MISSING
        if value in (MISSING, None):
            unknown.append((rec["session_id"], rec["seq"]))
            continue
        entry = per_session.setdefault(rec["session_id"], {"values": {}, "seqs": [], "last": rec, "ts": ts})
        entry["values"].setdefault(json.dumps(value, sort_keys=True), rec["seq"])
        entry["seqs"].append(rec["seq"])
        entry["last"], entry["ts"] = rec, ts
    out = []
    for session_id, entry in per_session.items():
        count = len(entry["values"])
        if count > agg["over"]:
            if agg["cite"] == "first":
                seqs = sorted(set(entry["values"].values()))
            else:
                seqs = sorted(set(entry["seqs"]))
            out.append(_emit(rule, session_id, seqs, entry["ts"],
                             _render(rule.summary, entry["last"], entry["last"]["seq"], count)))
    return out, unknown


def _ts(rec, last_ts):
    """The record's ts, or the last valid ts seen in its session (or None)."""
    if parse_ts(rec.get("ts")) is not None:
        last_ts[rec["session_id"]] = rec["ts"]
    return last_ts.get(rec["session_id"])


def _emit(rule, session_id, cited_seq, ts, summary):
    finding = {
        "ts": ts,
        "rule_id": rule.id,
        "class": rule.cls,
        "kind": rule.kind,
        "severity": rule.severity,
        "session_id": session_id,
        "cited_seq": list(cited_seq),
        "summary": summary,
    }
    check_finding(finding)
    return finding


def check_finding(finding):
    """Reject a finding that cannot be traced back to trace lines (A5), or that
    breaks the format."""
    cited = finding.get("cited_seq") if isinstance(finding, dict) else None
    if not (isinstance(cited, list) and cited and all(is_seq(s) for s in cited)):
        raise FindingError("finding without cited_seq is rejected (A5): %r" % (finding,))
    for key in ("rule_id", "severity", "session_id", "summary"):
        if not isinstance(finding.get(key), str) or not finding[key]:
            raise FindingError("finding has no %s: %r" % (key, finding))
    if "class" in finding and finding["class"] not in CLASSES:
        raise FindingError("finding has an unknown class: %r" % (finding,))
    if "kind" in finding and not (isinstance(finding["kind"], str) and finding["kind"] in KINDS):
        raise FindingError("finding has an unknown kind (ADR-0002: %s): %r" % ("|".join(KINDS), finding))
    if "ts" not in finding or not (finding["ts"] is None or isinstance(finding["ts"], str)):
        raise FindingError("finding needs ts (a string, or null when the trace has none): %r" % (finding,))
    if "kind" not in finding:  # last: the finding is sound but for its kind (B-3)
        raise NoKindError("finding has no kind (ADR-0002: every finding carries one of %s; A3): %r"
                          % ("|".join(KINDS), finding))
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
            keep = SUMMARY_VALUE_MAX - 3
            text = text[:keep // 2] + "..." + text[-(keep - keep // 2):]
        return text
    return PLACEHOLDER.sub(value, template)
