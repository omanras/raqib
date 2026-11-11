"""Rule engine (M1.1): YAML rules (ADR-0001 section 4) evaluated by a pure
function. No rule consults a model (constitution A1).

A rule file holds one mapping:

    id: NET-TOOL                      # [A-Z][A-Z0-9]*(-[A-Z0-9]+)+, = file name
    title: Tool call reaches the network   # no { or }
    class: NET                        # SCOPE|NET|DESTRUCT|SECRET|SILENCE|DRIFT|USER|HOST
                                      # (USER: a person's rule made from the form, M8.2)
                                      # (CROSS is cross.py's, never a YAML rule's)
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
    require: {before: <node>}         # optional, demand only (M4.2b), see below
    holes: [a stale gate, ...]        # optional, demand or anchor only (G-6):
                                      # the known holes, one line each
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
    under_any      [paths]       path under one of these directories (M4.2b),
                                 placed as outside_any places context[key]

Logic is three-valued (A3): a predicate that cannot judge a line, because a
field it reads is missing, a string test (regex, prefix, glob) meets a value
that is not a string, or a path cannot be placed, gives "unknown", not
false. `not unknown` is unknown; `all` is false if any part is false, else
unknown if any part is unknown; `any` is true if any part is true, else
unknown if any part is unknown. `exists` always judges. A rule fires only on
true. Lines a rule could not judge are counted and reported as a "partial"
note, so a quiet rule is never mistaken for a clean one. Write `exists: true`
in front of a predicate when a missing field should mean "does not apply".

summary placeholders: {seq}, {count}, {<field>} (the line's value, "-" when
missing), and (M9.1, ADR-0010 decision 4) {matched:<field>[,<field>...]}:
the values of those fields that the rule's match holds on the line the
summary is rendered on - the elements of a list that a has_any's list
holds, a scalar an eq, in, regex, prefix or glob holds - read only in the
branches that hold on that line (an all or any that is true, never inside
a not), field by field in the order named and each value once, joined by
", "; "-" when none. Deterministic, from the cited line alone (A1, A5): for
programs ["curl", "bash", "rm"] DESTRUCT-CMD's list holds rm, not the head.
It changes no finding but its sentence: the lines that fire and the cited
seqs are match's, as before.

ADR-0002: a signature matches the shape of a bad act and is cheap to evade,
so it must list its evasions; a demand requires evidence of an act and its
absence is the finding; an anchor measures against a record the agent does
not write. kind and evasion errors name the rule id and the field. Every
finding carries its rule's kind; check_finding rejects one without it
(NoKindError, B-3).

Paths are normalised lexically by norm_path() (symlinks are not resolved): a
relative path is joined to the line's cwd (for outside_any: to context
"root" when given), and `~` paths count as absolute. A drive-letter or UNC
path is a Windows path, compared with / and backslash alike, ASCII case
folded (A-Z only); any other path is POSIX and case-sensitive; a path of
one system is never under a directory of the other (M5.1b). Context "root"
must be absolute on one of the two systems.

aggregate: {distinct: <field>, over: N, as: path?, cite: all|first?} gives
one finding per session when more than N distinct values of <field> occur on
matching lines. `as: path` compares placed, normalised paths. `cite: first`
cites the first line of each distinct value instead of every matching line.

require (M4.2b, ADR-0002 Amendments D and G): a demand whose evidence is on
another line of the session (file order). Only on kind demand, never with
aggregate. match picks the trigger lines.
- {before: <node>}: a trigger fires when no line of its session up to and
  including it matches the node. One finding per trigger line, citing it.
- {after: <node>, until: <node>}: each trigger is judged at the first later
  line of its session that matches until (the deadline): it fires when no
  line between the two matches after. One finding per deadline, citing the
  triggers that fire there and the deadline, with the deadline's ts; its
  summary is rendered on the deadline line, {count} the number of triggers.
Three-valued: when no evidence line is true but some evidence line is
unknown, the trigger is unknown; a trigger whose deadline never comes is
unknown (a deadline line that is unknown makes the triggers before it
unknown). A true evidence line wins over unknown ones (H-2), and a trigger
that cannot be judged is not unknown when its evidence is true, since it
cannot fire (H-3). A pre line with no post line of its seq later in the
trace (a call whose result never came, SILENCE-HALF's fact) stands for itself
and for that missing post: judged as the post with no ok, a line that could
match there is unknown, never true (G-7). Unknown triggers are counted in the
partial note, each seq with its cause (H-3: the trigger cannot be judged, no
post line, evidence unknown, deadline unknown, no deadline came), never a
finding.

holes (G-6): a demand or an anchor may list its known holes, in the shape of
a signature's evasion list; a signature may not (it lists evasion).
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

CLASSES = ("SCOPE", "NET", "DESTRUCT", "SECRET", "SILENCE", "DRIFT", "CROSS",  # CROSS: M5.3 C-1
           "USER",   # USER: M8.2 REDO E-7, a person's rule made from the form (ADR-0009 Amendment E)
           "HOST")   # HOST: M7.2 REDO C-13, the rules of raqib watch --host (host lines, not a session)
CODE_CLASS = "CROSS"   # findings of raqib/rules/cross.py only: no YAML rule declares it (M5.3 D-11)
SEVERITIES = ("low", "medium", "high")
STATUSES = ("active", "disabled")
KINDS = ("signature", "demand", "anchor")  # ADR-0002
REQUIRED = ("id", "title", "class", "severity", "fp_budget", "match", "fixtures")
OPTIONAL = ("status", "description", "summary", "aggregate", "require", "bounds")   # bounds: M7.6c
# kind is required and evasion required iff kind is signature (ADR-0002);
# both are checked after the id, so their errors can name the rule.
KIND_FIELDS = ("kind", "evasion", "holes")   # holes: M4.2b G-6
RULE_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\Z")
FIELD = re.compile(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*\Z")
CONTEXT_KEY = re.compile(r"[a-z_][a-z0-9_]*\Z")
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
OPS = ("eq", "ne", "in", "not_in", "has_any", "exists", "nonempty", "regex", "prefix", "glob",
       "outside", "outside_any", "under_any")
REQUIRE_SHAPES = ({"before"}, {"after", "until"})   # M4.2b
SUMMARY_VALUE_MAX = 80
# H-3: why a require rule could not judge a line, named per seq in its partial note.
CAUSE_TRIGGER = "the trigger cannot be judged"
CAUSE_NO_POST = "no post line"
CAUSE_EVIDENCE = "evidence unknown"
CAUSE_DEADLINE = "deadline unknown"
CAUSE_NO_DEADLINE = "no deadline came"
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
        self.holes = tuple(doc.get("holes", ()))
        self.severity = doc["severity"]
        self.fp_budget = doc["fp_budget"]
        self.status = doc.get("status", "active")
        self.summary = doc.get("summary") or doc["title"]
        self.fixtures = doc["fixtures"]
        # M7.6c (ADR-0008 Amendment B): the bounds of the thresholds the person may set, from the YAML's
        # bounds: block (None: the YAML has none, so no threshold of the rule is editable); see bounds_of()
        self.bounds = bounds_of(doc)
        self.context_keys = set()
        self.match = _compile(doc["match"], "match", self)
        # M9.1 (ADR-0010 decision 4): what the match holds on a line, for {matched:...}; built only when used
        self.explain = (_explainer(doc["match"], "match", self)
                        if any(_matched_fields(n) for n in PLACEHOLDER.findall(self.summary)) else None)
        agg = doc.get("aggregate")
        self.aggregate = None
        if agg is not None:
            self.aggregate = {"get": _getter(agg["distinct"]), "over": agg["over"],
                              "as": agg.get("as"), "cite": agg.get("cite", "all")}
        req = doc.get("require")
        self.require = None
        if req is not None:
            self.require = {key: _compile(node, "require.%s" % key, self) for key, node in req.items()}

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


def load_catalog(directory, overlay=None, user_rules=None):
    """Load every *.yaml rule in a directory, sorted by id. A missing or empty
    catalog, or a rule file with another extension, is an error: no rules
    must never look like no findings (A3).

    M7.6 (ADR-0008): with overlay (the path of ~/.raqib/rules.yaml) or
    user_rules (the directory ~/.raqib/rules.d), raqib/overlay.py's build()
    adds the person's rules the loader and the fixture runner accept and
    applies the overlay on top; the result is an overlay.Catalog, a list
    whose .overlay says what was applied, refused or is a hole. Without
    them the catalog is read exactly as before (the gate, check-rules)."""
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
    if overlay is None and user_rules is None:
        return rules
    from raqib import overlay as person   # imported here: overlay imports this module
    return person.build(rules, overlay=None if overlay is None else str(overlay),
                        user_rules=None if user_rules is None else str(user_rules))


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
    if doc["class"] == CODE_CLASS:   # M5.3 ruling D-11
        bad("class", "CROSS is the class of the code rule raqib/rules/cross.py; a YAML rule may not declare it")
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
            why = fixture_path_problem(p)
            if why:   # M7.6 REDO A-1: one check on every OS, under both path rules
                bad("fixtures.%s" % kind, "%r must be a relative path inside the repo (%s)" % (p, why))
    both = sorted(set(fixtures["positive"]) & set(fixtures["negative"]))
    if both:   # M7.6 REDO A-4 (ADR-0008): a fixture cannot measure a rule both ways; no budget excuses it
        bad("fixtures", "%s listed as both positive and negative" % ", ".join(repr(p) for p in both))
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
    req = doc.get("require")
    if "require" in doc:   # H-6: require: null is an error, as holes: null is
        if doc["kind"] != "demand":
            bad("require", "only a demand requires evidence on another line (ADR-0002 Amendment D); kind %s"
                           " must not have one" % doc["kind"])
        if agg is not None:
            bad("require", "never together with aggregate (ADR-0002 Amendment D)")
        if not (isinstance(req, dict) and set(req) in REQUIRE_SHAPES):
            bad("require", "must be {before: <node>} or {after: <node>, until: <node>}")
    if "bounds" in doc:   # M7.6c: the YAML's bounds of its declared thresholds
        why = bounds_problem(doc)
        if why:
            bad("bounds", why)
    summary = doc.get("summary")
    if summary is not None:
        for name in PLACEHOLDER.findall(summary):
            if name not in ("seq", "count") and not FIELD.match(name) and _matched_fields(name) is None:
                bad("summary", "bad placeholder {%s}" % name)
    try:
        return Rule(doc, source)
    except _NodeError as exc:
        raise RuleError("%s: %s" % (source, exc))


# --- bounds (M7.6c, ADR-0008 Amendment B) -------------------------------------------------------------
# A rule may declare which of its thresholds a person may change (raqib rules --threshold, the Rules panel)
# and within what, beside the match that holds them:
#     bounds:
#       k: {min: 1, max: 100}       # a declared threshold: an eq of the match, a whole number > 0, declared once
#       relations:
#         - "k <= r"                # between two bounded thresholds: <= or >=
# A threshold is named by the last part of its field (input_meta.rhythm.k -> k). A rule with no bounds: block
# has no editable threshold; one with `bounds: {}` says so in words. The YAML's own values must lie within
# its bounds and satisfy its relations (else the rule is refused by the loader).
BOUND_KEYS = ("min", "max")
RELATIONS_KEY = "relations"
RELATION = re.compile(r"\s*([a-z_][a-z0-9_]*)\s*(<=|>=)\s*([a-z_][a-z0-9_]*)\s*\Z")


def eq_predicates(node, out=None):
    """Every predicate {field, eq, ...} of a match tree, in order."""
    out = [] if out is None else out
    if isinstance(node, dict):
        if isinstance(node.get("field"), str) and "eq" in node:
            out.append(node)
        for v in node.values():
            eq_predicates(v, out)
    elif isinstance(node, list):
        for v in node:
            eq_predicates(v, out)
    return out


def _whole(value):
    return isinstance(value, int) and not isinstance(value, bool)


def declared_thresholds(doc):
    """{name: {"field", "value"}}: the eq predicates of the match whose value
    is a whole number > 0 and whose field carries one eq only (a threshold
    the YAML declares), named by the field's last part; a name two fields
    share is not one threshold and is left out."""
    preds = eq_predicates((doc or {}).get("match"))
    out, seen = {}, {}
    for p in preds:
        field = p["field"]
        if not (_whole(p["eq"]) and p["eq"] > 0) or sum(1 for q in preds if q["field"] == field) != 1:
            continue
        name = field.rsplit(".", 1)[-1]
        seen[name] = seen.get(name, 0) + 1
        out[name] = {"field": field, "value": p["eq"]}
    return {n: t for n, t in out.items() if seen[n] == 1}


def bounds_problem(doc):
    """Why a rule's bounds: block is not sound, or None."""
    block = doc.get("bounds")
    if not isinstance(block, dict):
        return "must be a mapping of threshold -> {min, max}, and relations"
    declared = declared_thresholds(doc)
    fields = {}
    for name, b in block.items():
        if name == RELATIONS_KEY:
            continue
        if name not in declared:
            return "%r is not a declared threshold of the match (an eq, a whole number > 0, declared once; declared:" \
                   " %s)" % (name, ", ".join(sorted(declared)) or "none")
        if not (isinstance(b, dict) and set(b) == set(BOUND_KEYS) and all(_whole(b[k]) for k in BOUND_KEYS)):
            return "%s: must be {min: N, max: M}, whole numbers" % name
        if not 1 <= b["min"] <= b["max"]:
            return "%s: must have 1 <= min <= max (%r..%r)" % (name, b["min"], b["max"])
        value = declared[name]["value"]
        if not b["min"] <= value <= b["max"]:
            return "%s: the match's own value %d is outside %d..%d" % (name, value, b["min"], b["max"])
        fields[name] = value
    relations = block.get(RELATIONS_KEY, [])
    if not isinstance(relations, list):
        return "relations: must be a list of \"a <= b\" / \"a >= b\""
    for text in relations:
        m = RELATION.match(text) if isinstance(text, str) else None
        if not m:
            return "relations: %r must read \"a <= b\" or \"a >= b\"" % (text,)
        a, op, b = m.groups()
        for name in (a, b):
            if name not in fields:
                return "relations: %r names %s, which has no bounds here" % (text, name)
        if a == b:
            return "relations: %r relates a threshold to itself" % text
        if not (fields[a] <= fields[b] if op == "<=" else fields[a] >= fields[b]):
            return "relations: the match's own values break %r (%s=%d, %s=%d)" % (text, a, fields[a], b, fields[b])
    return None


def bounds_of(doc):
    """{"fields": {name: {"field", "min", "max"}}, "relations": [(small, big, text)]}
    of a sound bounds: block (each relation as small <= big), or None when
    the rule has none."""
    block = doc.get("bounds")
    if not isinstance(block, dict):
        return None
    declared = declared_thresholds(doc)
    fields = {n: {"field": declared[n]["field"], "min": b["min"], "max": b["max"]}
              for n, b in block.items() if n != RELATIONS_KEY and n in declared and isinstance(b, dict)}
    relations = []
    for text in block.get(RELATIONS_KEY) or []:
        m = RELATION.match(text) if isinstance(text, str) else None
        if m:
            a, op, b = m.groups()
            relations.append((a, b, text.strip()) if op == "<=" else (b, a, text.strip()))
    return {"fields": fields, "relations": relations}


def fixture_path_problem(path):
    r"""M7.6 REDO A-1 (ADR-0008 Amendment A): why a fixture path is not a
    relative path that stays inside the directory it is joined to under the
    POSIX AND the Windows path rules alike, on every OS; None when it is
    one. Refused: a non-string or empty path; a root (a leading / or \, so
    also //server and \\?\); a colon anywhere (a drive C: or C:x, an NTFS
    stream); a .. component, split on / and \ both; a path that names no
    file (only . components). ntpath's rules are those
    separators, roots and drives, written out here because the gate's
    child pre-imports only PREIMPORT (tools/gate.py) before a rule file is
    imported; raqib/overlay.py joins every path under ntpath too."""
    if not (isinstance(path, str) and path):
        return "not a non-empty string"
    if path[0] in "/\\":
        return "a root (/ or \\)"
    if ":" in path:
        return "a drive or a colon"
    parts = re.split(r"[\\/]", path)
    if ".." in parts:
        return "a .. component"
    if all(p in ("", ".") for p in parts):
        return "no file name (it is the directory itself)"
    return None


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
        if "holes" in doc:
            _check_lines(doc["holes"], "holes", bad)
        return
    if "holes" in doc:
        bad("holes", "only a demand or an anchor lists holes; a signature lists them as evasion"
                     " (ADR-0002 Amendment G, G-6)")
    if "evasion" not in doc:
        bad("evasion", "missing; a signature must list its known evasions, one line each"
                       " (ADR-0002: a signature with no listed evasion is invalid)")
    _check_lines(doc["evasion"], "evasion", bad)


def _check_lines(items, field, bad):
    """evasion and holes: a non-empty list of non-empty one-line strings."""
    if not (isinstance(items, list) and items):
        bad(field, "must be a non-empty list of one-line strings, not %r" % (items,))
    for i, item in enumerate(items):
        if not (isinstance(item, str) and item.strip() and item.isprintable()):
            bad("%s[%d]" % (field, i), "must be a non-empty one-line string of printable characters, not %r"
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
    if op == "under_any":   # M4.2b: a literal list, placed as outside_any places context[key]
        if not context_ok(arg):
            raise _NodeError("%s: must be a non-empty list of paths" % at)
        entries = list(arg)

        def under_any(line, ctx):
            anchor = ctx.get("root") or line.get("cwd")
            path = _place(get(line), line.get("cwd"))
            placed = [_place(e, anchor) for e in entries]
            if path is None or any(r is None for r in placed):
                return UNKNOWN
            return any(_under(path, r) for r in placed)
        return under_any
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


# A Windows path (M5.1b): a drive letter with a separator, or a UNC path,
# recognised by its backslashes only (C-5), so POSIX //x stays POSIX.
WINDOWS_PATH = re.compile(r"[A-Za-z]:[\\/]|\\\\[^\\/]")
# Under a Windows anchor these cannot be placed (C-2): a rooted path with no
# drive (\x, on the current drive) or a drive-relative one (C:x, against that
# drive's own current directory, which the trace does not record).
WINDOWS_UNPLACEABLE = re.compile(r"\\|[A-Za-z]:")
# The Win32 file and device namespace prefixes \\?\ and \\.\ (C-9), in front of
# a drive path or of UNC\server\share. Only those two are stripped: any other
# path under a prefix (\\.\pipe\x, \\?\Volume{...}\x) keeps the UNC reading,
# with ? or . as its server, so it is never placed inside a project.
WINDOWS_PREFIX = re.compile(r"\\\\[?.]\\(?:(?=[A-Za-z]:[\\/])|[Uu][Nn][Cc](?=\\[^\\/]))")
# Case folding of Windows paths is ASCII A-Z only (C-11), as NTFS's upcase table
# does for ASCII. str.lower would also fold non-ASCII letters, some to ASCII
# (KELVIN SIGN U+212A to k), and so join directories that Windows keeps apart.
ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def norm_path(path):
    r"""The one path normaliser of the rules (M5.1b E1): ("posix" or
    "windows", normalised path), or None for a value that is not a non-empty
    string. _place returns its result, _under compares two of them, and the
    context root check reads it. Nothing else normalises a path.

    - A drive-letter path (X:\ or X:/) or a UNC path (\\server\share) is a
      Windows path: every \ becomes /, . and .. are resolved lexically and
      never climb above the drive root or the share, and ASCII case is
      folded, A-Z to a-z only (C-11): C:\Users\Bob and c:/users/bob/ are
      one path, "c:/users/bob". A non-ASCII letter is kept as written: a
      directory spelled C:\WOR + U+212A KELVIN SIGN is not C:\work (str.lower
      would make it so), and a non-ASCII case difference that Windows folds
      (U+00C9 and U+00E9) makes two paths here. A \\?\ or \\.\ prefix is
      stripped first (C-9) when a drive path or UNC\server\share follows:
      \\?\C:\x is C:\x, and \\?\UNC\srv\share\x is \\srv\share\x.
    - Any other string is a POSIX path, normalised as before M5.1b
      (posixpath.normpath, a leading // collapsed to /) and case-sensitive:
      /work/P and /work/p are two paths. A \ in it is a file name character.

    /mnt/c/Users/x (WSL) and C:\Users\x are NOT equal (ruling Q-6): one is a
    POSIX path, the other a Windows path, and a path of one system is never
    under a directory of the other. Symlinks, junctions, subst drives and
    8.3 short names are not resolved: this is lexical only.
    """
    if not isinstance(path, str) or not path:
        return None
    if not WINDOWS_PATH.match(path):
        placed = posixpath.normpath(path)
        if placed.startswith("//"):
            placed = "/" + placed.lstrip("/")
        return ("posix", placed)
    prefix = WINDOWS_PREFIX.match(path)
    if prefix:   # C-9: \\?\C:\x -> C:\x; \\?\UNC\srv\share\x -> \srv\share\x -> \\srv\share\x
        path = path[prefix.end():]
        if path.startswith("\\"):
            path = "\\" + path
    text = path.replace("\\", "/")
    if text[1] == ":":
        head, rest = text[:2], text[2:]
    else:  # //server/share/rest: the share is the root
        parts = [p for p in text[2:].split("/") if p]
        head, rest = "//" + "/".join(parts[:2]), "/".join(parts[2:])
    rest = posixpath.normpath("/" + rest.lstrip("/"))   # one leading /: .. stops at the root
    return ("windows", (head + rest).translate(ASCII_FOLD))   # C-11: A-Z only


def _absolute(value):
    """norm_path(value) when value is absolute on either system (POSIX /...,
    or a Windows drive or UNC path), else None. A ~ path is not absolute
    here: it can be a path, never an anchor."""
    placed = norm_path(value)
    if placed is None or (placed[0] == "posix" and not placed[1].startswith("/")):
        return None
    return placed


def _place(path, cwd):
    """norm_path's result for path made absolute, or None if it cannot be
    placed. A relative path is joined to cwd, which must be absolute on
    either system; under a Windows cwd \\x and C:x cannot be placed (C-2).
    A ~ path counts as absolute (POSIX)."""
    if not isinstance(path, str) or not path:
        return None
    if not (path.startswith("/") or path.startswith("~") or WINDOWS_PATH.match(path)):
        anchor = _absolute(cwd)
        if anchor is None:
            return None
        if anchor[0] == "windows" and WINDOWS_UNPLACEABLE.match(path):
            return None
        path = cwd.rstrip("/") + "/" + path
    placed = norm_path(path)
    if placed[0] == "posix" and not (placed[1].startswith("/") or placed[1].startswith("~")):
        return None
    return placed


def _under(path, root):
    """True if path is root or inside it. Both are norm_path() results (as
    _place returns them); a path of one system is never under a directory of
    the other, so /mnt/c/x is not under C:\\ nor \\\\srv\\share\\x under /."""
    if path[0] != root[0]:
        return False
    path, root = path[1], root[1].rstrip("/") or "/"
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
    if "root" in context and _absolute(context["root"]) is None:   # absolute on neither system (E2)
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
        if unknown and rule.require is not None:   # H-3: the cause of each seq
            shown = ", ".join("%s:%d (%s)" % (u[0], u[1], u.cause) for u in unknown[:5])
            notes.append({"rule_id": rule.id, "status": "partial",
                          "detail": "could not judge %d line(s) (session:seq %s%s)" % (
                              len(unknown), shown, " ..." if len(unknown) > 5 else "")})
        elif unknown:
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
    if rule.require is not None:
        return _judge_require(rule, records, context)
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
                                 _render(rule.summary, rec, rec["seq"], 1, rule, context)))
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
                             _render(rule.summary, entry["last"], entry["last"]["seq"], count, rule,
                                     context)))
    return out, unknown


def _ghosts(records):
    """For each record, the post line it stands for when it is a pre with no
    post line of its (session_id, seq) later in the trace (G-7): the pre with
    phase post and no ok; else None."""
    later_posts = set()
    out = [None] * len(records)
    for i in range(len(records) - 1, -1, -1):
        rec = records[i]
        key = (rec["session_id"], rec["seq"])
        if rec.get("phase") == "post":
            later_posts.add(key)
        elif rec.get("phase") == "pre" and key not in later_posts:
            ghost = {k: v for k, v in rec.items() if k != "ok"}
            ghost["phase"] = "post"
            out[i] = ghost
    return out


def _value(node, rec, ghost, ctx):
    """node on a line; a pre with no post (ghost) is also its missing post,
    which can make the line unknown, never true."""
    return _value_why(node, rec, ghost, ctx)[0]


def _value_why(node, rec, ghost, ctx):
    """(value, cause): the cause names why a line is unknown (H-3)."""
    value = node(rec, ctx)
    if value is True:
        return value, None
    if value is UNKNOWN:
        return value, CAUSE_TRIGGER
    if ghost is not None and node(ghost, ctx) is not False:
        return UNKNOWN, CAUSE_NO_POST
    return value, None


class _Why(tuple):
    """(session_id, seq) of a line a require rule could not judge, with the
    cause (H-3); compares and formats as the pair."""

    def __new__(cls, key, cause):
        self = tuple.__new__(cls, key)
        self.cause = cause
        return self


def _judge_require(rule, records, context):
    """(findings, unknown) of a require rule (see the module docstring).
    H-2: a true evidence line wins over unknown ones; evidence is unknown
    only when no evidence line is true and one is unknown. H-3: a trigger
    that cannot be judged but whose evidence is true is not unknown (it
    cannot fire); every unknown entry carries its cause."""
    req = rule.require
    ghosts = _ghosts(records)
    last_ts = {}
    unknown = []
    out = []
    if "before" in req:
        evidence = {}   # session_id -> "true" | "unknown"
        seen = set()
        for rec, ghost in zip(records, ghosts):
            ts = _ts(rec, last_ts)
            sid, key = rec["session_id"], (rec["session_id"], rec["seq"])
            e = _value(req["before"], rec, ghost, context)
            if e is True:
                evidence[sid] = "true"
            elif e is UNKNOWN and evidence.get(sid) != "true":
                evidence[sid] = "unknown"
            t, cause = _value_why(rule.match, rec, ghost, context)
            if t is False or key in seen or evidence.get(sid) == "true":
                continue
            seen.add(key)
            if t is UNKNOWN:
                unknown.append(_Why(key, cause))
            elif evidence.get(sid) == "unknown":
                unknown.append(_Why(key, CAUSE_EVIDENCE))
            else:
                out.append(_emit(rule, sid, [rec["seq"]], ts, _render(rule.summary, rec, rec["seq"], 1, rule,
                                                                          context)))
        return out, unknown
    pending = {}   # session_id -> [[key, cause]]; cause None: open, else why it is unknown
    for rec, ghost in zip(records, ghosts):
        ts = _ts(rec, last_ts)
        sid, key = rec["session_id"], (rec["session_id"], rec["seq"])
        waiting = pending.setdefault(sid, [])
        d = _value(req["until"], rec, ghost, context)
        if d is True and waiting:
            unknown += [_Why(k, cause) for k, cause in waiting if cause is not None]
            fire = sorted({k[1] for k, cause in waiting if cause is None})
            if fire:
                seqs = sorted(set(fire) | {rec["seq"]})
                out.append(_emit(rule, sid, seqs, ts, _render(rule.summary, rec, rec["seq"], len(fire), rule,
                                                              context)))
            del waiting[:]
        elif d is UNKNOWN and waiting:
            unknown += [_Why(k, cause or CAUSE_DEADLINE) for k, cause in waiting]
            del waiting[:]
        elif d is False and waiting:
            e = _value(req["after"], rec, ghost, context)
            if e is True:
                del waiting[:]            # H-2, H-3: open and unknown triggers alike
            elif e is UNKNOWN:
                for item in waiting:
                    item[1] = item[1] or CAUSE_EVIDENCE
        t, cause = _value_why(rule.match, rec, ghost, context)
        if t is not False and all(k != key for k, _ in waiting):
            waiting.append([key, None if t is True else cause])
    for waiting in pending.values():
        unknown += [_Why(k, cause or CAUSE_NO_DEADLINE) for k, cause in waiting]
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


def _shown(v):
    text = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
    return "".join(c if c.isprintable() else "?" for c in text)


def _cut(text):
    if len(text) > SUMMARY_VALUE_MAX:
        keep = SUMMARY_VALUE_MAX - 3
        text = text[:keep // 2] + "..." + text[-(keep - keep // 2):]
    return text


def _render(template, line, seq, count, rule=None, ctx=None):
    held = []   # M9.1: what the match holds on this line, read once if a {matched:...} asks for it

    def value(match):
        name = match.group(1)
        if name == "seq":
            return str(seq)
        if name == "count":
            return str(count)
        fields = _matched_fields(name)
        if fields is not None:
            if not held:
                held.append(rule.explain(line, ctx or {})[1] if rule is not None and rule.explain else [])
            return _cut(matched_text(held[0], fields))
        v = _getter(name)(line)
        if v is MISSING or v is None:
            return "-"
        return _cut(_shown(v))
    return PLACEHOLDER.sub(value, template)


# --- {matched:...} (M9.1, ADR-0010 decision 4) ------------------------------------------------------------
# The sentence names what the rule's own list holds on the cited line, not the command's first word. The
# explainer walks the same match tree the compiled rule judges with, three-valued, and returns with the value
# the (field, value) pairs its value predicates held on, from the branches that hold only.

MATCHED = "matched:"
VALUE_OPS = ("eq", "in", "has_any", "regex", "prefix", "glob")


def _matched_fields(name):
    """The fields of a {matched:F1,F2} placeholder, or None when name is not one."""
    if not name.startswith(MATCHED):
        return None
    fields = name[len(MATCHED):].split(",")
    return fields if fields and all(FIELD.match(f) for f in fields) else None


def matched_text(held, fields):
    """The values of held [(field, value)] for these fields, field by field, each once, joined; "-": none."""
    out = []
    for field in fields:
        for f, v in held:
            text = _shown(v)
            if f == field and text not in out:
                out.append(text)
    return ", ".join(out) if out else "-"


def _explainer(node, where, rule):
    """fn(line, ctx) -> (value, [(field, held value)]): value is the compiled node's own (the same predicates,
    combined by _all and _any); the pairs come from the value predicates of the branches that are true."""
    keys = set(node)
    if keys in ({"all"}, {"any"}):
        (kind,) = keys
        parts = [_explainer(n, "%s.%s[%d]" % (where, kind, i), rule) for i, n in enumerate(node[kind])]
        combine = _all if kind == "all" else _any

        def branch(line, ctx):
            results = [p(line, ctx) for p in parts]
            v = combine([r for r, _ in results])
            return v, ([pair for r, pairs in results if r is True for pair in pairs] if v is True else [])
        return branch
    if keys == {"not"}:
        inner = _explainer(node["not"], where + ".not", rule)

        def negate(line, ctx):   # a not names nothing: what it holds is what the rule refuses
            v = inner(line, ctx)[0]
            return (UNKNOWN if v is UNKNOWN else not v), []
        return negate
    test = _predicate(node, where, rule)
    field = node["field"]
    (op,) = [k for k in node if k != "field"]
    get = _getter(field)

    def leaf(line, ctx):
        v = test(line, ctx)
        if v is not True or op not in VALUE_OPS:
            return v, []
        got = get(line)
        if op == "has_any":
            return v, [(field, x) for x in got if any(_same(x, a) for a in node[op])]
        return v, [(field, got)]
    return leaf
