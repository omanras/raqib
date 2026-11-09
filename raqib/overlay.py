"""The rules overlay (M7.6, ADR-0008 decisions 1-5): the person's choice of
which rules watch and of their declared thresholds, kept outside the
package in ~/.raqib/rules.yaml, and the person's own rules in
~/.raqib/rules.d/.

The overlay file is yamlite's subset (raqib/rules/yamlite.py reads it; this
module writes it, every string double-quoted):

    # Raqib rules overlay (ADR-0008): written by `raqib rules` and the window's Rules panel
    raqib_overlay: 1
    rules:
      HOST-RHYTHM:
        status: "off"                  # "on" | "off" (quoted: yamlite refuses plain on/off)
        since: "2026-11-09T10:00:00Z"  # when the entry was last written
        thresholds:
          k: 5                         # a declared threshold of the rule, within BOUNDS

It is an overlay, never a copy of the catalog: the catalog stays the
package's and is read as before; the overlay is applied on top at load
(engine.load_catalog(..., overlay=PATH, user_rules=DIR)). What it may change
of a rule is its status (off: the engine's existing `status: disabled`) and
the `eq` value of a declared threshold; never its kind, class, severity,
budget or fixtures (apply() checks that the rule it compiles keeps them).

A declared threshold is an `eq` predicate of the rule's match on a field of
BOUNDS whose value is a positive int, declared once in the rule: HOST-RHYTHM's
k, w and r (input_meta.rhythm.*), AGENT-DARK-LIVE's streak and live_window.
The bounds are built in here, conservative, because the catalog YAMLs declare
none (a `bounds:` block in the YAMLs is the Table's later task): k 1..100,
w 1..3600 seconds, r 1..1000 rounds, streak 1..100, live_window 1..1000 and
never below the rule's streak.

A malformed overlay (not yamlite, or not the shape above) is ONE hole and
nothing of it is applied (ADR-0008 decision 2: never half-applied). An entry
of a sound file that names an unknown rule or field, a field that is not a
declared eq threshold, a value outside its bounds, or "on" for a rule its
YAML disables (A6: a rule over budget is disabled, not tuned live) is
refused with the reason, said at the start of every watch, and not applied;
the other entries apply.

A rule under rules.d joins the catalog only when the engine's loader and
the fixture runner accept it (A6: fixtures positive and negative, a measured
false-positive rate within its budget), its fixture paths relative to
rules.d; its id may not be a catalog rule's. It is marked origin user
everywhere it is shown. Every refusal is said, never dropped (A3).

Writes (A4): only overlay_path() (atomically: a temp file in ~/.raqib, then
os.replace) and files under user_dir() (add_rule's copies). Nothing here
reaches a watched process or a project.
"""
from __future__ import annotations

import copy
import datetime
import os
import tempfile

from raqib.rules import engine, fixtures, yamlite

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "raqib", "rules", "catalog")
DIR_NAME = ".raqib"
OVERLAY_NAME = "rules.yaml"
USER_DIR_NAME = "rules.d"
FORMAT = 1
TOP_KEYS = ("raqib_overlay", "rules")
ENTRY_KEYS = ("status", "since", "thresholds")
WORDS = ("on", "off")
# The built-in bounds of the declared thresholds (field -> (low, high)); see the module docstring.
BOUNDS = {"input_meta.rhythm.k": (1, 100), "input_meta.rhythm.w": (1, 3600), "input_meta.rhythm.r": (1, 1000),
          "input_meta.streak": (1, 100), "input_meta.live_window": (1, 1000)}
# A threshold that may not be below another of the same rule: live_window >= streak.
AT_LEAST = {"input_meta.live_window": "input_meta.streak"}
HEADER = "# Raqib rules overlay (ADR-0008): written by `raqib rules` and the window's Rules panel; edit with care\n"
NEXT_WATCH = "applies to the next watch (a running watch keeps the rules it started with)"


class OverlayError(ValueError):
    """A change refused, with the reason (raqib rules exits 2)."""


class Catalog(list):
    """The rules, as a list, with what the overlay did (`overlay`, describe())."""
    overlay = None


def raqib_dir(home=None):
    return os.path.join(home or os.path.expanduser("~"), DIR_NAME)


def overlay_path(home=None):
    return os.path.join(raqib_dir(home), OVERLAY_NAME)


def user_dir(home=None):
    return os.path.join(raqib_dir(home), USER_DIR_NAME)


def now_text(now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- thresholds -------------------------------------------------------------------------------

def _predicates(node, out):
    if isinstance(node, dict):
        if isinstance(node.get("field"), str):
            out.append(node)
        for v in node.values():
            _predicates(v, out)
    elif isinstance(node, list):
        for v in node:
            _predicates(v, out)
    return out


def _short(field):
    return field.rsplit(".", 1)[-1]


def thresholds(rule):
    """{name: {"field", "value", "low", "high"}} of a rule's declared
    thresholds, in match order (name: the field's last part, k, w, r,
    streak, live_window)."""
    preds = _predicates((rule.doc or {}).get("match"), [])
    out = {}
    for p in preds:
        field = p["field"]
        if field not in BOUNDS or "eq" not in p:
            continue
        value = p["eq"]
        if sum(1 for q in preds if q["field"] == field) != 1:
            continue   # declared more than once: not one threshold
        if not (isinstance(value, int) and not isinstance(value, bool) and value > 0):
            continue
        low, high = BOUNDS[field]
        out[_short(field)] = {"field": field, "value": value, "low": low, "high": high}
    return out


def resolve(rule, name):
    """The threshold name of `name` (a short name or the dotted field) in
    rule, or OverlayError with the reason."""
    table = thresholds(rule)
    for short, t in table.items():
        if name in (short, t["field"]):
            return short
    preds = _predicates((rule.doc or {}).get("match"), [])
    same = [p for p in preds if name in (p["field"], _short(p["field"]))]
    if not same:
        raise OverlayError("%s has no field %r (its declared thresholds: %s)" % (
            rule.id, name, ", ".join(sorted(table)) or "none"))
    if not any("eq" in p for p in same):
        raise OverlayError("%r is not an eq value of %s: only a declared eq threshold can change (ADR-0008)"
                           % (name, rule.id))
    raise OverlayError("%r is an eq of %s but not a declared threshold (no bound in raqib/overlay.py: the gate's"
                       " fields and words are fixed; declared thresholds: %s)" % (
                           name, rule.id, ", ".join(sorted(table)) or "none"))


def check_value(rule, name, value, others=None):
    """OverlayError when value is not a whole number within the bounds of
    the threshold `name` of rule. others: the other thresholds' values in
    effect ({name: value}), for live_window >= streak."""
    t = thresholds(rule)[name]
    if not (isinstance(value, int) and not isinstance(value, bool)):
        raise OverlayError("%s %s must be a whole number, not %r" % (rule.id, name, value))
    if not t["low"] <= value <= t["high"]:
        raise OverlayError("%s %s = %d is outside its bounds %d..%d (raqib/overlay.py BOUNDS)" % (
            rule.id, name, value, t["low"], t["high"]))
    floor_field = AT_LEAST.get(t["field"])
    if floor_field is not None:
        floor_name = _short(floor_field)
        current = dict((k, v["value"]) for k, v in thresholds(rule).items())
        current.update(others or {})
        floor = current.get(floor_name)
        if floor is not None and value < floor:
            raise OverlayError("%s %s = %d is below its %s (%d): the live window is never shorter than the streak"
                               % (rule.id, name, value, floor_name, floor))
    for other_field, base_field in AT_LEAST.items():
        if base_field == t["field"]:
            other = _short(other_field)
            current = dict((k, v["value"]) for k, v in thresholds(rule).items())
            current.update(others or {})
            if other in current and current[other] < value:
                raise OverlayError("%s %s = %d is above its %s (%d): the live window is never shorter than the"
                                   " streak; raise %s first" % (rule.id, name, value, other, current[other], other))


# --- the file ---------------------------------------------------------------------------------

def empty():
    return {"rules": {}}


def parse(text):
    """The overlay mapping of a file's text, or OverlayError (malformed:
    one hole, nothing applied). Only the shape is checked here; check()
    judges the entries against the catalog."""
    try:
        doc = yamlite.loads(text)
    except yamlite.YamlError as exc:
        raise OverlayError("not the YAML subset Raqib reads (%s)" % exc)
    except RecursionError:
        raise OverlayError("nesting too deep")
    if doc is None:
        return empty()
    if not isinstance(doc, dict):
        raise OverlayError("the overlay must hold a mapping with rules:")
    stray = sorted(k for k in doc if k not in TOP_KEYS)
    if stray:
        raise OverlayError("unknown top-level key(s) %s (only %s)" % (", ".join(stray), ", ".join(TOP_KEYS)))
    if "raqib_overlay" in doc and doc["raqib_overlay"] != FORMAT:
        raise OverlayError("raqib_overlay must be %d, not %r" % (FORMAT, doc["raqib_overlay"]))
    rules = doc.get("rules")
    if rules is None:
        rules = {}
    if not isinstance(rules, dict):
        raise OverlayError("rules: must be a mapping of rule id -> {status, since, thresholds}")
    for rid, entry in rules.items():
        if not isinstance(entry, dict) or not entry:
            raise OverlayError("rules.%s: must be a mapping with status and/or thresholds" % rid)
        bad = sorted(k for k in entry if k not in ENTRY_KEYS)
        if bad:
            raise OverlayError("rules.%s: unknown key(s) %s (only %s)" % (rid, ", ".join(bad), ", ".join(ENTRY_KEYS)))
        if "status" in entry and entry["status"] not in WORDS:
            raise OverlayError("rules.%s.status: must be \"on\" or \"off\", not %r" % (rid, entry["status"]))
        if "since" in entry and not (isinstance(entry["since"], str) and entry["since"].strip()):
            raise OverlayError("rules.%s.since: must be a non-empty string" % rid)
        th = entry.get("thresholds", {})
        if not isinstance(th, dict):
            raise OverlayError("rules.%s.thresholds: must be a mapping of name -> whole number" % rid)
        for name, value in th.items():
            if not (isinstance(value, int) and not isinstance(value, bool)):
                raise OverlayError("rules.%s.thresholds.%s: must be a whole number, not %r" % (rid, name, value))
        if "status" not in entry and not th:
            raise OverlayError("rules.%s: says nothing (no status, no thresholds)" % rid)
    return {"rules": {rid: dict(entry) for rid, entry in rules.items()}}


def read(path):
    """(doc, state, hole): state "absent" (no file: empty doc), "read", or
    "malformed" (hole: the reason; the doc is empty, nothing applies)."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return empty(), "absent", None
    except (OSError, UnicodeDecodeError) as exc:
        return empty(), "malformed", "%s cannot be read (%s): nothing of it is applied" % (path, exc)
    try:
        return parse(text), "read", None
    except OverlayError as exc:
        return empty(), "malformed", "%s is malformed: %s: nothing of it is applied" % (path, exc)


def _quote(text):
    out = []
    for c in str(text):
        if c in '"\\':
            out.append("\\" + c)
        elif " " <= c <= "~":
            out.append(c)
        else:
            out.append("\\u%04x" % ord(c))
    return '"%s"' % "".join(out)


def dumps(doc):
    """The overlay as text in yamlite's subset (parse(dumps(d)) == d)."""
    lines = [HEADER, "raqib_overlay: %d\n" % FORMAT]
    rules = doc.get("rules") or {}
    if not rules:
        lines.append("rules: {}\n")
        return "".join(lines)
    lines.append("rules:\n")
    for rid in sorted(rules):
        entry = rules[rid]
        lines.append("  %s:\n" % rid)
        if "status" in entry:
            lines.append("    status: %s\n" % _quote(entry["status"]))
        if "since" in entry:
            lines.append("    since: %s\n" % _quote(entry["since"]))
        th = entry.get("thresholds") or {}
        if th:
            lines.append("    thresholds:\n")
            for name in sorted(th):
                lines.append("      %s: %d\n" % (name, th[name]))
    return "".join(lines)


def _atomic_write(path, data):
    """data (bytes) to path: a temp file in its directory, then os.replace."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".raqib-rules-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.remove(tmp)


def write(doc, home=None):
    """Write the overlay (atomically) to overlay_path(home); its path."""
    path = overlay_path(home)
    text = dumps(doc)
    assert parse(text) == {"rules": doc.get("rules") or {}}, "the overlay writer and reader disagree"
    try:
        _atomic_write(path, text.encode("ascii"))
    except OSError as exc:
        raise OverlayError("cannot write %s: %s" % (path, exc.strerror or exc))
    return path


# --- judging the entries against the catalog ------------------------------------------------------

def check_entry(rule, entry):
    """[reasons] an entry of a sound overlay is refused for (empty: it applies)."""
    reasons = []
    if rule is None:
        return ["no such rule in the catalog or rules.d"]
    if entry.get("status") == "on" and getattr(rule, "status", "active") == "disabled":
        reasons.append("its YAML says status: disabled (A6: a rule over its budget is disabled, not tuned live);"
                       " the overlay cannot turn it on")
    values = {}
    for name, value in (entry.get("thresholds") or {}).items():
        try:
            values[resolve(rule, name)] = value
        except OverlayError as exc:
            reasons.append(str(exc))
    for name, value in values.items():
        try:
            check_value(rule, name, value, values)
        except OverlayError as exc:
            reasons.append(str(exc))
    return reasons


def _set_eq(match, field, value):
    for p in _predicates(match, []):
        if p["field"] == field and "eq" in p:
            p["eq"] = value


def apply(rules, doc, path, state="read", hole=None):
    """A Catalog of rules with the overlay doc applied (see the module
    docstring), and its .overlay (describe()'s source)."""
    by_id = {r.id: r for r in rules}
    entries = (doc or {}).get("rules") or {}
    refused, applied = [], []
    out = Catalog()
    for rule in rules:
        entry = entries.get(rule.id)
        reasons = check_entry(rule, entry) if entry else []
        if entry and reasons:
            refused.append("%s: %s" % (rule.id, "; ".join(reasons)))
        if not entry or reasons:
            new = rule
            new.off_by = getattr(rule, "off_by", None)
        else:
            new_doc = copy.deepcopy(rule.doc)
            changed = {}
            table = thresholds(rule)
            for name, value in sorted((entry.get("thresholds") or {}).items()):
                short = resolve(rule, name)
                field = table[short]["field"]
                if table[short]["value"] != value:
                    changed[short] = (table[short]["value"], value)
                _set_eq(new_doc["match"], field, value)
            off = entry.get("status") == "off"
            since = entry.get("since") or "-"
            source = rule.source
            if off:
                new_doc["status"] = "disabled"
                source = "the overlay %s (off since %s; rule file %s)" % (path, since, rule.source)
            new = engine.compile_rule(new_doc, source)
            for attr in ("kind", "cls", "severity", "fp_budget", "fixtures", "id"):
                if getattr(new, attr) != getattr(rule, attr):   # never: only status and eq values change
                    raise OverlayError("the overlay changed %s of %s" % (attr, rule.id))
            new.origin = getattr(rule, "origin", "package")
            new.base_source = rule.source
            new.off_by = path if off else None
            new.off_since = since if off else None
            new.changed = changed
            if off:
                applied.append("%s off (since %s)" % (rule.id, since))
            elif entry.get("status") == "on":
                applied.append("%s on" % rule.id)
            for name, (was, now) in sorted(changed.items()):
                applied.append("%s %s = %d (its YAML: %d)" % (rule.id, name, now, was))
        if not hasattr(new, "origin"):
            new.origin = "package"
        out.append(new)
    for rid in sorted(set(entries) - set(by_id)):
        refused.append("%s: no such rule in the catalog or rules.d" % rid)
    out.overlay = {"path": path, "file": state, "hole": hole, "refused": refused, "applied": applied}
    return out


def load_user_rules(directory, taken):
    """(rules, refused): the rules of directory/*.yaml the loader and the
    fixture runner accept (fixtures relative to directory), each marked
    origin user; refused: one reason per file (A3: said, never dropped)."""
    rules, refused = [], []
    if not directory or not os.path.isdir(directory):
        return rules, refused
    names = sorted(os.listdir(directory))
    for name in names:
        if name.lower().endswith((".yml", ".yaml")) and not name.endswith(".yaml"):
            refused.append("%s: a rule file must end in .yaml" % os.path.join(directory, name))
    seen = set(taken)
    for name in names:
        if not name.endswith(".yaml"):
            continue
        path = os.path.join(directory, name)
        try:
            rule = validate_rule(path, directory, seen)
        except OverlayError as exc:
            refused.append(str(exc))
            continue
        rule.origin = "user"
        seen.add(rule.id)
        rules.append(rule)
    return rules, refused


def validate_rule(path, root, taken=()):
    """The rule of a YAML file when the engine's loader and the fixture
    runner accept it (fixtures relative to root), else OverlayError with
    the loader's or the runner's reason."""
    try:
        rule = engine.load_rule(path)
    except engine.RuleError as exc:
        raise OverlayError("%s refused by the loader: %s" % (path, exc))
    if rule.id in taken:
        raise OverlayError("%s: rule id %s is already in the catalog or rules.d" % (path, rule.id))
    try:
        result = fixtures.check_rule(rule, root)
    except (fixtures.FixtureError, OSError, ValueError) as exc:
        raise OverlayError("%s refused by the fixture runner: %s" % (path, exc))
    if result["verdict"] not in ("ok", "disabled"):
        missed = [p["path"] for p in result["positives"] if not p["fired"]]
        raise OverlayError("%s refused by the fixture runner: %s (fp_rate %s, budget %s, %d measured, %d unmeasured%s)"
                           % (path, result["verdict"], result["fp_rate"], result["fp_budget"], result["measured"],
                              result["unmeasured"], "; positives missed: %s" % ", ".join(missed) if missed else ""))
    return rule


def build(rules, overlay=None, user_rules=None):
    """engine.load_catalog's overlay step: the catalog rules, the rules of
    user_rules (rules.d), then the overlay file at `overlay` on top."""
    rules = list(rules)
    for r in rules:
        r.origin = getattr(r, "origin", "package")
    users, user_refused = load_user_rules(user_rules, {r.id for r in rules})
    combined = rules + sorted(users, key=lambda r: r.id)   # the catalog's order kept; the person's after it
    if overlay is None:
        doc, state, hole = empty(), "absent", None
    else:
        doc, state, hole = read(overlay)
    out = apply(combined, doc, overlay, state, hole)
    out.overlay.update(user_dir=user_rules, user=[{"rule_id": r.id, "source": r.source} for r in users],
                       user_refused=user_refused)
    return out


def load(home=None, catalog=None):
    """The catalog as a watch loads it: the package's, rules.d and the overlay."""
    return engine.load_catalog(catalog or CATALOG, overlay=overlay_path(home), user_rules=user_dir(home))


# --- what is said ----------------------------------------------------------------------------------

def describe(rules):
    """What the overlay did, JSON-able: watch.json and the host state keep
    it as rules_overlay. off lists every rule that judges nothing: by the
    overlay (since) or by its YAML (status: disabled, A6)."""
    info = dict(getattr(rules, "overlay", None) or {"path": None, "file": "not loaded", "hole": None,
                                                    "refused": [], "applied": []})
    info.setdefault("user", [{"rule_id": r.id, "source": r.source} for r in rules
                             if getattr(r, "origin", "package") == "user"])
    info.setdefault("user_refused", [])
    info.setdefault("user_dir", None)
    off = []
    for r in rules:
        if getattr(r, "off_by", None):
            off.append({"rule_id": r.id, "by": "the overlay %s" % r.off_by, "since": getattr(r, "off_since", None),
                        "severity": r.severity, "kind": r.kind})
        elif r.status == "disabled":
            off.append({"rule_id": r.id, "by": "its YAML (status: disabled, A6)", "since": None,
                        "severity": r.severity, "kind": r.kind})
    info["off"] = off
    info["thresholds"] = [{"rule_id": r.id, "name": name, "value": now, "yaml": was}
                          for r in rules for name, (was, now) in sorted((getattr(r, "changed", None) or {}).items())]
    kinds = sorted({r.kind for r in rules})
    info["kinds_off"] = [k for k in kinds if all(r.status == "disabled" for r in rules if r.kind == k)]
    return info


def off_text(info):
    """"N rules off: <ids>", or None when no rule is off."""
    off = (info or {}).get("off") or []
    if not off:
        return None
    return "%d rule%s off: %s" % (len(off), "" if len(off) == 1 else "s", ", ".join(o["rule_id"] for o in off))


def start_lines(info):
    """The lines every watch prints at its start (ADR-0008 decision 2, A3)."""
    out = []
    path = info.get("path")
    state = info.get("file")
    if state == "absent":
        out.append("rules overlay %s: none (every rule as its YAML declares it)" % path)
    elif state == "malformed":
        out.append("rules overlay: HOLE: %s" % info.get("hole"))
    elif state == "read":
        out.append("rules overlay %s: %d applied, %d refused" % (path, len(info.get("applied") or []),
                                                                 len(info.get("refused") or [])))
    else:
        out.append("rules overlay: not loaded (the catalog as its YAMLs declare it)")
    out += ["rules overlay: applied: %s" % a for a in info.get("applied") or []]
    out += ["rules overlay: REFUSED (not applied): %s" % r for r in info.get("refused") or []]
    out += ["rules: user rule %s (origin: user) from %s" % (u["rule_id"], u["source"]) for u in info.get("user") or []]
    out += ["rules: user rule REFUSED: %s" % r for r in info.get("user_refused") or []]
    text = off_text(info)
    out.append("rules: %s (not judged; each is listed in the final report)" % text if text else
               "rules: no rule off")
    for kind in info.get("kinds_off") or []:
        out.append("rules: every catalog rule of kind %s is off: nothing is judged as a %s by the catalog" % (kind, kind))
    return out


def count_not_judged(rules, records, context, into):
    """A3/A6 (ADR-0008 decision 3): for each rule off, what it would have
    judged: the lines its gate admits (fixtures.gate_of; every line when it
    has no gate) and, run anyway on them (engine.judge, whatever its
    status), how often it would have fired and how many lines it would have
    cited. Accumulated in into[rule_id]; never a finding, never a knock."""
    for r in rules:
        if r.status != "disabled":
            continue
        entry = into.setdefault(r.id, {"lines": 0, "fired": 0, "cited": 0, "note": None})
        gate = fixtures.gate_of(r)
        entry["lines"] += sum(1 for rec in records if isinstance(rec, dict) and (
            not gate or all(rec.get(k) == v for k, v in gate.items())))
        missing = sorted(k for k in r.context_keys if not engine.context_ok((context or {}).get(k)))
        if missing:
            entry["note"] = "what it would have fired is not counted: it needs context %s" % ", ".join(missing)
            continue
        found, _ = engine.judge(r, records, context or {})
        entry["fired"] += len(found)
        entry["cited"] += len({(f["session_id"], s) for f in found for s in f["cited_seq"]})
    return into


def not_judged_text(rule_id, counts):
    c = counts.get(rule_id) or {"lines": 0, "fired": 0, "cited": 0, "note": None}
    text = "not judged by %s (off): %d lines" % (rule_id, c["lines"])
    if c.get("note"):
        return "%s; %s" % (text, c["note"])
    return "%s; it would have fired %d time(s), citing %d line(s)" % (text, c["fired"], c["cited"])


def report_lines(info, counts):
    """The final report's RULES section: each rule off, by whom and since
    when, and what it did not judge; the thresholds changed; the refusals."""
    off = info.get("off") or []
    out = ["RULES OFF (ADR-0008; they do not change the exit code, and the watch is not clean of what they would"
           " have found): %d" % len(off)]
    for o in off:
        out.append("  - %s [%s] off by %s%s: %s" % (
            o["rule_id"], o.get("severity"), o["by"], " since %s" % o["since"] if o.get("since") else "",
            not_judged_text(o["rule_id"], counts)))
    out.append("RULES OVERLAY: %s" % start_lines(info)[0])
    out += ["  - threshold %s %s = %s (its YAML: %s)" % (t["rule_id"], t["name"], t["value"], t["yaml"])
            for t in info.get("thresholds") or []]
    out += ["  - REFUSED (not applied): %s" % r for r in info.get("refused") or []]
    out += ["  - user rule %s (origin: user) from %s" % (u["rule_id"], u["source"]) for u in info.get("user") or []]
    out += ["  - user rule REFUSED: %s" % r for r in info.get("user_refused") or []]
    for kind in info.get("kinds_off") or []:
        out.append("  - every catalog rule of kind %s is off" % kind)
    return out


# --- the listing and the changes (raqib rules, the Rules panel) ---------------------------------------

def listing(rules):
    """One row per rule: id, kind, class, severity, budget, status (on /
    off), origin, thresholds [{name, value, low, high, yaml}]."""
    rows = []
    for r in rules:
        changed = getattr(r, "changed", None) or {}
        rows.append({"id": r.id, "kind": r.kind, "class": r.cls, "severity": r.severity, "budget": r.fp_budget,
                     "status": "off" if r.status == "disabled" else "on",
                     "off_by": "overlay" if getattr(r, "off_by", None) else ("yaml" if r.status == "disabled" else None),
                     "origin": getattr(r, "origin", "package"),
                     "thresholds": [{"name": n, "value": t["value"], "low": t["low"], "high": t["high"],
                                     "yaml": changed.get(n, (t["value"],))[0]} for n, t in thresholds(r).items()]})
    return rows


def threshold_text(t):
    return "%s=%d%s [%d..%d]" % (t["name"], t["value"], "*" if t["value"] != t["yaml"] else "", t["low"], t["high"])


def table_text(rows):
    """The listing as text (raqib rules, the panel): one line per rule."""
    head = ("ID", "KIND", "CLASS", "SEVERITY", "BUDGET", "STATUS", "ORIGIN", "THRESHOLDS")
    body = [(r["id"], r["kind"], r["class"], r["severity"], "%g" % r["budget"],
             r["status"] + (" (yaml)" if r["off_by"] == "yaml" else ""), r["origin"],
             ", ".join(threshold_text(t) for t in r["thresholds"]) or "-") for r in rows]
    widths = [max(len(str(x[i])) for x in [head] + body) for i in range(len(head) - 1)]
    lines = []
    for cells in [head] + body:
        lines.append("  ".join(str(c).ljust(w) for c, w in zip(cells, widths)) + "  " + str(cells[-1]))
    return "\n".join(line.rstrip() for line in lines) + "\n"


def _base(home=None, catalog=None):
    """The catalog and rules.d with no overlay: what the overlay is judged against."""
    return engine.load_catalog(catalog or CATALOG, overlay=None, user_rules=user_dir(home))


def _current(home):
    doc, state, hole = read(overlay_path(home))
    if state == "malformed":
        raise OverlayError("%s; fix it or remove the file by hand (it is never overwritten while malformed)" % hole)
    return doc


def _rule(rules, rid):
    for r in rules:
        if r.id == rid:
            return r
    raise OverlayError("no rule %r in the catalog or rules.d (raqib rules lists them)" % (rid,))


def set_status(rid, word, home=None, now=None, catalog=None):
    """Turn a rule on or off in the overlay; the line said."""
    if word not in WORDS:
        raise OverlayError("a rule is set on or off, not %r" % (word,))
    rule = _rule(_base(home, catalog), rid)
    doc = _current(home)
    entry = dict(doc["rules"].get(rid) or {})
    entry.update(status=word, since=now_text(now))
    reasons = check_entry(rule, entry)
    if reasons:
        raise OverlayError("%s: %s" % (rid, "; ".join(reasons)))
    doc["rules"][rid] = entry
    path = write(doc, home)
    return "%s %s in %s; %s" % (rid, word, path, NEXT_WATCH)


def set_threshold(rid, name, value, home=None, now=None, catalog=None):
    """Set a declared threshold of a rule in the overlay; the line said."""
    rule = _rule(_base(home, catalog), rid)
    short = resolve(rule, name)
    if isinstance(value, str):
        text = value.strip()
        if not (text.isdigit() and text.isascii()):
            raise OverlayError("%s %s must be a whole number, not %r" % (rid, short, value))
        value = int(text)
    doc = _current(home)
    entry = dict(doc["rules"].get(rid) or {})
    th = dict(entry.get("thresholds") or {})
    th = {resolve(rule, k): v for k, v in th.items()}
    th[short] = value
    entry.update(thresholds=th, since=now_text(now))
    reasons = check_entry(rule, entry)
    if reasons:
        raise OverlayError("%s: %s" % (rid, "; ".join(reasons)))
    doc["rules"][rid] = entry
    path = write(doc, home)
    return "%s %s = %d in %s; %s" % (rid, short, value, path, NEXT_WATCH)


def reset(rid, home=None, catalog=None):
    """Remove a rule's entry from the overlay: it is as its YAML declares it."""
    doc = _current(home)
    if rid not in doc["rules"]:
        _rule(_base(home, catalog), rid)
        return "%s has no entry in %s: it is as its YAML declares it" % (rid, overlay_path(home))
    del doc["rules"][rid]
    path = write(doc, home)
    return "%s reset in %s: as its YAML declares it; %s" % (rid, path, NEXT_WATCH)


def add_rule(path, home=None, catalog=None):
    """Validate a person's rule file (the engine's loader and the fixture
    runner, fixtures relative to the file's directory) and copy it, with its
    fixture files, under user_dir(home); the line said. Nothing is copied
    when anything is refused."""
    path = os.path.abspath(path)
    if not path.endswith(".yaml"):
        raise OverlayError("%s: a rule file must end in .yaml" % path)
    src_root = os.path.dirname(path)
    target_dir = user_dir(home)
    taken = {r.id for r in _base(home, catalog)}
    rule = validate_rule(path, src_root, taken)
    copies = [(path, os.path.join(target_dir, rule.id + ".yaml"))]
    for kind in ("positive", "negative"):
        for p in rule.fixtures[kind]:
            copies.append((os.path.join(src_root, p), os.path.join(target_dir, p)))
    plan = []
    for src, dst in copies:
        try:
            with open(src, "rb") as f:
                data = f.read()
        except OSError as exc:
            raise OverlayError("%s cannot be read: %s" % (src, exc.strerror or exc))
        if os.path.exists(dst):
            with open(dst, "rb") as f:
                if f.read() != data:
                    raise OverlayError("%s exists in rules.d with other content: nothing copied" % dst)
        plan.append((dst, data))
    try:
        for dst, data in plan:
            _atomic_write(dst, data)
    except OSError as exc:
        raise OverlayError("cannot write under %s: %s" % (target_dir, exc.strerror or exc))
    return "%s added as %s (origin: user; %d fixture file(s) copied; %s)" % (
        rule.id, copies[0][1], len(copies) - 1, NEXT_WATCH)
