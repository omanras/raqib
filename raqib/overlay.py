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
          k: 5                         # a declared threshold, within its YAML's bounds

It is an overlay, never a copy of the catalog: the catalog stays the
package's and is read as before; the overlay is applied on top at load
(engine.load_catalog(..., overlay=PATH, user_rules=DIR)). What it may change
of a rule is its status (off: the engine's existing `status: disabled`) and
the `eq` value of a declared threshold; never its kind, class, severity,
budget or fixtures (apply() checks that the rule it compiles keeps them).

A declared threshold is an `eq` predicate of the rule's match whose value is
a whole number > 0, declared once (engine.declared_thresholds), named by its
field's last part: HOST-RHYTHM's k, w, r and suspect_every, AGENT-DARK-LIVE's
streak and live_window, HOST-UNWATCHED's none_rounds. M7.6c (ADR-0008
Amendment B): a person may change it only when the rule's YAML gives it
bounds (its `bounds:` block, engine.bounds_of: min, max, and relations such
as "k <= r", "live_window >= streak"); a declared threshold without bounds,
or any threshold of a rule whose YAML has no bounds block, is fixed: listed
as such by `raqib rules` and refused when set. There are no built-in bounds.
M7.6c REDO (ADR-0008 Amendment E): "measured" means sensitive (E-2): a
bounded threshold is editable only where raqib/rules/fixturegen.py makes an
edge pair for it (a positive that stops firing at the stricter neighbouring
value, a negative that fires at the looser one): HOST-RHYTHM's k, w, r and
AGENT-DARK-LIVE's streak, live_window; any other (a person's rule's) is
FIXED, "not measurable: no fixture is sensitive to <field>".
A changed threshold is measured before it is allowed, when it is set and at
a load whose overlay or catalog changed since the last measurement (E-7:
the result is kept in ~/.raqib/rules.measured.json, keyed by a hash of the
overlay, every rule file and the packaged inventories; say(MEASURING) while
it runs): the rule's fixtures are made AT the new values, in memory, by the
package itself (an installed raqib needs no tests/), and it is run on them:
every positive must fire, no negative and no synthetic desktop's arrival
(E-4: SYNTHETIC exports of two desktops whose trees arrive) may fire, the
false-positive rate over the measured negatives (E-5: never the synthetic
desktops, which cannot fire it) must stay within the declared budget, and
each changed field's edge pair must flip at its neighbours. A value that
fails, or that cannot be measured, is refused naming the fixture and the
condition (E-6); nothing is allowed on faith.

A malformed overlay (not yamlite, or not the shape above) is ONE hole and
nothing of it is applied (ADR-0008 decision 2: never half-applied). An entry
of a sound file that names an unknown rule or field, a field that is not a
declared eq threshold, a value outside its bounds, or "on" for a rule its
YAML disables (A6: a rule over budget is disabled, not tuned live) is
refused with the reason, said at the start of every watch, and not applied;
the other entries apply.

A person's rule lives in rules.d/<ID>/<ID>.yaml with its fixtures beside it
(M7.6 REDO A-1): it joins the catalog only when the engine's loader and the
fixture runner accept it (A6: fixtures positive and negative, never one file
both ways (A-4), a measured false-positive rate within its budget); every
file of it is read and written only through fixture_file() (relative, no
.., no drive, no root, no link, under rules.d/<ID>/ by realpath, under the
POSIX and the Windows path rules alike). Its id may not be a catalog rule's;
its class may not be HOST (A-6: host rules are fixed in v1). It is marked
origin user everywhere it is shown; one refused at load is counted in "N
rules off (refused: why)" (A-5). Every refusal is said, never dropped (A3).

Writes (A4): only overlay_path() (atomically: a temp file in ~/.raqib, then
os.replace) and files under user_dir()/<ID>/ (add_rule's copies, each
destination through fixture_file). Nothing here
reaches a watched process or a project.
"""
from __future__ import annotations

import copy
import datetime
import ntpath
import os
import posixpath
import tempfile

from raqib.rules import engine, fixturegen, fixtures, trace, yamlite

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "raqib", "rules", "catalog")
DIR_NAME = ".raqib"
OVERLAY_NAME = "rules.yaml"
USER_DIR_NAME = "rules.d"
FORMAT = 1
TOP_KEYS = ("raqib_overlay", "rules")
ENTRY_KEYS = ("status", "since", "thresholds")
WORDS = ("on", "off")
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


FIXED_NO_BLOCK = "fixed: its YAML has no bounds block"
FIXED_NO_BOUND = "fixed: its YAML gives it no bounds"


NOT_MEASURABLE = "not measurable: no fixture is sensitive to %s"


def _bounded(rule):
    bounds = getattr(rule, "bounds", None) or {"fields": {}}
    out = {}
    for name, t in engine.declared_thresholds(rule.doc).items():
        b = bounds["fields"].get(name)
        if b is not None and b["field"] == t["field"]:
            out[name] = {"field": t["field"], "value": t["value"], "low": b["min"], "high": b["max"]}
    return out


def _sensitive(rule):
    """M7.6c REDO E-2: the fields the generator has an edge pair for (a
    package rule fixturegen makes; a person's rule has none)."""
    if getattr(rule, "fixture_root", None) or getattr(rule, "origin", "package") == "user":
        return ()
    return fixturegen.edge_fields(rule.id)


def thresholds(rule):
    """{name: {"field", "value", "low", "high", "lo", "hi"}} of a rule's
    editable thresholds, in match order: declared, with bounds in its YAML
    (the fence) AND an edge pair the generator makes (E-2: measured means
    sensitive); lo..hi is the range the measurement accepts given the
    other values (E-6, fixturegen.effective)."""
    bounded = _bounded(rule)
    sensitive = _sensitive(rule)
    values = {n: t["value"] for n, t in engine.declared_thresholds(rule.doc).items()}
    out = {}
    for name, t in bounded.items():
        if name in sensitive:
            lo, hi = fixturegen.effective(rule.id, name, values, t["low"], t["high"])
            out[name] = dict(t, lo=lo, hi=hi)
    return out


def fixed_thresholds(rule):
    """{name: {"field", "value", "why"}}: the declared thresholds a person
    may not change, said by `raqib rules` and the panel (E2): no bounds
    block, no bounds for it, or (E-2) bounds but no fixture sensitive to it."""
    editable = thresholds(rule)
    bounded = _bounded(rule)
    out = {}
    for name, t in engine.declared_thresholds(rule.doc).items():
        if name in editable:
            continue
        if name in bounded:
            why = NOT_MEASURABLE % name
        else:
            why = FIXED_NO_BLOCK if getattr(rule, "bounds", None) is None else FIXED_NO_BOUND
        out[name] = dict(t, why=why)
    return out


def relations(rule):
    """[(small, big, text)]: the YAML's relations between its thresholds (small <= big)."""
    return list((getattr(rule, "bounds", None) or {}).get("relations") or [])


def resolve(rule, name):
    """The threshold name of `name` (a short name or the dotted field) in
    rule, or OverlayError with the reason."""
    table = thresholds(rule)
    for short, t in table.items():
        if name in (short, t["field"]):
            return short
    for short, t in fixed_thresholds(rule).items():
        if name in (short, t["field"]):
            raise OverlayError("%s %s is not editable (%s; ADR-0008 Amendments B, E: a threshold changes only"
                               " within the bounds its YAML declares, where a fixture is sensitive to it)"
                               % (rule.id, short, t["why"]))
    preds = _predicates((rule.doc or {}).get("match"), [])
    same = [p for p in preds if name in (p["field"], _short(p["field"]))]
    if not same:
        raise OverlayError("%s has no field %r (its declared thresholds: %s)" % (
            rule.id, name, ", ".join(sorted(table)) or "none"))
    if not any("eq" in p for p in same):
        raise OverlayError("%r is not an eq value of %s: only a declared eq threshold can change (ADR-0008)"
                           % (name, rule.id))
    raise OverlayError("%r is an eq of %s but not a declared threshold (not a whole number > 0 declared once: the"
                       " gate's fields and words are fixed; declared thresholds: %s)" % (
                           name, rule.id, ", ".join(sorted(table)) or "none"))


def check_value(rule, name, value, others=None):
    """OverlayError when value is not a whole number within the bounds of
    the threshold `name` of rule, or breaks a relation its YAML declares.
    others: the other thresholds' values in effect ({name: value})."""
    t = thresholds(rule)[name]
    if not (isinstance(value, int) and not isinstance(value, bool)):
        raise OverlayError("%s %s must be a whole number, not %r" % (rule.id, name, value))
    if not t["low"] <= value <= t["high"]:
        raise OverlayError("%s %s = %d is outside its bounds %d..%d (its YAML's bounds)" % (
            rule.id, name, value, t["low"], t["high"]))
    current = dict((k, v["value"]) for k, v in thresholds(rule).items())
    current.update(others or {})
    current[name] = value
    for small, big, text in relations(rule):
        if name not in (small, big) or small not in current or big not in current or current[small] <= current[big]:
            continue
        why = "its YAML's bounds say %s" % text
        if name == big:
            raise OverlayError("%s %s = %d is below its %s (%d): %s" % (rule.id, name, value, small, current[small],
                                                                       why))
        raise OverlayError("%s %s = %d is above its %s (%d): %s; raise %s first" % (
            rule.id, name, value, big, current[big], why, big))


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


def apply(rules, doc, path, state="read", hole=None, say=None, cache=None):
    """A Catalog of rules with the overlay doc applied (see the module
    docstring), and its .overlay (describe()'s source). M7.6c REDO E-7:
    cache (build()'s, from ~/.raqib/rules.measured.json) gives the results
    of a measurement made for the same overlay and catalog (its stamp), so
    a load with no change measures nothing; say(MEASURING) is called once
    before the first measurement that runs."""
    by_id = {r.id: r for r in rules}
    said = []
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
            new.fixture_root = getattr(rule, "fixture_root", None)
            label = ", ".join("%s=%d" % (n, v[1]) for n, v in sorted(changed.items()))
            new.changed_fields = sorted(changed)
            failed = []
            if changed:
                known = (cache or {}).get("old", {}).get("%s|%s" % (rule.id, label))
                if known is not None and cache.get("fresh"):   # E-7: measured for this very overlay and catalog
                    failed, new.measured = list(known.get("reasons") or []), known.get("summary")
                else:
                    if say is not None and not said:
                        said.append(MEASURING)
                        say(MEASURING)
                    failed = measure(new, label)
                if cache is not None:
                    cache["new"]["%s|%s" % (rule.id, label)] = {"reasons": list(failed),
                                                                "summary": getattr(new, "measured", None)}
            if failed:   # M7.6 REDO A-3: a changed threshold is measured; one that fails is refused, entry whole
                refused.append("%s: %s" % (rule.id, "; ".join(failed)))
                if not hasattr(rule, "origin"):
                    rule.origin = "package"
                rule.off_by = getattr(rule, "off_by", None)
                out.append(rule)
                continue
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
    out.overlay = {"path": path, "file": state, "hole": hole, "refused": refused, "applied": applied,
                   "measuring": "measured now" if said else ("from %s" % MEASURED_NAME if cache and cache.get("new")
                                                            else None)}
    if cache is not None:
        save_measured(cache)
    return out


def fixture_file(root, rel):
    """M7.6 REDO A-1 (ADR-0008 Amendment A, A4): the path of a person's
    rule's file rel under root, or OverlayError with the path quoted. rel
    must pass engine.fixture_path_problem (relative, no .., no drive, no
    root, under the POSIX and the Windows rules alike), use / between its
    directories (a \\ is read two ways), stay under its base when joined by
    ntpath AND posixpath, have no link (symlink, junction, any reparse
    point) at any step below root (the M7.2b I-1 check), and resolve by
    realpath under realpath(root). Every read and every write of a file of
    a person's rule goes through here."""
    why = engine.fixture_path_problem(rel)
    if why is None and "\\" in rel:
        why = "a \\ (write / between directories: a \\ is a separator on Windows only)"
    if why is None:
        for mod, base in ((ntpath, "C:\\base"), (posixpath, "/base")):
            joined = mod.normpath(mod.join(base, rel))
            if not joined.startswith(base + mod.sep):
                why = "outside its directory when joined by %s (%s)" % (mod.__name__, joined)
                break
    if why:
        raise OverlayError("path %r refused: %s (ADR-0008 A-1: a rule's files stay under rules.d/<rule>/)" % (rel, why))
    full = os.path.join(root, *rel.split("/"))
    path = root
    for part in rel.split("/"):
        path = os.path.join(path, part)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            break
        except OSError as exc:
            raise OverlayError("path %r refused: %s cannot be read (%s)" % (rel, path, exc.strerror or exc))
        attrs = getattr(st, "st_file_attributes", 0) or 0
        junction = getattr(os.path, "isjunction", None)
        if os.path.islink(path) or attrs & 0x400 or (junction is not None and junction(path)):
            raise OverlayError("path %r refused: %s is a link" % (rel, path))
    real = os.path.realpath(root)
    target = os.path.realpath(full)
    try:
        under = os.path.commonpath([os.path.normcase(real), os.path.normcase(target)]) == os.path.normcase(real)
    except ValueError:   # another drive
        under = False
    if not under or target == real:
        raise OverlayError("path %r refused: it resolves to %s, outside %s" % (rel, target, real))
    return full


def load_user_rules(directory, taken):
    """(rules, refused, refused_ids): the rules of directory/<ID>/<ID>.yaml
    the loader and the fixture runner accept (their files read through
    fixture_file, under directory/<ID>/), each marked origin user; refused:
    one reason per entry (A3: said, never dropped); refused_ids: [{rule_id,
    reason}] for "N rules off" (A-5)."""
    rules, refused, ids = [], [], []

    def no(name, reason):
        refused.append(reason)
        ids.append({"rule_id": name, "reason": reason})
    if not directory or not os.path.isdir(directory):
        return rules, refused, ids
    seen = set(taken)
    for name in sorted(os.listdir(directory)):
        here = os.path.join(directory, name)
        if not os.path.isdir(here):
            if name.lower().endswith((".yml", ".yaml")):
                no(os.path.splitext(name)[0], "%s: a rule lives in rules.d/<ID>/<ID>.yaml with its fixtures beside it"
                   " (ADR-0008 A-1); this file is not read" % here)
            continue
        try:
            fixture_file(directory, name)   # the rule's own directory: no link, under rules.d
            yaml_path = fixture_file(here, name + ".yaml")
            if not os.path.isfile(yaml_path):
                raise OverlayError("%s: no %s.yaml in it" % (here, name))
            rule = validate_rule(yaml_path, here, seen, user=True)
        except OverlayError as exc:
            no(name, str(exc))
            continue
        rule.origin = "user"
        rule.fixture_root = here
        seen.add(rule.id)
        rules.append(rule)
    return rules, refused, ids


HOST_FIXED = "host rules are fixed in v1 (the host watch does not load a person's rules yet)"


def validate_rule(path, root, taken=(), user=False):
    """The rule of a YAML file when the engine's loader and the fixture
    runner accept it (fixtures relative to root, each through fixture_file
    for a person's rule), else OverlayError with the loader's or the
    runner's reason. user: a person's rule (A-6: never of class HOST)."""
    try:
        rule = engine.load_rule(path)
    except engine.RuleError as exc:
        raise OverlayError("%s refused by the loader: %s" % (path, exc))
    if rule.id in taken:
        raise OverlayError("%s: rule id %s is already in the catalog or rules.d" % (path, rule.id))
    if user and rule.cls == "HOST":   # M7.6 REDO A-6
        raise OverlayError("%s: class HOST: %s" % (path, HOST_FIXED))
    if user:
        for kind in ("positive", "negative"):
            for p in rule.fixtures[kind]:
                fixture_file(root, p)
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


def _judged(rule, lines):
    """(fired, measured) of a rule on one round's generated lines, as
    fixtures.outcome judges a file (C-1a: no line through the rule's gate,
    or a line it cannot judge, is unmeasured)."""
    for i, rec in enumerate(lines):
        problem = trace.strict_problem(rec)
        if problem:
            raise fixtures.FixtureError("line %d is not a sound trace record (%s)" % (i + 1, problem))
    found, unknown = engine.judge(rule, lines, {})
    if found:
        return True, True
    return False, not unknown and fixtures.passes_gate(fixtures.gate_of(rule), lines)


def _run_judged(rule, rounds):
    """(fired, measured) over a generated run: fired in any round (a host
    rule fires once per streak, so a firing before the last round is seen
    only there); measured when it fired or a round is measured (a line
    through the gate, every line judged)."""
    got = [_judged(rule, lines) for lines in rounds]
    return any(f for f, _ in got), any(f or m for f, m in got)


def _name(path):
    return os.path.splitext(os.path.basename(path))[0]


def _builder():
    """The round builder fixturegen is handed (E-8: raqib/rules/ never imports raqib.host; this module does)."""
    from raqib import host
    return host.fixture_builder()


def _cond(path):
    why = fixturegen.CONDITIONS.get(path[len(fixturegen.FIXTURE_DIR):]) if path.startswith(
        fixturegen.FIXTURE_DIR) else None
    return ": %s" % why if why else ""


def _edges(rule, values, fields, label, builder):
    """E-2: ([reasons], [said]): for each changed field, its edge pair run
    at the neighbouring values (the fixtures made at the new value): the
    positive must stop firing at the stricter one, the negative must fire
    at the looser one. A neighbour outside the bounds or breaking a
    relation is not run; a field neither neighbour can be run for is not
    measurable at that value."""
    reasons, said = [], []
    for f in fields:
        pos, neg = (fixturegen.FIXTURE_DIR + p for p in fixturegen.EDGES[rule.id][f])
        ran = 0
        for step, path, want in ((fixturegen.STRICTER[f], pos, False), (-fixturegen.STRICTER[f], neg, True)):
            other_values = dict(values)
            other_values[f] = values[f] + step
            try:
                other = fixturegen.with_values(rule, other_values)
            except engine.RuleError:
                continue
            made = fixturegen.generate(other, builder, shape=values, only={path})
            got = _run_judged(other, made["runs"][path])[0]
            ran += 1
            if got != want:
                reasons.append("%s: not sensitive at %s=%d: %s %s" % (
                    label, f, other_values[f], _name(path), "still fires" if got else "does not fire"))
            else:
                said.append("%s %s at %s=%d" % (_name(path), "fires" if want else "stops firing", f,
                                                other_values[f]))
        if not ran:
            reasons.append("%s: not measurable at %s=%d: neither neighbouring value can be run" % (label, f,
                                                                                                values[f]))
    return reasons, said


def measure_generated(rule, label, fields=None):
    """M7.6c (ADR-0008 Amendments B, E; A6): ([reasons], summary) of a rule
    fixturegen makes fixtures for, on its fixtures generated at its own
    (changed) values: every positive fires in its run; no negative fires in
    any round of its run (fixturegen.LAST_ROUND_ONLY: in its last round);
    the false-positive rate over the measured negatives stays within the
    budget (E-5: the synthetic desktops are run and refused if they fire,
    never counted: they cannot fire the rule); and (E-2) each changed field
    is sensitive at its new value (its edge pair flips at the neighbours).
    A refusal names the fixture and the condition (E-6)."""
    builder = _builder()
    try:
        made = fixturegen.generate(rule, builder)
        runs = made["runs"]
        last = set(made["last_round_only"])
        arrivals = set(made["arrivals"])
        positives = [(p, _run_judged(rule, runs[p])[0]) for p, _ in made["positive"]]
        negatives = [(p,) + (_judged(rule, runs[p][-1]) if p in last else _run_judged(rule, runs[p]))
                     for p, _ in made["negative"]]
        values = made["values"]
        fields = [f for f in (fields if fields is not None else fixturegen.edge_fields(rule.id))
                  if f in fixturegen.EDGES.get(rule.id, {})]
        edge_reasons, edge_said = _edges(rule, values, fields, label, builder)
    except (fixturegen.GenerateError, fixtures.FixtureError, engine.RuleError, OSError, ValueError) as exc:
        return ["%s: cannot be measured: %s" % (label, exc)], None
    reasons = ["%s: %s no longer fires%s" % (label, _name(p), _cond(p)) for p, fired in positives if not fired]
    reasons += ["%s: %s fires%s" % (label, _name(p), ": would fire on a synthetic desktop" if p in arrivals
                                    else _cond(p)) for p, fired, _ in negatives if fired]
    measured = [n for n in negatives if n[2] and n[0] not in arrivals]   # E-5
    desktops = [n for n in negatives if n[0] in arrivals]
    rate = sum(1 for n in measured if n[1]) / len(measured) if measured else None
    if rate is None:
        reasons.append("%s: cannot be measured: no generated negative passes the rule's gate" % label)
    elif rate > rule.fp_budget:
        reasons.append("%s: the false-positive rate measured on %d negatives, %g, is above its budget %g" % (
            label, len(measured), rate, rule.fp_budget))
    reasons += edge_reasons
    summary = ("measured at %s on fixtures generated at it (sensitive: %s): %d of %d positives fire; %d of %d"
               " measured negatives fire; the %d synthetic desktops do not fire (run, not counted: they cannot"
               " fire it); fp rate %s, budget %g" % (
                   label, "; ".join(edge_said) or "-", sum(1 for _, f in positives if f), len(positives),
                   sum(1 for n in measured if n[1]), len(measured), len(desktops),
                   "-" if rate is None else "%g" % rate, rule.fp_budget))
    return reasons, summary


_MEASURED = {}       # (rule id, label, its doc) -> measure_generated's result: memory only, never a file
MEASURED_KEPT = 16


def measure(rule, label):
    """M7.6 REDO A-3, M7.6c (A6): [reasons] the overlaid rule fails its
    measurement for: a positive that no longer fires, a negative (or a
    benign arrival) that fires, a budget broken, or a fixture that is not
    there to measure with. label names the change ("k=5"). Empty: measured,
    it holds; the summary is kept on the rule (rule.measured). A rule
    fixturegen generates is measured on fixtures made at its values (the
    package's, so an installed raqib measures the same); any other on its
    own fixture files (a person's rule: under rules.d)."""
    if rule.id in fixturegen.GENERATED and not getattr(rule, "fixture_root", None):
        import json
        key = (rule.id, label, json.dumps(rule.doc, sort_keys=True, default=str))
        if key not in _MEASURED:   # in this process only: a set_threshold and the load after it measure once
            while len(_MEASURED) >= MEASURED_KEPT:
                _MEASURED.pop(next(iter(_MEASURED)))
            _MEASURED[key] = measure_generated(rule, label, getattr(rule, "changed_fields", None))
        reasons, rule.measured = _MEASURED[key]
        return list(reasons)
    root = getattr(rule, "fixture_root", None) or ROOT
    reasons = []
    for kind in ("positive", "negative"):
        for p in rule.fixtures[kind]:
            full = fixture_file(root, p) if getattr(rule, "fixture_root", None) else os.path.join(root, p)
            if not os.path.isfile(full):
                reasons.append("%s: cannot be measured: fixture %s is not here (no generator makes it)"
                               % (label, p))
    if reasons:
        return reasons
    try:
        result = fixtures.check_rule(rule, root)
    except (fixtures.FixtureError, OSError, ValueError) as exc:
        return ["%s: cannot be measured: %s" % (label, exc)]
    reasons += ["%s: %s no longer fires" % (label, _name(x["path"])) for x in result["positives"] if not x["fired"]]
    reasons += ["%s: %s fires" % (label, _name(x["path"])) for x in result["negatives"] if x["fired"]]
    if not reasons and result["verdict"] not in ("ok", "disabled"):
        reasons.append("%s: the fixture runner says %s" % (label, result["verdict"]))
    if not reasons:
        rule.measured = "measured at %s on its fixture files: %d positives fire; fp rate %s, budget %g" % (
            label, len(result["positives"]), result["fp_rate"], rule.fp_budget)
    return reasons


MEASURING = "measuring the overlay's thresholds..."
MEASURED_NAME = "rules.measured.json"


def measured_path(home=None):
    return os.path.join(raqib_dir(home), MEASURED_NAME)


def stamp(rules, overlay):
    """E-7: the hash of what a measurement depends on: raqib's version, every
    rule file (the catalog's and rules.d's), the overlay file and the
    packaged inventories. Another stamp: measure again."""
    import hashlib
    import raqib
    h = hashlib.sha256(("raqib %s\n" % getattr(raqib, "__version__", "?")).encode("ascii"))
    paths = sorted({getattr(r, "base_source", None) or r.source for r in rules}) + [overlay or "", fixturegen.HOSTDATA]
    for p in paths:
        h.update(("\n%s\n" % os.path.basename(p)).encode("utf-8", "replace"))
        try:
            with open(p, "rb") as f:
                h.update(f.read())
        except OSError:
            h.update(b"(absent)")
    return h.hexdigest()


def load_measured(path, current):
    """{"path", "stamp", "old", "new", "fresh"}: the cache of the last
    measurement (E-7); fresh when it was made for this very stamp."""
    old, fresh = {}, False
    try:
        with open(path, encoding="ascii") as f:
            data = __import__("json").load(f)
        if isinstance(data, dict) and isinstance(data.get("results"), dict):
            old, fresh = data["results"], data.get("stamp") == current
    except (OSError, ValueError):
        pass
    return {"path": path, "stamp": current, "old": old, "new": {}, "fresh": fresh}


def save_measured(cache):
    """Write the cache (atomically) when this load measured or the stamp
    changed; a cache that cannot be written only means measuring again."""
    if (cache.get("fresh") and cache["new"] == cache["old"]) or not (cache["new"] or cache["old"]):
        return   # nothing new to keep (and nothing measured where nothing was kept: no file at all)
    import json
    text = json.dumps({"about": "M7.6c REDO E-7: the last measurement of ~/.raqib/rules.yaml's thresholds (raqib"
                                " writes it; delete it to measure again)", "stamp": cache["stamp"],
                       "results": cache["new"]}, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    try:
        _atomic_write(cache["path"], text.encode("ascii"))
    except OSError:
        pass


def build(rules, overlay=None, user_rules=None, say=None):
    """engine.load_catalog's overlay step: the catalog rules, the rules of
    user_rules (rules.d), then the overlay file at `overlay` on top.
    M7.6c REDO E-7: a measurement's result is kept beside the overlay in
    rules.measured.json and reused while nothing it depends on changed;
    say(line) is told when a measurement runs."""
    rules = list(rules)
    for r in rules:
        r.origin = getattr(r, "origin", "package")
    users, user_refused, refused_ids = load_user_rules(user_rules, {r.id for r in rules})
    combined = rules + sorted(users, key=lambda r: r.id)   # the catalog's order kept; the person's after it
    if overlay is None:
        doc, state, hole = empty(), "absent", None
    else:
        doc, state, hole = read(overlay)
    cache = None
    if overlay is not None and state == "read":
        cache = load_measured(os.path.join(os.path.dirname(overlay), MEASURED_NAME), stamp(combined, overlay))
    out = apply(combined, doc, overlay, state, hole, say=say, cache=cache)
    out.overlay.update(user_dir=user_rules, user=[{"rule_id": r.id, "source": r.source} for r in users],
                       user_refused=user_refused, user_refused_ids=refused_ids)
    return out


def load(home=None, catalog=None, say=None):
    """The catalog as a watch loads it: the package's, rules.d and the
    overlay (engine.load_catalog's steps; say: told when a measurement runs, E-7)."""
    return build(engine.load_catalog(catalog or CATALOG), overlay=overlay_path(home), user_rules=user_dir(home),
                 say=say)


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
    info.setdefault("user_refused_ids", [])
    info.setdefault("user_dir", None)
    off = []
    for r in rules:
        if getattr(r, "off_by", None):
            off.append({"rule_id": r.id, "by": "the overlay %s" % r.off_by, "since": getattr(r, "off_since", None),
                        "severity": r.severity, "kind": r.kind})
        elif r.status == "disabled":
            off.append({"rule_id": r.id, "by": "its YAML (status: disabled, A6)", "since": None,
                        "severity": r.severity, "kind": r.kind})
    for u in info["user_refused_ids"]:   # M7.6 REDO A-5: a person's rule refused at load judges nothing: it is off
        off.append({"rule_id": u["rule_id"], "by": "refused at load", "since": None, "severity": None, "kind": None,
                    "refused": u["reason"]})
    info["off"] = off
    info["thresholds"] = [{"rule_id": r.id, "name": name, "value": now, "yaml": was}
                          for r in rules for name, (was, now) in sorted((getattr(r, "changed", None) or {}).items())]
    package = [r for r in rules if getattr(r, "origin", "package") == "package"]   # "every catalog rule of kind X"
    kinds = sorted({r.kind for r in package})
    info["kinds_off"] = [k for k in kinds if all(r.status == "disabled" for r in package if r.kind == k)]
    return info


REASON_MAX = 160   # the characters of a refusal shown in "N rules off" (the report keeps it whole)


def off_word(o):
    """One rule of "N rules off": its id, and "(refused: why)" for a person's rule refused at load (A-5)."""
    if o.get("refused"):
        why = str(o["refused"])
        return "%s (refused: %s)" % (o["rule_id"], why if len(why) <= REASON_MAX else why[:REASON_MAX - 3] + "...")
    return str(o["rule_id"])


def off_text(info):
    """"N rules off: <ids>", or None when no rule is off."""
    off = (info or {}).get("off") or []
    if not off:
        return None
    return "%d rule%s off: %s" % (len(off), "" if len(off) == 1 else "s", ", ".join(off_word(o) for o in off))


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


SUPPRESSED = "%d findings suppressed by the overlay"


def suppressed(counts):
    """M7.6 REDO A-2: how many findings the rules off would have made."""
    return sum(c.get("fired") or 0 for c in (counts or {}).values())


def clean_word(word, counts):
    """M7.6 REDO A-2 (ADR-0008 Amendment A): a CLEAN result word where an
    off rule would have fired: "CLEAN (N findings suppressed by the
    overlay)"; the exit code stays the person's choice, the words do not."""
    n = suppressed(counts)
    return "%s (%s)" % (word, SUPPRESSED % n) if n else word


def report_lines(info, counts):
    """The final report's RULES section: each rule off, by whom and since
    when, and what it did not judge; the thresholds changed; the refusals."""
    off = info.get("off") or []
    out = ["RULES OFF (ADR-0008; they do not change the exit code, and the watch is not clean of what they would"
           " have found): %d" % len(off)]
    for o in off:
        if o.get("refused"):   # A-5
            out.append("  - %s (a person's rule) off: refused at load: %s" % (o["rule_id"], o["refused"]))
            continue
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
                                     "lo": t["lo"], "hi": t["hi"],
                                     "yaml": changed.get(n, (t["value"],))[0]} for n, t in thresholds(r).items()],
                     # M7.6c E2: the declared thresholds a person may not change, and why
                     "fixed": [{"name": n, "value": t["value"], "why": t["why"]} for n, t in fixed_thresholds(r).items()]})
    return rows


def threshold_text(t):
    if "why" in t:   # M7.6c E2: fixed (no bounds in its YAML; REDO E-2: or no fixture sensitive to it)
        return "%s=%d (%s)" % (t["name"], t["value"], t["why"])
    text = "%s=%d%s [%d..%d" % (t["name"], t["value"], "*" if t["value"] != t["yaml"] else "", t["low"], t["high"])
    if "lo" in t and (t["lo"], t["hi"]) != (t["low"], t["high"]):   # E-6: the range the measurement accepts
        text += "; measured %d..%d" % (t["lo"], t["hi"])
    return text + "]"


def table_text(rows):
    """The listing as text (raqib rules, the panel): one line per rule."""
    head = ("ID", "KIND", "CLASS", "SEVERITY", "BUDGET", "STATUS", "ORIGIN", "THRESHOLDS")
    body = [(r["id"], r["kind"], r["class"], r["severity"], "%g" % r["budget"],
             r["status"] + (" (yaml)" if r["off_by"] == "yaml" else ""), r["origin"],
             ", ".join(threshold_text(t) for t in r["thresholds"] + r.get("fixed", [])) or "-") for r in rows]
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


def set_threshold(rid, name, value, home=None, now=None, catalog=None, say=None):
    """Set a declared threshold of a rule in the overlay; the line said.
    M7.6c REDO E-7: measured here (say(MEASURING) first), and the result is
    kept for the loads after it (rules.measured.json), which then measure
    nothing."""
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
    measured = None
    if not reasons:   # M7.6 REDO A-3, M7.6c: measured (at the new values) before it is written
        trial = apply([rule], {"rules": {rid: entry}}, overlay_path(home), say=say)
        reasons = [r.split(": ", 1)[1] for r in trial.overlay["refused"]]
        measured = getattr(trial[0], "measured", None) if trial else None
    if reasons:
        raise OverlayError("%s: %s" % (rid, "; ".join(reasons)))
    doc["rules"][rid] = entry
    path = write(doc, home)
    try:   # E-7: the load after a set reuses this measurement (this process's memory), and keeps it on disk
        load(home, catalog)
    except (engine.RuleError, OverlayError):
        pass
    return "%s %s = %d in %s; %s%s" % (rid, short, value, path, "%s; " % measured if measured else "", NEXT_WATCH)


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
    runner, fixtures relative to the file's directory, each through
    fixture_file) and copy it, with its fixture files, under
    user_dir(home)/<ID>/ - every destination through fixture_file
    (realpath under that directory, M7.6 REDO A-1); the line said. Nothing
    is copied when anything is refused; the fixtures are written first and
    the YAML last, so a copy cut short is a rule with no YAML (refused at
    load, said)."""
    path = os.path.abspath(path)
    if not path.endswith(".yaml"):
        raise OverlayError("%s: a rule file must end in .yaml" % path)
    src_root = os.path.dirname(path)
    taken = {r.id for r in _base(home, catalog)}
    rule = validate_rule(path, src_root, taken, user=True)
    rules_d = user_dir(home)
    target_dir = fixture_file(rules_d, rule.id)
    copies = []
    for kind in ("positive", "negative"):
        for p in rule.fixtures[kind]:
            copies.append((fixture_file(src_root, p), fixture_file(target_dir, p)))
    copies.append((path, fixture_file(target_dir, rule.id + ".yaml")))   # last
    plan = []
    for src, dst in copies:
        try:
            with open(src, "rb") as f:
                data = f.read()
            if os.path.exists(dst):
                with open(dst, "rb") as f:
                    if f.read() != data:
                        raise OverlayError("%s exists in rules.d with other content: nothing copied" % dst)
        except OSError as exc:
            raise OverlayError("%s cannot be read: %s" % (exc.filename or src, exc.strerror or exc))
        plan.append((dst, data))
    try:
        for dst, data in plan:
            _atomic_write(dst, data)
    except OSError as exc:
        raise OverlayError("cannot write under %s: %s" % (target_dir, exc.strerror or exc))
    return "%s added as %s (origin: user; %d fixture file(s) copied; %s)" % (
        rule.id, copies[-1][1], len(copies) - 1, NEXT_WATCH)
