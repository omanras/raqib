"""policies.yml loader (ADR-0001 section 5).

``load(path)`` returns ``Loaded(config, problems)`` and never raises.
``config`` is None only when the file could not be read or is not a YAML
mapping; otherwise it holds whatever parsed, and ``problems`` (same dict
shape as ledger problems, plus ``field``) name every field that is wrong.

Each policy is validated by its type. A policy whose type, measure, limit,
match or band is not one of the declared shapes is kept with status
``unknown`` and a reason (A2, A5: an undeclared policy is never guessed).
A measure that names an undeclared category, account or class is both a
file problem (class ``invalid``) and an ``unknown`` policy.

Declared shapes (v0.1):
  measure  {sum: <group>.<category> | <group>, period: month|quarter|year}
           {holdings: class.<c> | account.<a>}
           {share: class.<c>}
           {drawdown: account.<a>, window_days: N}
           ``sum: income`` and ``sum: expense`` are the ADR's ``income`` and
           ``expense`` measures (the whole group).
  limit    {value: N} | {pct_of: income, value: P} |
           {months_of: expense, value: M} | {pct: P}
  match    any of tags, tags_any, account, category, min_amount
  band     {min_pct: A, max_pct: B}

YAML numbers: floats are read as Decimal from their text (never float, A5);
duplicate keys are a parse problem; every mapping remembers its line.
"""

import datetime
import os
import re
from decimal import Decimal, InvalidOperation
from typing import NamedTuple, Optional

import yaml

from .ledger import MAX_FILE_BYTES, _problem, INVALID
from .periods import KINDS

DEFAULT_CLASSES = ("cash", "equity", "fund", "property", "gold", "debt", "other")
TYPES = ("cap", "floor", "routine", "red_line", "kill", "allocation")
REQUIRED_GROUPS = ("income", "expense")

_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_NUMBER_RE = re.compile(r"^-?[0-9]+(\.[0-9]+)?$")


# ------------------------------------------------------------------ YAML reading


class Map(dict):
    """A YAML mapping that remembers the line it starts on."""
    line = 0


class _Loader(yaml.SafeLoader):
    pass


def _construct_map(loader, node):
    data = Map()
    data.line = node.start_mark.line + 1
    yield data
    seen = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=True)
        try:
            hash(key)
        except TypeError:
            raise yaml.constructor.ConstructorError(
                None, None, "unhashable mapping key", key_node.start_mark)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, "duplicate key %r" % (key,), key_node.start_mark)
        seen.add(key)
    data.update(loader.construct_mapping(node, deep=True))


def _construct_float(loader, node):
    text = node.value.replace("_", "")
    try:
        return Decimal(text)
    except InvalidOperation:
        return node.value  # .inf / .nan: left as text so validation rejects it


def _construct_text(loader, node):
    return node.value


_Loader.add_constructor("tag:yaml.org,2002:map", _construct_map)
_Loader.add_constructor("tag:yaml.org,2002:float", _construct_float)
# Dates stay text: PyYAML would raise on 2026-13-01 and turn 2026-10-01
# 10:00:00 into a datetime; as_date() judges the text strictly instead.
_Loader.add_constructor("tag:yaml.org,2002:timestamp", _construct_text)


def read_yaml(path):
    """Read one YAML document. Returns (data, problems, file); never raises.
    data is None when the file could not be read or parsed."""
    file = os.path.basename(os.fspath(path)) if path is not None else "?"
    try:
        size = os.stat(path).st_size
    except FileNotFoundError:
        return None, [_problem(file, 0, "FILE-MISSING", "file not found: %s" % path)], file
    except (OSError, TypeError, ValueError) as exc:
        return None, [_problem(file, 0, "FILE-UNREADABLE", "cannot stat %s: %s" % (path, exc))], file
    if size >= MAX_FILE_BYTES:
        return None, [_problem(file, 0, "FILE-TOO-LARGE",
                               "file is %d bytes; the limit is %d" % (size, MAX_FILE_BYTES))], file
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES)
    except (OSError, TypeError, ValueError) as exc:
        return None, [_problem(file, 0, "FILE-UNREADABLE", "cannot read %s: %s" % (path, exc))], file
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        line = data.count(b"\n", 0, exc.start) + 1
        return None, [_problem(file, line, "BAD-ENCODING",
                               "file is not UTF-8 (byte %d: %s)" % (exc.start, exc.reason))], file
    try:
        doc = yaml.load(text, Loader=_Loader)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark or exc.context_mark
        line = (mark.line + 1) if mark is not None else 0
        reason = exc.problem or exc.context or str(exc)
        return None, [_problem(file, line, "BAD-YAML", "YAML error: %s" % reason)], file
    except yaml.YAMLError as exc:
        return None, [_problem(file, 0, "BAD-YAML", "YAML error: %s" % exc)], file
    except Exception as exc:  # the contract is "never raises"
        return None, [_problem(file, 0, "BAD-YAML", "YAML error: %s: %s" % (type(exc).__name__, exc))], file
    if doc is None:
        return None, [_problem(file, 0, "FILE-EMPTY", "file holds no YAML document")], file
    return doc, [], file


# ------------------------------------------------------------------- structures


class Policy(NamedTuple):
    id: str
    type: str
    title: str
    measure: Optional[dict]
    limit: Optional[dict]
    match: Optional[dict]
    period: Optional[str]
    band: Optional[dict]
    status: str            # "ok" | "unknown"
    reason: Optional[str]
    line: int
    file: str
    raw: dict

    @property
    def cite(self):
        return "%s:%d" % (self.file, self.line)


class Config(NamedTuple):
    version: Optional[int]
    base_currency: Optional[str]
    accounts: tuple
    categories: dict        # group -> tuple of category names
    classes: tuple
    snapshot_max_age_days: Optional[int]
    policies: tuple
    file: str

    @property
    def all_categories(self):
        return tuple(c for group in self.categories.values() for c in group)

    def group_of(self, category):
        for group, names in self.categories.items():
            if category in names:
                return group
        return None

    @property
    def policy_ids(self):
        return tuple(p.id for p in self.policies)

    def policy(self, pid):
        for p in self.policies:
            if p.id == pid:
                return p
        return None


class Loaded(NamedTuple):
    config: Optional[Config]
    problems: list


# ------------------------------------------------------------------- validation


def is_number(value):
    """A YAML int, a Decimal (from a YAML float), or decimal text. Not bool."""
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, Decimal)):
        return value.is_finite() if isinstance(value, Decimal) else True
    if isinstance(value, str):
        return bool(_NUMBER_RE.match(value))
    return False


def to_decimal(value):
    """Decimal from a value that passed is_number."""
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    return Decimal(value)


def _is_name(value):
    return isinstance(value, str) and bool(_NAME_RE.match(value))


def _line(obj, default):
    return obj.line if isinstance(obj, Map) else default


class _Check(object):
    """Collects file problems for one policies.yml."""

    def __init__(self, file):
        self.file = file
        self.problems = []

    def add(self, line, code, field, reason):
        self.problems.append(_problem(self.file, line, code, reason, INVALID, field=field))


def _validate_measure(measure, cfg, chk, line, field):
    """Returns (normalized, reason). reason is set when the measure is unknown."""
    if not isinstance(measure, dict):
        return None, "measure must be a mapping"
    keys = set(measure)
    kinds = keys & {"sum", "holdings", "share", "drawdown"}
    if len(kinds) != 1:
        return None, "measure must have exactly one of sum, holdings, share, drawdown (got %s)" % (
            ", ".join(sorted(keys)) or "nothing")
    kind = kinds.pop()
    target = measure[kind]
    if not isinstance(target, str) or not target:
        return None, "measure.%s must be text" % kind
    if kind == "sum":
        extra = keys - {"sum", "period"}
        if extra:
            return None, "measure has unexpected keys: %s" % ", ".join(sorted(extra))
        if "period" not in measure:
            return None, "measure.period is missing (month, quarter or year)"
        period = measure["period"]
        if period not in KINDS:
            return None, "measure.period %r is not month, quarter or year" % (period,)
        group, _, category = target.partition(".")
        if group not in cfg["categories"]:
            chk.add(line, "UNDECLARED-CATEGORY", field + ".sum", "group %r is not declared" % group)
            return None, "measure.sum names undeclared group %r" % group
        if category:
            if "." in category or category not in cfg["categories"][group]:
                chk.add(line, "UNDECLARED-CATEGORY", field + ".sum",
                        "category %r is not declared under %r" % (category, group))
                return None, "measure.sum names undeclared category %r" % target
        return {"kind": "sum", "group": group, "category": category or None, "period": period}, None
    extra = keys - {kind, "window_days"} if kind == "drawdown" else keys - {kind}
    if extra:
        return None, "measure has unexpected keys: %s" % ", ".join(sorted(extra))
    by, _, name = target.partition(".")
    if kind == "holdings" and by not in ("class", "account"):
        return None, "measure.holdings must be class.<c> or account.<a>"
    if kind == "share" and by != "class":
        return None, "measure.share must be class.<c>"
    if kind == "drawdown" and by != "account":
        return None, "measure.drawdown must be account.<a>"
    if not name or "." in name:
        return None, "measure.%s %r is malformed" % (kind, target)
    if by == "class" and name not in cfg["classes"]:
        chk.add(line, "UNDECLARED-CLASS", field + "." + kind, "class %r is not declared" % name)
        return None, "measure.%s names undeclared class %r" % (kind, name)
    if by == "account" and name not in cfg["accounts"]:
        chk.add(line, "UNDECLARED-ACCOUNT", field + "." + kind, "account %r is not declared" % name)
        return None, "measure.%s names undeclared account %r" % (kind, name)
    out = {"kind": kind, "by": by, "name": name}
    if kind == "drawdown":
        window = measure.get("window_days")
        if isinstance(window, bool) or not isinstance(window, int) or window < 1:
            return None, "measure.window_days must be a positive integer"
        out["window_days"] = window
    return out, None


def _validate_limit(limit, allowed):
    if not isinstance(limit, dict):
        return None, "limit must be a mapping"
    keys = set(limit)
    if keys == {"value"} and "value" in allowed:
        if not is_number(limit["value"]):
            return None, "limit.value must be a number"
        return {"kind": "value", "value": to_decimal(limit["value"])}, None
    if keys == {"pct_of", "value"} and "pct_of" in allowed:
        if limit["pct_of"] != "income":
            return None, "limit.pct_of must be income"
        if not is_number(limit["value"]):
            return None, "limit.value must be a number"
        return {"kind": "pct_of", "of": "income", "value": to_decimal(limit["value"])}, None
    if keys == {"months_of", "value"} and "months_of" in allowed:
        if limit["months_of"] != "expense":
            return None, "limit.months_of must be expense"
        if not is_number(limit["value"]):
            return None, "limit.value must be a number"
        return {"kind": "months_of", "of": "expense", "value": to_decimal(limit["value"])}, None
    if keys == {"pct"} and "pct" in allowed:
        if not is_number(limit["pct"]):
            return None, "limit.pct must be a number"
        return {"kind": "pct", "value": to_decimal(limit["pct"])}, None
    return None, "limit must be one of %s (got keys: %s)" % (
        ", ".join("{%s}" % a for a in allowed), ", ".join(sorted(keys)) or "nothing")


def _validate_match(match, cfg, chk, line, field):
    if not isinstance(match, dict):
        return None, "match must be a mapping"
    keys = set(match)
    extra = keys - {"tags", "tags_any", "account", "category", "min_amount"}
    if extra:
        return None, "match has unexpected keys: %s" % ", ".join(sorted(extra))
    if not keys:
        return None, "match needs at least one of tags, tags_any, account, category, min_amount"
    out = {}
    if "tags" in match:
        tags = match["tags"]
        if isinstance(tags, str):
            tags = [tags]
        if not isinstance(tags, list) or not tags or not all(_is_name(t) for t in tags):
            return None, "match.tags must be a tag or a list of tags"
        out["tags"] = tuple(tags)
    if "tags_any" in match:
        tags = match["tags_any"]
        if not isinstance(tags, list) or not tags or not all(_is_name(t) for t in tags):
            return None, "match.tags_any must be a non-empty list of tags"
        out["tags_any"] = tuple(tags)
    if "account" in match:
        account = match["account"]
        if not isinstance(account, str):
            return None, "match.account must be text"
        if account not in cfg["accounts"]:
            chk.add(line, "UNDECLARED-ACCOUNT", field + ".account", "account %r is not declared" % account)
            return None, "match.account names undeclared account %r" % account
        out["account"] = account
    if "category" in match:
        category = match["category"]
        if not isinstance(category, str):
            return None, "match.category must be text"
        if category not in cfg["all_categories"]:
            chk.add(line, "UNDECLARED-CATEGORY", field + ".category", "category %r is not declared" % category)
            return None, "match.category names undeclared category %r" % category
        out["category"] = category
    if "min_amount" in match:
        if not is_number(match["min_amount"]):
            return None, "match.min_amount must be a number"
        out["min_amount"] = to_decimal(match["min_amount"])
    return out, None


def _validate_band(band):
    if not isinstance(band, dict):
        return None, "band must be a mapping"
    if set(band) != {"min_pct", "max_pct"}:
        return None, "band must have exactly min_pct and max_pct"
    if not is_number(band["min_pct"]) or not is_number(band["max_pct"]):
        return None, "band.min_pct and band.max_pct must be numbers"
    lo, hi = to_decimal(band["min_pct"]), to_decimal(band["max_pct"])
    if not (0 <= lo <= hi <= 100):
        return None, "band must satisfy 0 <= min_pct <= max_pct <= 100"
    return {"min_pct": lo, "max_pct": hi}, None


_NEEDS = {
    "cap": ("measure", "limit"),
    "floor": ("measure", "limit"),
    "routine": ("match", "period"),
    "red_line": ("match",),
    "kill": ("measure", "limit"),
    "allocation": ("measure", "band"),
}
_LIMITS = {
    "cap": ("value", "pct_of", "months_of"),
    "floor": ("value", "pct_of", "months_of"),
    "kill": ("pct",),
}


def _validate_policy(raw, index, cfg, chk, default_line):
    line = _line(raw, default_line)
    field = "policies[%d]" % index
    if not isinstance(raw, dict):
        chk.add(line, "BAD-FIELD", field, "policy must be a mapping")
        return None
    pid = raw.get("id")
    if not _is_name(pid):
        chk.add(line, "BAD-FIELD", field + ".id", "policy id is missing or not a plain name")
        return None
    ptype = raw.get("type")
    title = raw.get("title", pid)
    if not isinstance(title, str) or not title:
        chk.add(line, "BAD-FIELD", field + ".title", "title must be non-empty text")
        title = pid

    def unknown(reason):
        return Policy(pid, str(ptype), title, None, None, None, None, None, "unknown", reason, line, chk.file, raw)

    if ptype not in TYPES:
        return unknown("type %r is not one of %s" % (ptype, ", ".join(TYPES)))
    allowed = set(_NEEDS[ptype]) | {"id", "type", "title"}
    extra = set(raw) - allowed
    if extra:
        return unknown("unexpected keys for type %s: %s" % (ptype, ", ".join(sorted(extra))))
    for need in _NEEDS[ptype]:
        if need not in raw:
            return unknown("type %s needs %s" % (ptype, " and ".join(_NEEDS[ptype])))
    measure = limit = match = band = period = None
    if "measure" in raw:
        measure, reason = _validate_measure(raw["measure"], cfg, chk, _line(raw["measure"], line), field + ".measure")
        if reason:
            return unknown(reason)
        if ptype == "kill" and measure["kind"] != "drawdown":
            return unknown("kill needs a drawdown measure")
        if ptype == "allocation" and measure["kind"] != "share":
            return unknown("allocation needs a share measure")
    if "limit" in raw:
        limit, reason = _validate_limit(raw["limit"], _LIMITS[ptype])
        if reason:
            return unknown(reason)
    if "match" in raw:
        match, reason = _validate_match(raw["match"], cfg, chk, _line(raw["match"], line), field + ".match")
        if reason:
            return unknown(reason)
    if "period" in raw:
        period = raw["period"]
        if period not in KINDS:
            return unknown("period %r is not month, quarter or year" % (period,))
    if "band" in raw:
        band, reason = _validate_band(raw["band"])
        if reason:
            return unknown(reason)
    return Policy(pid, ptype, title, measure, limit, match, period, band, "ok", None, line, chk.file, raw)


def _names(value, chk, line, field, what):
    """A non-empty list of unique plain names, else a problem and ()."""
    if not isinstance(value, list) or not value:
        chk.add(line, "BAD-FIELD", field, "%s must be a non-empty list" % what)
        return ()
    out = []
    for item in value:
        if not _is_name(item):
            chk.add(line, "BAD-FIELD", field, "%s entry %r is not a plain name" % (what, item))
        elif item in out:
            chk.add(line, "DUP-ID", field, "%s %r is declared twice" % (what, item))
        else:
            out.append(item)
    return tuple(out)


def load(path):
    """Read policies.yml. Returns Loaded(config, problems); never raises."""
    doc, problems, file = read_yaml(path)
    if doc is None:
        return Loaded(None, problems)
    chk = _Check(file)
    chk.problems.extend(problems)
    if not isinstance(doc, dict):
        chk.add(1, "BAD-SHAPE", "", "policies.yml must be a mapping at the top level")
        return Loaded(None, chk.problems)
    top = _line(doc, 1)
    try:
        return Loaded(_build(doc, top, chk), chk.problems)
    except Exception as exc:  # the contract is "never raises"
        chk.add(0, "INTERNAL", "", "loader failed: %s: %s" % (type(exc).__name__, exc))
        return Loaded(None, chk.problems)


def _build(doc, top, chk):
    known = {"version", "base_currency", "accounts", "categories", "classes",
             "snapshot_max_age_days", "policies"}
    for key in sorted(set(doc) - known, key=str):
        chk.add(top, "BAD-FIELD", str(key), "unknown top-level key %r" % (key,))

    version = doc.get("version")
    if version != 1 or isinstance(version, bool):
        chk.add(top, "BAD-FIELD", "version", "version must be 1 (got %r)" % (version,))
        version = None

    base = doc.get("base_currency")
    if "base_currency" not in doc:
        chk.add(top, "MISSING-FIELD", "base_currency", "base_currency is missing")
        base = None
    elif not isinstance(base, str) or not _CURRENCY_RE.match(base):
        chk.add(top, "BAD-FIELD", "base_currency", "base_currency must be a 3-letter ISO-4217 code")
        base = None

    accounts = _names(doc.get("accounts"), chk, top, "accounts", "accounts")

    categories = {}
    cats = doc.get("categories")
    if not isinstance(cats, dict) or not cats:
        chk.add(top, "BAD-FIELD", "categories", "categories must be a mapping of group -> list of names")
    else:
        seen = {}
        for group, names in cats.items():
            if not _is_name(group):
                chk.add(_line(cats, top), "BAD-FIELD", "categories", "group %r is not a plain name" % (group,))
                continue
            names = _names(names, chk, _line(cats, top), "categories." + group, "categories." + group)
            kept = []
            for name in names:
                if name in seen:
                    chk.add(_line(cats, top), "DUP-ID", "categories." + group,
                            "category %r is declared under both %r and %r" % (name, seen[name], group))
                else:
                    seen[name] = group
                    kept.append(name)
            categories[group] = tuple(kept)
        for group in REQUIRED_GROUPS:
            if group not in categories:
                chk.add(_line(cats, top), "MISSING-FIELD", "categories." + group,
                        "categories must declare the group %r" % group)

    if "classes" in doc:
        classes = _names(doc.get("classes"), chk, top, "classes", "classes")
    else:
        classes = DEFAULT_CLASSES

    age = doc.get("snapshot_max_age_days")
    if "snapshot_max_age_days" not in doc:
        chk.add(top, "MISSING-FIELD", "snapshot_max_age_days", "snapshot_max_age_days is missing")
        age = None
    elif isinstance(age, bool) or not isinstance(age, int) or age < 1:
        chk.add(top, "BAD-FIELD", "snapshot_max_age_days", "snapshot_max_age_days must be a positive integer")
        age = None

    cfg = {"accounts": accounts, "categories": categories, "classes": classes,
           "all_categories": tuple(c for g in categories.values() for c in g)}
    policies = []
    raw_list = doc.get("policies")
    if not isinstance(raw_list, list) or not raw_list:
        chk.add(top, "EMPTY-POLICIES", "policies", "policies must be a non-empty list")
    else:
        ids = {}
        for index, raw in enumerate(raw_list):
            policy = _validate_policy(raw, index, cfg, chk, top)
            if policy is None:
                continue
            if policy.id in ids:
                chk.add(policy.line, "DUP-ID", "policies[%d].id" % index,
                        "policy id %r is already used at line %d" % (policy.id, ids[policy.id]))
                continue
            ids[policy.id] = policy.line
            policies.append(policy)
    return Config(version, base, accounts, categories, classes, age, tuple(policies), chk.file)


# -------------------------------------------------------------------- rendering


def measure_text(measure):
    """Short text for a normalized measure, for the one-line verdict."""
    if measure is None:
        return "?"
    kind = measure["kind"]
    if kind == "sum":
        target = measure["group"] + ("." + measure["category"] if measure["category"] else "")
        return "sum %s per %s" % (target, measure["period"])
    if kind == "drawdown":
        return "drawdown %s.%s over %d days" % (measure["by"], measure["name"], measure["window_days"])
    return "%s %s.%s" % (kind, measure["by"], measure["name"])


def limit_text(limit, base_currency=""):
    if limit is None:
        return "?"
    kind = limit["kind"]
    value = str(limit["value"])
    if kind == "value":
        return (value + " " + base_currency).strip()
    if kind == "pct_of":
        return "%s%% of %s" % (value, limit["of"])
    if kind == "months_of":
        return "%s months of %s" % (value, limit["of"])
    return value + "%"


def band_text(band):
    if band is None:
        return "?"
    return "%s%%..%s%%" % (band["min_pct"], band["max_pct"])


def match_text(match):
    if match is None:
        return "?"
    parts = []
    if "tags" in match:
        parts.append("tags " + ";".join(match["tags"]))
    if "tags_any" in match:
        parts.append("any tag of " + ",".join(match["tags_any"]))
    if "account" in match:
        parts.append("account " + match["account"])
    if "category" in match:
        parts.append("category " + match["category"])
    if "min_amount" in match:
        parts.append("amount >= " + str(match["min_amount"]))
    return ", ".join(parts)


def is_date_text(value):
    return isinstance(value, str) and bool(_DATE_RE.match(value))


def as_date(value):
    """A datetime.date from a YAML date or ISO text; None otherwise.
    A datetime (date with a time) is rejected: dates only."""
    if isinstance(value, datetime.datetime):
        return None
    if isinstance(value, datetime.date):
        return value
    if is_date_text(value):
        try:
            return datetime.date.fromisoformat(value)
        except ValueError:
            return None
    return None
