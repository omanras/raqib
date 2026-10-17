"""Evaluate one Sigma selection against one event (ADR-0001 sections 4-5).

``match_selection(selection, event)`` returns ``True``, ``False`` or an
``Unknown(reason)``.  It never raises on bad data.  ``Unknown`` is returned
for every Sigma feature outside the supported subset (an unsupported
modifier, an invalid regular expression, a selection shape Mizan does not
evaluate); it is never silently treated as a plain comparison (A4).

Inside one selection an ``Unknown`` dominates: a selection that uses an
unsupported feature is unknown whatever its other fields say.  The three-
valued logic that combines whole selections lives in mizan/condition.py.

Supported subset:
- mapping selection: AND across fields; a list of values is OR, or AND with
  the ``all`` modifier;
- list-of-strings selection: keyword search over every string value
  anywhere in the event, nested objects and arrays included;
- case-insensitive comparison; ``*`` and ``?`` wildcards; a backslash
  escapes ``*``, ``?`` and ``\\``; event values that are not strings compare
  as their JSON text;
- ``field: null`` matches an absent or null field;
- the exact field name first, then a dotted path through nested objects;
- modifiers ``contains``, ``startswith``, ``endswith``, ``all``, ``re``
  (with ``i``), ``exists``, ``gt``, ``gte``, ``lt``, ``lte``, ``cidr``,
  ``windash``.
"""

import functools
import ipaddress
import json
import math
import re
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["Unknown", "match_selection", "compile_selection", "lookup_field",
           "CompiledSelection", "KNOWN_MODIFIERS", "MISSING"]


class Unknown:
    """The third answer: Mizan could not judge, and says why.

    It has no truth value on purpose: ``if result:`` raises instead of
    silently counting an unknown as a match or a non-match.  Test with
    ``isinstance(result, Unknown)``.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: str):
        self.reason = str(reason)

    def __repr__(self) -> str:
        return "Unknown(%r)" % (self.reason,)

    def __eq__(self, other) -> bool:
        return isinstance(other, Unknown) and other.reason == self.reason

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(("Unknown", self.reason))

    def __bool__(self):
        raise TypeError("Unknown has no truth value; test with isinstance(x, Unknown)")


#: Sentinel for "the field is not in the event".
MISSING = object()

_STRING_KINDS = ("contains", "startswith", "endswith")
_NUMERIC_KINDS = ("gt", "gte", "lt", "lte")
_KIND_MODIFIERS = _STRING_KINDS + _NUMERIC_KINDS + ("re", "exists", "cidr")
_FLAG_MODIFIERS = ("all", "windash", "i")
KNOWN_MODIFIERS = frozenset(_KIND_MODIFIERS + _FLAG_MODIFIERS)

_JSON_NUMBER_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")


# --- event side ----------------------------------------------------------------

def lookup_field(event: Dict[str, Any], field: str):
    """Return the event value for ``field`` or ``MISSING``.

    The exact key wins; if it is absent and the name contains a dot, the
    name is resolved as a path through nested objects (ADR-0001 section 4).
    """
    if field in event:
        return event[field]
    if "." in field:
        current = event
        for part in field.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return MISSING
        return current
    return MISSING


def _json_text(value: Any) -> str:
    """The JSON text of a non-string value (compact, keys sorted)."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _as_number(value: Any) -> Optional[float]:
    """The numeric value of an event field under gt/gte/lt/lte, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value if math.isfinite(value) else None
    if isinstance(value, str) and _JSON_NUMBER_RE.match(value):
        try:
            number = float(value) if any(c in value for c in ".eE") else int(value)
        except (ValueError, OverflowError):
            return None
        if isinstance(number, float) and not math.isfinite(number):
            return None
        return number
    return None


def _strings_in(event: Dict[str, Any]) -> List[str]:
    """Every string value anywhere in the event (nested objects and arrays)."""
    out = []
    stack = [event]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return out


# --- rule side: patterns -------------------------------------------------------

def _wildcard_to_regex(value: str, windash: bool) -> str:
    out = []
    i = 0
    length = len(value)
    while i < length:
        char = value[i]
        if char == "\\":
            if i + 1 < length and value[i + 1] in "*?\\":
                out.append(re.escape(value[i + 1]))
                i += 2
                continue
            out.append(re.escape("\\"))
        elif char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        elif windash and char == "-":
            out.append("[-/]")
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


@functools.lru_cache(maxsize=8192)
def _compile_wildcard(value: str, kind: Optional[str], windash: bool):
    body = _wildcard_to_regex(value, windash)
    if kind is None:
        pattern = r"\A(?:%s)\Z" % body
    elif kind == "contains":
        pattern = body
    elif kind == "startswith":
        pattern = r"\A(?:%s)" % body
    else:  # endswith
        pattern = r"(?:%s)\Z" % body
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


@functools.lru_cache(maxsize=1024)
def _compile_regex(value: str, ignore_case: bool):
    """A compiled regex, or an ``Unknown`` when the pattern is invalid."""
    try:
        return re.compile(value, re.IGNORECASE if ignore_case else 0)
    except (re.error, OverflowError, RecursionError) as exc:
        return Unknown("invalid regular expression %r: %s" % (value, exc))


class _Matcher:
    """One rule-side value, ready to be tested against one event value."""

    __slots__ = ("test",)

    def __init__(self, test):
        self.test = test

    def __call__(self, value) -> bool:
        return self.test(value)


def _null_matcher() -> _Matcher:
    return _Matcher(lambda value: value is MISSING or value is None)


def _wildcard_matcher(text: str, kind: Optional[str], windash: bool) -> _Matcher:
    regex = _compile_wildcard(text, kind, windash)
    return _Matcher(lambda value: value is not MISSING and regex.search(_json_text(value)) is not None)


def _regex_matcher(regex) -> _Matcher:
    return _Matcher(lambda value: value is not MISSING and regex.search(_json_text(value)) is not None)


def _numeric_matcher(kind: str, bound) -> _Matcher:
    def test(value):
        number = _as_number(value) if value is not MISSING else None
        if number is None:
            return False
        if kind == "gt":
            return number > bound
        if kind == "gte":
            return number >= bound
        if kind == "lt":
            return number < bound
        return number <= bound
    return _Matcher(test)


def _cidr_matcher(network) -> _Matcher:
    def test(value):
        if value is MISSING or not isinstance(value, str):
            return False
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return address in network
    return _Matcher(test)


def _exists_matcher(expected: bool) -> _Matcher:
    return _Matcher(lambda value: (value is not MISSING) == expected)


# --- rule side: field specifications -------------------------------------------

class _FieldSpec:
    __slots__ = ("spec", "name", "kind", "all", "windash", "ignore_case", "matchers")

    def __init__(self, spec, name, kind, all_, windash, ignore_case):
        self.spec = spec
        self.name = name
        self.kind = kind
        self.all = all_
        self.windash = windash
        self.ignore_case = ignore_case
        self.matchers: List[_Matcher] = []

    def match(self, event: Dict[str, Any]) -> bool:
        value = lookup_field(event, self.name)
        if self.all:
            return all(m(value) for m in self.matchers)
        return any(m(value) for m in self.matchers)


def _parse_spec(spec: Any):
    """Parse ``field|mod|mod`` into a _FieldSpec without values, or Unknown."""
    if not isinstance(spec, str):
        return Unknown("field name must be a string (got %s)" % type(spec).__name__)
    parts = spec.split("|")
    name = parts[0]
    modifiers = parts[1:]
    if not name:
        return Unknown("empty field name in %r" % spec)
    seen = []
    for modifier in modifiers:
        if modifier not in KNOWN_MODIFIERS:
            return Unknown("unsupported modifier %r on field %r" % (modifier, name))
        if modifier in seen:
            return Unknown("modifier %r repeated on field %r" % (modifier, name))
        seen.append(modifier)
    kinds = [m for m in seen if m in _KIND_MODIFIERS]
    if len(kinds) > 1:
        return Unknown("modifiers %s cannot be combined on field %r"
                       % (" and ".join(repr(k) for k in kinds), name))
    kind = kinds[0] if kinds else None
    all_ = "all" in seen
    windash = "windash" in seen
    ignore_case = "i" in seen
    if ignore_case and kind != "re":
        return Unknown("modifier 'i' is only valid with 're' (field %r)" % name)
    if windash and kind not in (None,) + _STRING_KINDS:
        return Unknown("modifier 'windash' cannot be combined with %r (field %r)" % (kind, name))
    if kind == "exists" and (all_ or windash):
        return Unknown("modifier 'exists' takes no other modifier (field %r)" % name)
    return _FieldSpec(spec, name, kind, all_, windash, ignore_case)


def _build_matcher(field: _FieldSpec, value: Any):
    """A _Matcher for one rule-side value, or Unknown."""
    kind = field.kind
    name = field.name
    if kind == "exists":
        if not isinstance(value, bool):
            return Unknown("'exists' needs true or false (field %r)" % name)
        return _exists_matcher(value)
    if kind in _NUMERIC_KINDS:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return Unknown("%r needs a finite number in the rule (field %r)" % (kind, name))
        return _numeric_matcher(kind, value)
    if kind == "cidr":
        if not isinstance(value, str):
            return Unknown("'cidr' needs a network string (field %r)" % name)
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            return Unknown("invalid CIDR %r (field %r): %s" % (value, name, exc))
        return _cidr_matcher(network)
    if kind == "re":
        if not isinstance(value, str):
            return Unknown("'re' needs a pattern string (field %r)" % name)
        regex = _compile_regex(value, field.ignore_case)
        if isinstance(regex, Unknown):
            return Unknown("%s (field %r)" % (regex.reason, name))
        return _regex_matcher(regex)
    # plain, contains, startswith, endswith
    if value is None:
        if kind is not None or field.windash:
            return Unknown("null is only valid as a plain value (field %r)" % field.spec)
        return _null_matcher()
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bool, int, float)):
        text = _json_text(value)
    else:
        return Unknown("unsupported value type %s (field %r)" % (type(value).__name__, name))
    return _wildcard_matcher(text, kind, field.windash)


def _compile_field(spec: Any, raw_value: Any):
    field = _parse_spec(spec)
    if isinstance(field, Unknown):
        return field
    if isinstance(raw_value, list):
        if not raw_value:
            return Unknown("empty value list (field %r)" % field.name)
        values = raw_value
        if field.kind == "exists":
            return Unknown("'exists' takes a single true or false (field %r)" % field.name)
    else:
        values = [raw_value]
    for value in values:
        matcher = _build_matcher(field, value)
        if isinstance(matcher, Unknown):
            return matcher
        field.matchers.append(matcher)
    return field


# --- compiled selections -------------------------------------------------------

class CompiledSelection:
    """A selection validated and compiled once; ``match(event)`` many times."""

    __slots__ = ("fields", "keywords")

    def __init__(self, fields: Optional[List[_FieldSpec]], keywords: Optional[List[_Matcher]]):
        self.fields = fields
        self.keywords = keywords

    def match(self, event: Any):
        if not isinstance(event, dict):
            return Unknown("event is not a JSON object (got %s)" % type(event).__name__)
        try:
            if self.fields is not None:
                return all(field.match(event) for field in self.fields)
            strings = _strings_in(event)
            return any(keyword(text) for text in strings for keyword in self.keywords)
        except Exception as exc:  # never raise on bad data
            return Unknown("matcher error: %s: %s" % (type(exc).__name__, exc))


def _compile_mapping(selection: Dict[str, Any]):
    fields = []
    for spec, raw_value in selection.items():
        field = _compile_field(spec, raw_value)
        if isinstance(field, Unknown):
            return field
        fields.append(field)
    return CompiledSelection(fields, None)


def _compile_keywords(selection: List[Any]):
    keywords = []
    for index, keyword in enumerate(selection):
        if not isinstance(keyword, str):
            return Unknown("keyword %d must be a string (got %s); a list of mappings is not supported"
                           % (index + 1, type(keyword).__name__))
        keywords.append(_wildcard_matcher(keyword, "contains", False))
    return CompiledSelection(None, keywords)


def compile_selection(selection: Any):
    """Validate and compile one selection; a ``CompiledSelection`` or ``Unknown``."""
    try:
        if isinstance(selection, dict):
            if not selection:
                return Unknown("empty selection mapping")
            return _compile_mapping(selection)
        if isinstance(selection, list):
            if not selection:
                return Unknown("empty keyword list")
            return _compile_keywords(selection)
        return Unknown("selection must be a mapping or a list of keywords (got %s)"
                       % type(selection).__name__)
    except Exception as exc:  # never raise on bad data
        return Unknown("matcher error: %s: %s" % (type(exc).__name__, exc))


@functools.lru_cache(maxsize=1024)
def _compile_cached(key: str):
    return compile_selection(json.loads(key))


def _is_json_native(value: Any) -> bool:
    """True when ``value`` is built only of dict (string keys), list, str,
    int, float, bool and None, so that a JSON round trip reproduces it."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    return False
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, (str, bool, int, float)) or item is None:
            if type(item) not in (str, bool, int, float, type(None)):
                return False  # a subclass (an Enum, a YAML timestamp) is not native
        else:
            return False
    return True


def _cache_key(selection: Any) -> Optional[str]:
    """A JSON key for the compile cache, or None when the selection would not
    survive the JSON round trip unchanged."""
    if not _is_json_native(selection):
        return None
    try:
        return json.dumps(selection, sort_keys=True)
    except (TypeError, ValueError):
        return None


def match_selection(selection: Any, event: Any):
    """Evaluate ``selection`` against ``event``: True, False or Unknown."""
    try:
        key = _cache_key(selection) if isinstance(selection, (dict, list)) else None
        compiled = _compile_cached(key) if key is not None else compile_selection(selection)
        if isinstance(compiled, Unknown):
            return compiled
        return compiled.match(event)
    except Exception as exc:  # never raise on bad data
        return Unknown("matcher error: %s: %s" % (type(exc).__name__, exc))
