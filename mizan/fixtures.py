"""Sidecar fixtures of a rule and the verdict they give (ADR-0001 sections 4, 6).

Next to ``<name>.yml`` live ``<name>.positive.jsonl`` (every line must match)
and ``<name>.negative.jsonl`` (no line may match).  ``judge(rule)`` returns a
``report.Result``:

- ``invalid``  the rule itself did not load (the loader's problems);
- ``unknown``  the rule uses a feature Mizan does not evaluate, or any
               fixture line could not be judged: malformed JSON, not an
               object, not UTF-8, over the line limit, an unreadable or
               oversized file (A4, A7); each is cited ``<file>:<line>``;
- ``fail``     a positive line did not match or a negative line matched
               (each cited), or a sidecar is missing or has no event (A2);
- ``pass``     everything else; the lines it rests on are cited too (A5).

Fixture files are data, never code (A7): no eval, strict JSON, a byte
limit per line and per file, and every malformed line is reported with its
number.  Blank lines are not events; they are counted and reported, never
silently dropped.
"""

import json
import os
import re
from typing import Any, Iterator, List, Optional, Tuple

from mizan import condition
from mizan.loader import Problems, Rule
from mizan.matcher import Unknown
from mizan.report import Result

#: ADR-0001 section 4 limits.
MAX_LINE_BYTES = 1 << 20
MAX_FILE_BYTES = 256 << 20

POSITIVE = "positive"
NEGATIVE = "negative"


# --- JSON Lines reading ----------------------------------------------------------------

class Line:
    """One line of a JSON Lines file: ``event`` (a dict) or ``error``."""

    __slots__ = ("number", "event", "error")

    def __init__(self, number: Optional[int], event: Any = None, error: Optional[str] = None):
        self.number = number
        self.event = event
        self.error = error

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:
        return "Line(%r, event=%r, error=%r)" % (self.number, self.event, self.error)


def _reject_constant(name: str):
    raise ValueError("non-standard JSON constant %s" % name)


def _reject_duplicates(pairs):
    seen = set()
    out = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate key %r" % key)
        seen.add(key)
        out[key] = value
    return out


_JSON_POSITION_RE = re.compile(r": line 1 column (\d+) \(char \d+\)$")


def _json_error_text(exc: Exception) -> str:
    """json's message without its own 'line 1' (every event is one line)."""
    text = (str(exc).splitlines() or ["?"])[0]
    return _JSON_POSITION_RE.sub(r" (column \1)", text)


def parse_event(text: str) -> Tuple[Any, Optional[str]]:
    """Strict JSON object from one line: (event, None) or (None, error)."""
    try:
        value = json.loads(text, parse_constant=_reject_constant,
                           object_pairs_hook=_reject_duplicates)
    except ValueError as exc:
        return None, "malformed JSON: %s" % _json_error_text(exc)
    except RecursionError:
        return None, "malformed JSON: nested too deeply"
    if not isinstance(value, dict):
        return None, "event is not a JSON object (got %s)" % type(value).__name__
    return value, None


def sidecar_paths(rule_path: str) -> Tuple[str, str]:
    """(positive, negative) sidecar paths of a rule file."""
    stem = os.path.splitext(rule_path)[0]
    return ("%s.%s.jsonl" % (stem, POSITIVE), "%s.%s.jsonl" % (stem, NEGATIVE))


def file_problem(path: str) -> Optional[str]:
    """Why ``path`` cannot be read as a JSON Lines file, or None."""
    if not os.path.exists(path):
        return "missing"
    if not os.path.isfile(path):
        return "not a file"
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return "cannot be read: %s" % (exc.strerror or exc)
    if size > MAX_FILE_BYTES:
        return "file larger than %d bytes (%d)" % (MAX_FILE_BYTES, size)
    return None


def iter_jsonl(path: str) -> Iterator[Line]:
    """Yield one ``Line`` per line of a JSON Lines file, never raising.

    A whole-file problem (missing, unreadable, over the size limit) is one
    ``Line`` with ``number`` None.  Blank lines yield ``Line(n, None, None)``
    with ``event`` None and no error; callers count them.
    """
    problem = file_problem(path)
    if problem is not None:
        yield Line(None, None, problem)
        return
    try:
        with open(path, "rb") as handle:
            number = 0
            for raw in handle:
                number += 1
                if raw.endswith(b"\n"):
                    raw = raw[:-1]
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                if len(raw) > MAX_LINE_BYTES:
                    yield Line(number, None, "line longer than %d bytes (%d)" % (MAX_LINE_BYTES, len(raw)))
                    continue
                if not raw.strip():
                    yield Line(number, None, None)
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    yield Line(number, None, "not UTF-8 text (byte %d)" % exc.start)
                    continue
                event, error = parse_event(text)
                yield Line(number, event, error)
    except OSError as exc:
        yield Line(None, None, "cannot be read: %s" % (exc.strerror or exc))


# --- verdicts ------------------------------------------------------------------------------

class _Side:
    """What one sidecar file contributed."""

    __slots__ = ("kind", "path", "events", "blank", "wrong", "unknown", "problem", "judged")

    def __init__(self, kind: str, path: str):
        self.kind = kind
        self.path = path
        self.events = 0
        self.blank = 0
        self.wrong: List[int] = []
        self.unknown: List[Tuple[int, str]] = []
        self.problem: Optional[str] = None
        self.judged: List[int] = []

    def as_dict(self):
        return {"file": self.path, "events": self.events, "blank_lines": self.blank,
                "wrong": list(self.wrong), "unknown": [n for n, _ in self.unknown],
                "problem": self.problem}


def _judge_side(side: _Side, compiled, result: Result, must_match: bool) -> None:
    for line in iter_jsonl(side.path):
        if line.number is None:
            side.problem = line.error
            return
        if line.error is not None:
            side.unknown.append((line.number, line.error))
            result.cite(side.path, line.number, line.error)
            continue
        if line.event is None:
            side.blank += 1
            continue
        side.events += 1
        if compiled is None:
            continue  # the rule itself is unknown; lines are counted, not judged
        verdict = compiled.evaluate(line.event)
        if isinstance(verdict, Unknown):
            side.unknown.append((line.number, verdict.reason))
            result.cite(side.path, line.number, "unknown: %s" % verdict.reason)
        elif verdict is must_match:
            side.judged.append(line.number)
        else:
            side.wrong.append(line.number)
            result.cite(side.path, line.number,
                        "did not match (must match)" if must_match else "matched (must not match)")


def judge(rule, compiled=None) -> Result:
    """The verdict of a rule's sidecar fixtures; never raises."""
    if isinstance(rule, Problems):
        return Result("invalid", rule.path, problems=rule.as_list())
    if not isinstance(rule, Rule):
        return Result("invalid", str(getattr(rule, "path", rule)),
                      problems=[{"field": "rule", "reason": "not a loaded rule"}])
    result = Result("pass", rule.path, id=rule.id, title=rule.title)
    if compiled is None:
        compiled = condition.compile_rule(rule)
    rule_unknown = None
    if isinstance(compiled, Unknown):
        rule_unknown = compiled.reason
        result.cite(rule.path, None, "unknown: %s" % rule_unknown)
        compiled = None
    positive_path, negative_path = sidecar_paths(rule.path)
    sides = [_Side(POSITIVE, positive_path), _Side(NEGATIVE, negative_path)]
    for side in sides:
        _judge_side(side, compiled, result, must_match=(side.kind == POSITIVE))
    any_unknown = rule_unknown is not None
    any_fail = False
    for side in sides:
        if side.problem is not None:
            if side.problem == "missing":
                result.cite(side.path, None, "missing: every rule needs a %s fixture (A2)" % side.kind)
                any_fail = True
            else:
                result.cite(side.path, None, side.problem)
                any_unknown = True
        elif side.events == 0:
            result.cite(side.path, None, "no event: a %s fixture needs at least one non-empty line (A2)" % side.kind)
            any_fail = True
        if side.unknown:
            any_unknown = True
        if side.wrong:
            any_fail = True
    if any_unknown:
        result.status = "unknown"
    elif any_fail:
        result.status = "fail"
    else:
        result.status = "pass"
        for side in sides:  # A5: the lines the pass rests on
            verb = "matched" if side.kind == POSITIVE else "did not match"
            for number in side.judged:
                result.cite(side.path, number, verb)
    notes = []
    for side in sides:
        if side.blank:
            notes.append("%s: %d blank line(s) ignored" % (side.path, side.blank))
    result.details["fixtures"] = {side.kind: side.as_dict() for side in sides}
    if notes:
        result.details["notes"] = notes
    return result


def match_file(rule, events_path: str, compiled=None) -> Result:
    """Run one rule over one JSON Lines file (the ``match`` command).

    Status ``ok`` when every line was judged, ``unknown`` when any line was
    not, ``invalid`` when the rule did not load; matched and unknown lines
    are cited separately.  The file itself unreadable -> status ``unknown``
    with the file cited; the caller maps that to exit code 3.
    """
    if isinstance(rule, Problems):
        return Result("invalid", rule.path, problems=rule.as_list(),
                      details={"file": events_path, "events": 0, "matched": [], "unknown": []})
    if not isinstance(rule, Rule):
        return Result("invalid", str(getattr(rule, "path", rule)),
                      problems=[{"field": "rule", "reason": "not a loaded rule"}])
    result = Result("ok", rule.path, id=rule.id, title=rule.title)
    matched: List[int] = []
    unknown: List[dict] = []
    events = 0
    blank = 0
    file_error = None
    if compiled is None:
        compiled = condition.compile_rule(rule)
    if isinstance(compiled, Unknown):
        result.cite(rule.path, None, "unknown: %s" % compiled.reason)
        compiled = None
    for line in iter_jsonl(events_path):
        if line.number is None:
            file_error = line.error
            result.cite(events_path, None, line.error)
            break
        if line.error is not None:
            unknown.append({"line": line.number, "reason": line.error})
            result.cite(events_path, line.number, "unknown: %s" % line.error)
            continue
        if line.event is None:
            blank += 1
            continue
        events += 1
        if compiled is None:
            continue
        verdict = compiled.evaluate(line.event)
        if isinstance(verdict, Unknown):
            unknown.append({"line": line.number, "reason": verdict.reason})
            result.cite(events_path, line.number, "unknown: %s" % verdict.reason)
        elif verdict is True:
            matched.append(line.number)
            result.cite(events_path, line.number, "match")
    if compiled is None or unknown or file_error is not None:
        result.status = "unknown"
    result.details.update({
        "file": events_path, "events": events, "blank_lines": blank,
        "matched": matched, "unknown": unknown, "file_error": file_error,
    })
    result.details["notes"] = ["events=%d matched=%d unknown=%d%s" % (
        events, len(matched), len(unknown),
        " blank=%d" % blank if blank else "")]
    return result
