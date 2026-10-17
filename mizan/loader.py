"""Read one Sigma rule file and validate its shape (ADR-0001 section 3).

``load(path)`` returns a ``Rule`` when the file has the required shape, or a
``Problems`` list naming every problem found.  It never raises on bad input:
a missing file, a directory, binary garbage, invalid YAML, several YAML
documents, a non-mapping document or a missing/invalid field are all
problems, not exceptions.

Only the shape is validated here.  Whether a selection or the condition can
be evaluated is decided by the matcher and the condition module, which
return ``unknown`` for anything they do not support (A4).
"""

import math
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import yaml

#: The five Sigma levels (ADR-0001 section 3).
LEVELS = ("informational", "low", "medium", "high", "critical")

#: Keys of ``logsource`` of which at least one is required.
LOGSOURCE_KEYS = ("product", "category", "service")

#: Keys Mizan understands under ``x-mizan``.  Any other key is a problem:
#: ``x-mizan`` is Mizan's own namespace, so an unknown key there is most
#: likely a misspelling and is never silently ignored.
XMIZAN_KEYS = ("fp_budget", "corpus")

#: A rule file larger than this is refused (A7: size limits on every file).
MAX_RULE_BYTES = 1 << 20

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MERGE_TAG = "tag:yaml.org,2002:merge"


@dataclass(frozen=True)
class Problem:
    """One named problem: which field, and why."""

    field: str
    reason: str

    def as_dict(self) -> Dict[str, str]:
        return {"field": self.field, "reason": self.reason}


class Problems(list):
    """The problems of one rule file (a list of ``Problem``) plus its path."""

    def __init__(self, path: str, problems=()):
        super().__init__(problems)
        self.path = path

    def add(self, field: str, reason: str) -> None:
        self.append(Problem(field, reason))

    def as_list(self) -> List[Dict[str, str]]:
        return [p.as_dict() for p in self]

    def __repr__(self) -> str:
        return "Problems(%r, %s)" % (self.path, list.__repr__(self))


@dataclass(frozen=True)
class Rule:
    """A validated Sigma rule with the Mizan extension."""

    title: str
    id: str
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    condition: str
    level: str
    fp_budget: float
    corpus: Optional[List[str]]
    raw: Dict[str, Any]
    path: str

    @property
    def selections(self) -> Dict[str, Any]:
        """The search identifiers of ``detection`` (everything but condition)."""
        return {k: v for k, v in self.detection.items() if k != "condition"}


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys instead of keeping the
    last one silently (a rule with two ``condition`` keys is not a rule)."""

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            seen = set()
            for key_node, _value_node in node.value:
                if key_node.tag == _MERGE_TAG:
                    continue
                key = self.construct_object(key_node, deep=deep)
                try:
                    duplicate = key in seen
                except TypeError:
                    continue  # unhashable key: SafeLoader reports it below
                if duplicate:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping", node.start_mark,
                        "found duplicate key %r" % (key,), key_node.start_mark)
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _read_text(path: str, problems: Problems) -> Optional[str]:
    """Read the file as UTF-8 text, or record why it cannot be read."""
    if not os.path.isfile(path):
        problems.add("path", "not a file: %s" % path)
        return None
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_RULE_BYTES + 1)
    except OSError as exc:
        problems.add("path", "cannot be read: %s" % exc.strerror)
        return None
    if len(data) > MAX_RULE_BYTES:
        problems.add("file", "larger than %d bytes" % MAX_RULE_BYTES)
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        problems.add("file", "not UTF-8 text (byte %d)" % exc.start)
        return None


def _parse_yaml(text: str, problems: Problems) -> Optional[Dict[str, Any]]:
    """Parse exactly one YAML document that is a mapping."""
    try:
        documents = []
        for document in yaml.load_all(text, Loader=_StrictLoader):
            documents.append(document)
            if len(documents) > 1:
                break
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = ""
        if mark is not None:
            where = " at line %d column %d" % (mark.line + 1, mark.column + 1)
        detail = getattr(exc, "problem", None) or (str(exc).splitlines() or [type(exc).__name__])[0]
        problems.add("yaml", "not valid YAML%s: %s" % (where, detail))
        return None
    if not documents:
        problems.add("yaml", "empty file: no YAML document")
        return None
    if len(documents) > 1:
        problems.add("yaml", "several YAML documents in one file; one rule per file")
        return None
    document = documents[0]
    if not isinstance(document, dict):
        problems.add("yaml", "document is not a mapping (got %s)"
                     % type(document).__name__)
        return None
    return document


def _check_title(raw: Dict[str, Any], problems: Problems) -> Optional[str]:
    if "title" not in raw:
        problems.add("title", "missing")
        return None
    title = raw["title"]
    if not isinstance(title, str) or not title.strip():
        problems.add("title", "must be a non-empty string")
        return None
    return title


def _check_id(raw: Dict[str, Any], problems: Problems) -> Optional[str]:
    if "id" not in raw:
        problems.add("id", "missing")
        return None
    rule_id = raw["id"]
    if not isinstance(rule_id, str) or not _UUID_RE.match(rule_id):
        problems.add("id", "must be a UUID string (8-4-4-4-12 hex digits)")
        return None
    return rule_id


def _check_logsource(raw: Dict[str, Any], problems: Problems) -> Optional[Dict[str, Any]]:
    if "logsource" not in raw:
        problems.add("logsource", "missing")
        return None
    logsource = raw["logsource"]
    if not isinstance(logsource, dict):
        problems.add("logsource", "must be a mapping")
        return None
    present = [k for k in LOGSOURCE_KEYS if k in logsource]
    if not present:
        problems.add("logsource", "needs at least one of product, category, service")
        return None
    ok = True
    for key in present:
        value = logsource[key]
        if not isinstance(value, str) or not value.strip():
            problems.add("logsource.%s" % key, "must be a non-empty string")
            ok = False
    return logsource if ok else None


def _check_detection(raw: Dict[str, Any], problems: Problems):
    """Return (detection, condition) or (None, None)."""
    if "detection" not in raw:
        problems.add("detection", "missing")
        return None, None
    detection = raw["detection"]
    if not isinstance(detection, dict):
        problems.add("detection", "must be a mapping")
        return None, None
    ok = True
    condition = None
    if "condition" not in detection:
        problems.add("detection.condition", "missing")
        ok = False
    else:
        condition = detection["condition"]
        if not isinstance(condition, str) or not condition.strip():
            problems.add("detection.condition",
                         "must be a non-empty string (a list of conditions is not supported)")
            ok = False
            condition = None
    identifiers = [k for k in detection if k != "condition"]
    if not identifiers:
        problems.add("detection", "needs at least one search identifier besides condition")
        ok = False
    for key in identifiers:
        if not isinstance(key, str) or not key.strip():
            problems.add("detection", "search identifier %r must be a non-empty string" % (key,))
            ok = False
    if not ok:
        return None, None
    return detection, condition


def _check_level(raw: Dict[str, Any], problems: Problems) -> Optional[str]:
    if "level" not in raw:
        problems.add("level", "missing")
        return None
    level = raw["level"]
    if not isinstance(level, str) or level not in LEVELS:
        problems.add("level", "must be one of %s" % ", ".join(LEVELS))
        return None
    return level


def _check_xmizan(raw: Dict[str, Any], problems: Problems):
    """Return (fp_budget, corpus) or (None, None) on any problem."""
    if "x-mizan" not in raw:
        problems.add("x-mizan", "missing (declare x-mizan.fp_budget)")
        return None, None
    xmizan = raw["x-mizan"]
    if not isinstance(xmizan, dict):
        problems.add("x-mizan", "must be a mapping")
        return None, None
    ok = True
    for key in xmizan:
        if key not in XMIZAN_KEYS:
            problems.add("x-mizan.%s" % (key,), "unknown key (known: %s)" % ", ".join(XMIZAN_KEYS))
            ok = False
    fp_budget = None
    if "fp_budget" not in xmizan:
        problems.add("x-mizan.fp_budget", "missing")
        ok = False
    else:
        value = xmizan["fp_budget"]
        if not _is_number(value) or not math.isfinite(value):
            problems.add("x-mizan.fp_budget", "must be a number >= 0 (matches per 10,000 benign events)")
            ok = False
        elif value < 0:
            problems.add("x-mizan.fp_budget", "must not be negative")
            ok = False
        else:
            fp_budget = float(value)
    corpus = None
    if "corpus" in xmizan:
        value = xmizan["corpus"]
        if (not isinstance(value, list) or not value
                or not all(isinstance(v, str) and v.strip() for v in value)):
            problems.add("x-mizan.corpus", "must be a non-empty list of corpus file names")
            ok = False
        else:
            corpus = list(value)
    if not ok:
        return None, None
    return fp_budget, corpus


def _validate(raw: Dict[str, Any], path: str, problems: Problems) -> Optional[Rule]:
    title = _check_title(raw, problems)
    rule_id = _check_id(raw, problems)
    logsource = _check_logsource(raw, problems)
    detection, condition = _check_detection(raw, problems)
    level = _check_level(raw, problems)
    fp_budget, corpus = _check_xmizan(raw, problems)
    if problems:
        return None
    return Rule(
        title=title,
        id=rule_id,
        logsource=logsource,
        detection=detection,
        condition=condition,
        level=level,
        fp_budget=fp_budget,
        corpus=corpus,
        raw=raw,
        path=path,
    )


def find_rules(directory) -> List[str]:
    """Every ``*.yml`` file under ``directory`` (recursive), sorted; never
    raises -- an unreadable directory yields an empty list.  Callers check
    the directory exists first (ADR-0001 section 8: exit 3)."""
    found: List[str] = []
    try:
        root = os.fspath(directory)
        for current, dirs, files in os.walk(root):
            dirs.sort()
            for name in sorted(files):
                if name.endswith(".yml"):
                    found.append(os.path.join(current, name))
    except (OSError, TypeError):
        return []
    return found


def load(path):
    """Read the rule file at ``path``.

    Returns a ``Rule`` or a ``Problems`` list; never raises.  Unknown Sigma
    fields are kept in ``Rule.raw`` and are not problems (ADR-0001 section 3).
    """
    try:
        path_text = os.fspath(path)
        if isinstance(path_text, bytes):
            path_text = os.fsdecode(path_text)
    except TypeError:
        return Problems(repr(path), [Problem("path", "not a path: %r" % (path,))])
    problems = Problems(path_text)
    try:
        text = _read_text(path_text, problems)
        if text is None:
            return problems
        raw = _parse_yaml(text, problems)
        if raw is None:
            return problems
        rule = _validate(raw, path_text, problems)
        if rule is None:
            return problems
        return rule
    except Exception as exc:  # the contract: never raise on bad input
        problems.add("file", "cannot be loaded (%s: %s)" % (type(exc).__name__, exc))
        return problems
