"""decisions.yml loader (ADR-0001 section 7).

``load(path, policy_ids)`` returns ``Loaded(decisions, problems)`` and never
raises. The file is a YAML list; each entry needs ``id``, ``date``,
``review_by`` and ``status`` (open | closed); ``title`` and ``criteria``
are free text; ``policy`` and ``closes`` are optional and must name a
declared policy id when given. Bad dates, unknown policies, unknown
statuses, duplicate ids and a review date before the decision date are
problems naming the field; the entry is dropped and the run continues.
"""

from typing import NamedTuple, Optional

from .ledger import _problem, INVALID
from .policies import Map, as_date, read_yaml

STATUSES = ("open", "closed")


class Decision(NamedTuple):
    id: str
    date: object           # datetime.date
    title: str
    policy: Optional[str]
    criteria: str
    review_by: object      # datetime.date
    status: str
    closes: Optional[str]
    line: int
    file: str

    @property
    def cite(self):
        return "%s:%d" % (self.file, self.line)

    @property
    def is_open(self):
        return self.status == "open"

    def days_until_review(self, as_of):
        """Days from as_of to review_by; negative when overdue."""
        return (self.review_by - as_of).days

    def is_due(self, as_of):
        """DECISION-DUE: open and review_by strictly before as_of (ADR 7)."""
        return self.is_open and self.review_by < as_of


class Loaded(NamedTuple):
    decisions: tuple
    problems: list


def _text(value, default=""):
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return None


def _validate(raw, index, policy_ids, file, default_line, problems, kill_ids=None):
    line = raw.line if isinstance(raw, Map) else default_line
    field = "decisions[%d]" % index

    def bad(code, sub, reason):
        problems.append(_problem(file, line, code, reason, INVALID, field=field + sub))

    if not isinstance(raw, dict):
        bad("BAD-FIELD", "", "decision must be a mapping")
        return None
    known = {"id", "date", "title", "policy", "criteria", "review_by", "status", "closes"}
    ok = True
    for key in sorted(set(raw) - known, key=str):
        bad("BAD-FIELD", "." + str(key), "unknown key %r" % (key,))
        ok = False
    did = raw.get("id")
    if not isinstance(did, str) or not did.strip():
        bad("BAD-FIELD", ".id", "id is missing or not text")
        ok = False
    for name in ("date", "review_by"):
        if name not in raw:
            bad("MISSING-FIELD", "." + name, "%s is missing" % name)
            ok = False
    date = as_date(raw.get("date")) if "date" in raw else None
    if "date" in raw and date is None:
        bad("BAD-DATE", ".date", "date %r is not YYYY-MM-DD" % (raw.get("date"),))
        ok = False
    review_by = as_date(raw.get("review_by")) if "review_by" in raw else None
    if "review_by" in raw and review_by is None:
        bad("BAD-DATE", ".review_by", "review_by %r is not YYYY-MM-DD" % (raw.get("review_by"),))
        ok = False
    if date is not None and review_by is not None and review_by < date:
        bad("BAD-DATE", ".review_by", "review_by %s is before date %s" % (review_by, date))
        ok = False
    status = raw.get("status")
    if status not in STATUSES:
        bad("BAD-STATUS", ".status", "status must be open or closed (got %r)" % (status,))
        ok = False
    title = _text(raw.get("title"))
    if title is None:
        bad("BAD-FIELD", ".title", "title must be text")
        ok = False
    criteria = _text(raw.get("criteria"))
    if criteria is None:
        bad("BAD-FIELD", ".criteria", "criteria must be text")
        ok = False
    policy = raw.get("policy")
    if policy is not None:
        if not isinstance(policy, str) or policy not in policy_ids:
            bad("UNKNOWN-POLICY", ".policy", "policy %r is not a declared policy id" % (policy,))
            ok = False
    closes = raw.get("closes")
    if closes is not None:
        if not isinstance(closes, str) or closes not in policy_ids:
            bad("UNKNOWN-POLICY", ".closes", "closes %r is not a declared policy id" % (closes,))
            ok = False
        elif kill_ids is not None and closes not in kill_ids:
            bad("BAD-CLOSES", ".closes", "closes %r names a policy that is not of type kill" % (closes,))
            ok = False
    if not ok:
        return None
    return Decision(did, date, title, policy, criteria, review_by, status, closes, line, file)


def load(path, policy_ids, kill_ids=None):
    """Read decisions.yml. Returns Loaded(decisions, problems); never raises.

    ``policy_ids``: every declared policy id. ``kill_ids``: when given, the
    ids of the kill policies; a ``closes`` naming any other policy is a
    problem (M1.2 E4) and the decision is dropped."""
    doc, problems, file = read_yaml(path)
    if doc is None:
        return Loaded((), problems)
    policy_ids = set(policy_ids or ())
    kill_ids = set(kill_ids) if kill_ids is not None else None
    try:
        if not isinstance(doc, list):
            problems.append(_problem(file, 1, "BAD-SHAPE",
                                     "decisions.yml must be a list of decisions at the top level", INVALID,
                                     field=""))
            return Loaded((), problems)
        out = []
        seen = {}
        for index, raw in enumerate(doc):
            decision = _validate(raw, index, policy_ids, file, 1, problems, kill_ids)
            if decision is None:
                continue
            if decision.id in seen:
                problems.append(_problem(file, decision.line, "DUP-ID",
                                         "decision id %r is already used at line %d" % (decision.id, seen[decision.id]),
                                         INVALID, field="decisions[%d].id" % index))
                continue
            seen[decision.id] = decision.line
            out.append(decision)
        return Loaded(tuple(out), problems)
    except Exception as exc:  # the contract is "never raises"
        problems.append(_problem(file, 0, "INTERNAL", "loader failed: %s: %s" % (type(exc).__name__, exc)))
        return Loaded((), problems)
