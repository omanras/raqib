"""Results, their text and JSON rendering, and exit codes (ADR-0001 section 8-9).

A ``Result`` is the verdict on one rule.  Every result names the rule id
and cites the file and line of every fixture or corpus event it rests on
(A5).  Statuses: ``pass``, ``fail``, ``invalid``, ``unknown``,
``over_budget``, ``no_corpus``; only ``pass`` is green.

Exit codes: 0 green, 1 red, 2 usage error, 3 could not complete (a path
unreadable, a corpus file unparseable) -- 3 is also red.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

EXIT_GREEN = 0
EXIT_RED = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3

STATUSES = ("pass", "fail", "invalid", "unknown", "over_budget", "no_corpus")
GREEN_STATUSES = ("pass",)

#: Red statuses sort first in a report, in this order.
_STATUS_ORDER = {"invalid": 0, "unknown": 1, "fail": 2, "over_budget": 3, "no_corpus": 4, "pass": 5}

JSON_VERSION = 1


@dataclass(frozen=True)
class Citation:
    """Where a verdict rests: a file, a line (None for a whole-file finding)
    and why."""

    file: str
    line: Optional[int]
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {"file": self.file, "line": self.line, "reason": self.reason}

    def text(self) -> str:
        where = self.file if self.line is None else "%s:%d" % (self.file, self.line)
        return "%s %s" % (where, self.reason) if self.reason else where


@dataclass
class Result:
    """The verdict on one rule."""

    status: str
    path: str
    id: Optional[str] = None
    title: Optional[str] = None
    citations: List[Citation] = field(default_factory=list)
    problems: List[Dict[str, str]] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def green(self) -> bool:
        return self.status in GREEN_STATUSES

    def cite(self, file: str, line: Optional[int], reason: str) -> None:
        self.citations.append(Citation(file, line, reason))

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "status": self.status,
            "id": self.id,
            "title": self.title,
            "path": self.path,
            "citations": [c.as_dict() for c in self.citations],
        }
        if self.problems:
            out["problems"] = list(self.problems)
        out.update(self.details)
        return out

    def text(self) -> str:
        head = "%s %s %s" % (self.status, self.id or "-", self.title or self.path)
        lines = [head]
        for problem in self.problems:
            lines.append("  %s %s: %s" % (self.path, problem.get("field", "?"), problem.get("reason", "")))
        for citation in self.citations:
            lines.append("  " + citation.text())
        for note in self.details.get("notes", ()):
            lines.append("  " + str(note))
        return "\n".join(lines)


def sort_results(results: List[Result]) -> List[Result]:
    """Red first (invalid, unknown, fail, over_budget, no_corpus), then
    green; stable within a status."""
    return sorted(results, key=lambda r: _STATUS_ORDER.get(r.status, 99))


def is_green(results: List[Result]) -> bool:
    return bool(results) and all(r.green for r in results)


def render_text(results: List[Result]) -> str:
    return "\n".join(r.text() for r in results) + ("\n" if results else "")


def render_json(results: List[Result], **extra: Any) -> str:
    document: Dict[str, Any] = {"version": JSON_VERSION}
    document.update(extra)
    document["rules"] = [r.as_dict() for r in results]
    document["green"] = is_green(results)
    return json.dumps(document, indent=2, sort_keys=False, default=str) + "\n"


def exit_code(results: List[Result]) -> int:
    return EXIT_GREEN if is_green(results) else EXIT_RED


def rule_identity(rule_or_problems) -> Dict[str, Optional[str]]:
    """id and title for a Rule or, best effort, for a Problems list."""
    rule_id = getattr(rule_or_problems, "id", None)
    title = getattr(rule_or_problems, "title", None)
    if isinstance(rule_id, str) and isinstance(title, str):
        return {"id": rule_id, "title": title}
    return {"id": None, "title": None}
