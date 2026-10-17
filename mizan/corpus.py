"""Benign corpora and the false-positive budget (ADR-0001 section 7).

A corpus file is ``corpus/<name>.jsonl`` whose first line declares its
logsource::

    {"_mizan": {"logsource": {"product": "windows", "category": "process_creation"}}}

and whose other lines are benign events.  A rule is measured on the files
named in its ``x-mizan.corpus`` or, when that is absent, on every file whose
declared logsource agrees with the rule's on each of ``product``,
``category`` and ``service`` the rule sets.

    fp_per_10k = matches * 10000 / events

``measure(rule, corpus)`` returns a ``report.Result``:

- ``invalid``      the rule did not load;
- ``unknown``      the rule is unsupported, a selected corpus file has no
                   valid header, is empty or unreadable, or any of its
                   lines could not be judged (A4); each cited;
- ``no_corpus``    no file is compatible, or a file named in
                   ``x-mizan.corpus`` does not exist;
- ``over_budget``  fp_per_10k > fp_budget;
- ``pass``         within budget.

Every corpus match is cited ``<file>:<line>`` (A5).  A corpus file whose
header cannot be read affects every rule that selects by logsource,
because Mizan cannot tell whether the file belongs to the rule.
"""

import os
from typing import Any, Dict, List, Optional, Tuple

from mizan import condition
from mizan.fixtures import iter_jsonl
from mizan.loader import LOGSOURCE_KEYS, Problems, Rule
from mizan.matcher import Unknown
from mizan.report import Result

HEADER_KEY = "_mizan"
PER = 10000


class CorpusFile:
    """One corpus file, read once: header, events, and every problem."""

    __slots__ = ("path", "name", "logsource", "problem", "events", "bad_lines", "blank")

    def __init__(self, path: str):
        self.path = path
        self.name = os.path.basename(path)
        self.logsource: Optional[Dict[str, str]] = None
        self.problem: Optional[str] = None
        self.events: List[Tuple[int, dict]] = []
        self.bad_lines: List[Tuple[int, str]] = []
        self.blank = 0
        self._read()

    def _read(self) -> None:
        lines = iter_jsonl(self.path)
        header = None
        for line in lines:
            if line.number is None:
                self.problem = line.error
                return
            if line.error is not None:
                self.problem = "line %d: %s (the first line must declare the logsource)" % (line.number, line.error)
                return
            if line.event is None:
                self.blank += 1
                continue
            header = line
            break
        if header is None:
            self.problem = "empty: no header line"
            return
        logsource, problem = _parse_header(header.event)
        if problem is not None:
            self.problem = "line %d: %s" % (header.number, problem)
            return
        self.logsource = logsource
        for line in lines:
            if line.number is None:
                self.problem = line.error
                return
            if line.error is not None:
                self.bad_lines.append((line.number, line.error))
            elif line.event is None:
                self.blank += 1
            else:
                self.events.append((line.number, line.event))
        if not self.events and not self.bad_lines:
            self.problem = "empty: no event after the header"

    @property
    def usable(self) -> bool:
        return self.problem is None and self.logsource is not None

    def as_dict(self) -> Dict[str, Any]:
        return {"file": self.path, "logsource": self.logsource, "events": len(self.events),
                "blank_lines": self.blank, "bad_lines": [n for n, _ in self.bad_lines],
                "problem": self.problem}


def _parse_header(event: Any) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    if not isinstance(event, dict) or set(event) != {HEADER_KEY}:
        return None, "header must be exactly {\"%s\": {\"logsource\": {...}}}" % HEADER_KEY
    meta = event[HEADER_KEY]
    if not isinstance(meta, dict) or "logsource" not in meta:
        return None, "header %s must be a mapping with a logsource" % HEADER_KEY
    logsource = meta["logsource"]
    if not isinstance(logsource, dict) or not logsource:
        return None, "header logsource must be a non-empty mapping"
    if not any(key in logsource for key in LOGSOURCE_KEYS):
        return None, "header logsource needs at least one of product, category, service"
    for key, value in logsource.items():
        if not isinstance(key, str) or not isinstance(value, str) or not value.strip():
            return None, "header logsource values must be non-empty strings (%r)" % (key,)
    return dict(logsource), None


class Corpus:
    """Every ``*.jsonl`` file directly under a corpus directory."""

    def __init__(self, directory: str):
        self.directory = directory
        self.files: Dict[str, CorpusFile] = {}
        self.problem: Optional[str] = None
        if not os.path.isdir(directory):
            self.problem = "missing" if not os.path.exists(directory) else "not a directory"
            return
        try:
            names = sorted(n for n in os.listdir(directory)
                           if n.endswith(".jsonl") and os.path.isfile(os.path.join(directory, n)))
        except OSError as exc:
            self.problem = "cannot be read: %s" % (exc.strerror or exc)
            return
        for name in names:
            self.files[name] = CorpusFile(os.path.join(directory, name))

    @property
    def broken(self) -> List[CorpusFile]:
        """Files whose header could not be read (they belong to no one)."""
        return [f for f in self.files.values() if not f.usable]

    @property
    def complete(self) -> bool:
        """True when every file was parsed without a problem (exit code 3 otherwise)."""
        return self.problem is None and all(
            f.usable and not f.bad_lines for f in self.files.values())


def compatible(rule_logsource: Dict[str, Any], corpus_logsource: Dict[str, Any]) -> bool:
    """Every identifying key the rule sets is equal in the corpus declaration."""
    for key in LOGSOURCE_KEYS:
        if key in rule_logsource and rule_logsource[key] != corpus_logsource.get(key):
            return False
    return True


def _safe_name(name: str) -> bool:
    return bool(name) and os.path.basename(name) == name and name not in (".", "..")


def select(rule: Rule, corpus: Corpus):
    """(files, selected_by, citations) for a rule.

    ``files`` are the CorpusFile objects to measure on; ``citations`` are
    (file, line, reason) for files that are missing or broken.
    """
    citations: List[Tuple[str, Optional[int], str]] = []
    files: List[CorpusFile] = []
    if rule.corpus is not None:
        for name in rule.corpus:
            if not _safe_name(name):
                citations.append((os.path.join(corpus.directory, name), None,
                                  "x-mizan.corpus entries must be plain file names"))
                continue
            corpus_file = corpus.files.get(name)
            if corpus_file is None:
                citations.append((os.path.join(corpus.directory, name), None,
                                  "missing (named in x-mizan.corpus)"))
                continue
            files.append(corpus_file)
        return files, "x-mizan.corpus", citations
    for corpus_file in corpus.broken:
        citations.append((corpus_file.path, None, corpus_file.problem or "unreadable header"))
    for corpus_file in corpus.files.values():
        if corpus_file.usable and compatible(rule.logsource, corpus_file.logsource):
            files.append(corpus_file)
    return files, "logsource", citations


def _number(value: float) -> str:
    text = "%.4f" % value
    text = text.rstrip("0").rstrip(".")
    return text if text not in ("", "-0") else "0"


def summary_line(result: Result) -> str:
    """``fp/10k=<n> budget=<b> events=<e>`` for a measured result."""
    details = result.details.get("corpus", {})
    fp = details.get("fp_per_10k")
    budget = details.get("budget")
    return "fp/10k=%s budget=%s events=%d" % (
        "-" if fp is None else _number(fp),
        "-" if budget is None else _number(budget),
        details.get("events", 0) or 0)


def measure(rule, corpus: Corpus, compiled=None) -> Result:
    """The budget verdict of one rule on a corpus; never raises."""
    if isinstance(rule, Problems):
        return Result("invalid", rule.path, problems=rule.as_list())
    if not isinstance(rule, Rule):
        return Result("invalid", str(getattr(rule, "path", rule)),
                      problems=[{"field": "rule", "reason": "not a loaded rule"}])
    result = Result("pass", rule.path, id=rule.id, title=rule.title)
    details: Dict[str, Any] = {"budget": rule.fp_budget, "events": 0, "matches": 0,
                               "fp_per_10k": None, "files": [], "selected_by": None}
    result.details["corpus"] = details
    if compiled is None:
        compiled = condition.compile_rule(rule)
    rule_unknown = isinstance(compiled, Unknown)
    if rule_unknown:
        result.cite(rule.path, None, "unknown: %s" % compiled.reason)
        compiled = None
    if corpus.problem is not None:
        result.cite(corpus.directory, None, "corpus directory %s" % corpus.problem)
    files, selected_by, citations = select(rule, corpus)
    details["selected_by"] = selected_by
    any_unknown = rule_unknown
    missing_named = False
    for path, line, reason in citations:
        result.cite(path, line, reason)
        if "missing (named" in reason or "plain file names" in reason:
            missing_named = True
        else:
            any_unknown = True
    total_events = 0
    total_matches = 0
    for corpus_file in files:
        entry = {"file": corpus_file.path, "events": len(corpus_file.events), "matches": []}
        details["files"].append(entry)
        if not corpus_file.usable:
            result.cite(corpus_file.path, None, corpus_file.problem or "unreadable")
            any_unknown = True
            continue
        for number, reason in corpus_file.bad_lines:
            result.cite(corpus_file.path, number, "unknown: %s" % reason)
            any_unknown = True
        total_events += len(corpus_file.events)
        if compiled is None:
            continue
        for number, event in corpus_file.events:
            verdict = compiled.evaluate(event)
            if isinstance(verdict, Unknown):
                result.cite(corpus_file.path, number, "unknown: %s" % verdict.reason)
                any_unknown = True
            elif verdict is True:
                entry["matches"].append(number)
                total_matches += 1
                result.cite(corpus_file.path, number, "match")
    details["events"] = total_events
    details["matches"] = total_matches
    if total_events:
        details["fp_per_10k"] = total_matches * PER / float(total_events)
    if any_unknown:
        result.status = "unknown"
    elif not files or missing_named or total_events == 0:
        result.status = "no_corpus"
        if not files or total_events == 0:
            result.cite(rule.path, None, "no compatible corpus for logsource %s" % _logsource_text(rule.logsource))
    elif details["fp_per_10k"] > rule.fp_budget:
        result.status = "over_budget"
    else:
        result.status = "pass"
    result.details["notes"] = [summary_line(result) + " corpus=" + (
        ",".join(os.path.basename(f.path) for f in files) if files else "-")]
    return result


def _logsource_text(logsource: Dict[str, Any]) -> str:
    return "{" + ", ".join("%s=%s" % (k, logsource[k]) for k in LOGSOURCE_KEYS if k in logsource) + "}"
