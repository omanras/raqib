# HANDOFF — M0.1  (phase 0: loader)

Task: implement `mizan/loader.py` (+ package files `mizan/__init__.py`,
`mizan/__main__.py` stub) that reads one Sigma rule file and validates the
shape of docs/specs/ADR-0001 §3, returning a Rule or named problems.

Scope:
  mizan/
  tests/test_loader.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 `loader.load(path)` returns `Rule` with attributes title, id, logsource
     (dict), detection (dict), condition (str), level, fp_budget (float),
     corpus (list or None), raw (the full mapping), path.
- E2 On any problem it returns `Problems` (list of {field, reason}) instead,
     never raises: not a file, not YAML, not a mapping, several YAML docs,
     missing/invalid title, id (UUID), logsource, detection, condition,
     level (outside the five), x-mizan.fp_budget (missing or negative).
- E3 Unknown top-level Sigma fields are kept in raw and are not problems.
- E4 Fixtures in tests/fixtures/rules/: one valid rule and one file per
     problem class; a test per fixture; gate green.

Not in scope: matching, fixtures discovery, CLI commands.
Commit: `landed: M0.1 loader` or `STOP: M0.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
