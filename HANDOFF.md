# HANDOFF — M2.1  (phase 2: export via pySigma)

Task: implement `mizan/export.py` and the `export` command per
docs/specs/ADR-0001 §2, §9: a Sigma rule to a target query through pySigma,
as an optional dependency confined to this module.

Scope:
  mizan/export.py
  mizan/cli.py
  tests/test_export.py
  docs/review/
  README.md

Exit criteria:
- E1 `python3 -m mizan export RULE.yml --target splunk` prints the query;
     `--json` prints {"target", "query", "backend_version"}.
- E2 Targets: at least splunk and elastic (pySigma backends
     pysigma-backend-splunk, pysigma-backend-elasticsearch), imported
     lazily; a missing package yields exit 3 and one line naming the pip
     install command, never a traceback.
- E3 `import sigma` (pySigma) appears only in mizan/export.py (the gate
     already checks it); no network at export time.
- E4 Tests: a fake backend injected (no pySigma needed) covers success and
     the missing-package path; one test that runs the real backend is
     skipped when pySigma is absent. README gains the export line.
- E5 Gate green.

Not in scope: new targets beyond the two, rule rewriting, the engine.
Commit: `landed: M2.1 export via pySigma` or `STOP: M2.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
