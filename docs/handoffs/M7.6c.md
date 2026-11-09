# HANDOFF — M7.6c  (thresholds that can be measured, ADR-0008 Amendment B)

Task: a changed threshold can be measured, so it can be allowed: the host rules' fixtures are generated
at the requested values by a generator inside the package; bounds are declared in each YAML (A6 holds).

Scope:
  raqib/rules/fixturegen.py (new; the generators moved from tests/fixtures/host/make.py), raqib/overlay.py, raqib/rules/engine.py
  (bounds), raqib/rules/catalog/ (the five host YAMLs: bounds blocks), pyproject.toml (package data), raqib/cli.py,
  raqib/app.py (the panel's threshold edit), tests/, README.md, docs/review/

Exit criteria:
- E1 `raqib/rules/fixturegen.py`: the synthetic host-round generators of make.py (cycles, dark
     streaks, arrivals, the field shape) as package code, parametric in k, w, r, streak,
     live_window; `generate(rule, thresholds) -> {positive: [...], negative: [...]}` in memory; the
     shipped fixtures are exactly its output at the declared values (a test regenerates and diffs).
- E2 `bounds:` in each host rule's YAML: per threshold field, min, max and the relations (k <= r,
     live_window >= streak); engine.py loads them; overlay.py uses them instead of its built-ins;
     a YAML without bounds for a declared eq field = that field not editable, said in `raqib rules`.
- E3 Measuring: on `--threshold` and at load, overlay.py generates the rule's fixtures at the new
     values and runs the rule on them: the positives must fire and the negatives not, and the
     budget measured on the generated negatives must stay under the declared one; a value that
     fails is refused naming the fixture; an installed raqib measures the same (no tests/ needed).
- E4 The benign desktops' arrivals stay fixed fixtures (real exports); a threshold under which they fire is refused ("would fire on a benign desktop").
- E5 Tests: generator == shipped fixtures; bounds loaded and enforced; k=5 accepted and measured
     (positives regenerated at 5 cycles fire); k=100 r=10 refused by bounds; streak=5 accepted;
     a user rule without bounds not editable; CI install job: `raqib rules --threshold HOST-RHYTHM k 4`
     then `--reset` from the venv (no checkout). README: two lines. Kinds unchanged.
Not in scope: thresholds of the trace rules (none declared), `--remove`, new rules, macOS.
Commit: `landed: M7.6c thresholds that can be measured` or `STOP: M7.6c <reason>`.
Read HANDOFF.md and do only the task it specifies.
