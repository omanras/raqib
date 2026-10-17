# Mizan

A gate for detection rules. A Sigma rule enters the set only with evidence:
events it must match, events it must not match, and a declared
false-positive budget measured on a benign corpus. Deterministic, offline,
stdlib + PyYAML.

Status: v0.1 under construction on branch `mizan` of this repository
(branch `main` is Raqib, a different project). See `docs/DEVELOPMENT_PLAN.md`.

Export (optional): `python3 -m mizan export RULE.yml --target splunk|elastic`
converts a rule to a target query through pySigma. It needs
`pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch`;
without them the command exits 3 and prints that line. Only `mizan/export.py`
imports pySigma; `check`, `test`, `match` and `corpus` never do.
