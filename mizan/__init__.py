"""Mizan: a deterministic, offline gate for Sigma detection rules.

A rule enters the set only with evidence: events it must match, events it
must not match, and a declared false-positive budget measured on a benign
corpus.  See docs/CONSTITUTION.md and docs/specs/ADR-0001-architecture.md.

Runtime dependencies: the Python standard library and PyYAML.  pySigma is
optional and may be imported only by mizan/export.py (A6).
"""

__version__ = "0.1.0.dev0"
