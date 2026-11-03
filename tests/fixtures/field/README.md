# Field traces (never benign)

Traces from field runs that expect findings. They live here, outside the
benign corpus (tests/fixtures/*.log, top level only), by ADR-0002
Amendment E, E-1: an adversarial trace is never benign.

- 2026-11-02.log: the commander's first adversarial run (field notes
  docs/review/2026-11-02-field-note-first-adversarial-run.md and
  -empty-session.md); recreated shape, synthetic hashes: every sha256 is
  sha256("synthetic-<line>") of a line of this file (a call's input hash is
  that of its pre line, so pre and post agree as capture writes them), every
  tool line has a synthetic tool_use_id, and no path is a real one.
  Expected: SILENCE-EMPTY s1 and s2, SILENCE-GAP s3, SCOPE-PATH s5, NET-TOOL
  s6; s7 (python3 -c 'import urllib.request') is the recorded NET-TOOL miss.
