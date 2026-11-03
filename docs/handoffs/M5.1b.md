# HANDOFF — M5.1b  (phase 5: Windows paths in the rules)
Task: the four path rules judge Windows paths via one normaliser in the
engine; POSIX outcomes unchanged (rulings 2026-11-02-M5.1 Q-2..Q-6 and
2026-11-03-M5.1b C-1..C-6, binding).
Scope:
  raqib/rules/engine.py, raqib/rules/context.py, raqib/cli.py, tests/, docs/review/, README.md (line 17),
  docs/THREAT_MODEL.md (section 7), docs/specs/ADR-0001-architecture.md (builder note only),
  raqib/rules/catalog/{SCOPE-CWD-ROOT,SCOPE-CWD-MOVED,SCOPE-PATH,DRIFT-FILES}.yaml, .gitattributes

Exit criteria:
- E1 `norm_path()` in engine.py: one function used by `_place`, `_under` and
     the context root check. Drive-letter (`X:\`, `X:/`) and UNC paths:
     separators to `/`, case folded. POSIX paths: unchanged, case-sensitive.
     `/mnt/c/...` and `C:\...` are NOT equal (Q-6); say so in a docstring.
- E2 Context `root` accepts a Windows absolute path; `bad-context` only if
     absolute on neither system.
- E3 SCOPE-CWD-ROOT: second regex branch for the Windows roots of ruling
     C-1 (drive roots, Users, Windows, Temp, Program Files, ProgramData, UNC
     share root). A Windows cwd matching no branch is a judged NEGATIVE
     (C-1); description names the WSL, macOS and C-1 holes; C-2 forms.
- E4 Fixtures, listed in each YAML, for all four rules: a `C:\` positive and
     negative each, plus a mixed-case `c:/PROJ` case for SCOPE-PATH and
     SCOPE-CWD-MOVED. POSIX fixture outcomes unchanged (`check-rules` identical).
- E5 `.gitattributes`: `* text eol=lf`. Gate green on ubuntu + windows.
- E6 The two Windows xfail markers from M5.1 (test_report, test_ui) removed
     and both tests pass on Windows.

Not in scope: capture, installer, new rules, `source` field.
Commit: `landed: M5.1b windows paths` or `STOP: M5.1b <reason>`.
Read HANDOFF.md and do only the task it specifies.
