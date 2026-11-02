# HANDOFF — M6.3  (phase 6: packaging, `raqib doctor`, README around watch)

Task: `pip install .` / `pipx install .` puts `raqib` on PATH; `raqib doctor`
says in one screen what is missing; README starts from `raqib watch`.

Scope:
  pyproject.toml (new), raqib/__main__.py, raqib/cli.py, raqib/doctor.py (new),
  raqib/install.py (new), raqib/watch.py (import only), tools/, .github/workflows/gate.yml,
  tests/, README.md, docs/review/

Exit criteria:
- E1 `pyproject.toml`: stdlib-only runtime, pytest the only test extra,
     entry point `raqib = raqib.cli:main`, package data = catalog YAMLs and
     endpoints.yaml. The installer logic moves to `raqib/install.py`
     (tools/install_hooks.py becomes a thin wrapper; watch imports the
     package, never a checkout path - W14). `pip install .` in a clean venv
     then `raqib --help` and `raqib watch --help` work on Linux and Windows
     (CI job added).
- E2 `raqib doctor [PROJECT]`: Python, `claude` on PATH + version, hook
     settings (installed / missing / foreign), notifier backend, Sysmon
     (Windows), trace path writable; OK / MISSING per line; exit 1 if any
     MISSING. Read-only.
- E3 README rewritten: first screen = install + `raqib watch`; the rest
     below; old quickstart kept as "manual steps"; stale `--branch
     claude/v0.1` line removed.
- E4 gate.py checks unchanged; gate.yml adds the install job. Gate green ubuntu + windows.

Not in scope: PyPI publishing, signing, installers (.msi/.deb), tray icon.
Commit: `landed: M6.3 packaging + doctor` or `STOP: M6.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
