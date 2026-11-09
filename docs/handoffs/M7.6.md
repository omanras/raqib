# HANDOFF — M7.6  (the rules panel: overlay, `raqib rules`, the window's panel, ADR-0008)

Task: the person chooses which rules watch and their declared thresholds from the window or the
terminal; choices live in `~/.raqib/rules.yaml`, never in the package; a rule off is said everywhere.

Scope:
  raqib/overlay.py (new), raqib/rules/engine.py (load_catalog: overlay + rules.d), raqib/cli.py, raqib/watch.py
  (start lines, watch.json), raqib/host.py (state, report), raqib/ui.py (band), raqib/app.py (the panel), tests/, README.md, docs/review/

Exit criteria:
- E1 `raqib/overlay.py`: read `~/.raqib/rules.yaml` (yamlite: `rules: {ID: {status: on|off, thresholds:
     {field: value}}}`), validate against the catalog (unknown id/field, a value outside the YAML's
     bounds, a non-eq field = refused with the reason; a malformed file = one hole, nothing applied),
     apply on top (status -> engine disabled; thresholds -> the rule's eq value), write atomically;
     `origin: user` rules from `~/.raqib/rules.d/*.yaml` join only when the loader and the fixture
     runner accept them (A6).
- E2 `raqib rules` lists every rule (id, kind, class, severity, budget, status, origin, thresholds); `--set ID on|off`, `--threshold ID FIELD VALUE`, `--add FILE`, `--reset ID`; exit 2 on refusal.
- E3 Said, not silent: every watch prints the applied overlay at start, keeps it as `rules_overlay`
     in watch.json / the host state, shows "N rules off: <ids>" in the band and the window's header,
     and the final report lists each off rule with "since" and "not judged by <id> (off): M lines";
     the exit code is unchanged.
- E4 The panel: a "Rules" screen from the header - E2's table with on/off per rule, an edit per
     threshold (bounds enforced), Add (file picker -> validation shown), Reset; writes the overlay
     only; a running watch says "applies to the next watch"; nothing reaches a process or project (A4).
- E5 Tests: overlay round trip, every refusal, apply (host.py reads the changed K/W/R and streak), a high
     rule off still listed "not judged (off)" on a fixture with its finding, the CLI, the panel's state->text,
     a Tk test (skips without a display). CI: `raqib rules` + a `--set`/`--reset` pair. README: 4 lines.
Not in scope: the look pass (M7.6b), remote config, rules from the page, new rules.
Commit: `landed: M7.6 the rules panel` or `STOP: M7.6 <reason>`.
Read HANDOFF.md and do only the task it specifies.
