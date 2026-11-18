# HANDOFF — M12.1p  (ADR-0013 Amendment C, AC-1: the host watch without its page)

Task: `raqib watch --host --no-page`: the host watch opens no listener and serves no page. Nothing else of the watch changes. (The service's unit takes the option in the next task, not in this one.)

Scope:
  raqib/host.py (only: `start`, `command`, `loop`, `Running`, the end of the run where the server is closed, and where the watcher's `port` and `url` are written into its state, registry row and page data), raqib/cli.py (only: the option `--no-page` of `watch`, its usage line and help, and `watch`'s `--refresh` default becoming None: AC-13), tests/test_host_nopage.py (new), docs/GUIDE.md (only: the option, where `watch --host`'s options are told), tests/test_readme_top.py (only the guide's new or changed lines in its registry), docs/review/2026-11-18-M12.1p-questions.md

Exit criteria:
- E1 `host.start(..., no_page=True)`: `watch._serve` is not called, no socket is bound or listened on, no thread "raqib-host-page" is started; `watcher.url` is None and `watcher.port` is `{"requested": None, "used": None, "warning": None}`; the start says one line: `raqib watch --host: no page is served (--no-page): no port is opened`. A test proves it by replacing `watch._serve` and `ui.make_server` with functions that fail the test, and by binding the default port itself after the start.
- E2 `host.loop` with no page: the lines "page ..." and "page not opened ..." are not written; nothing is opened in a browser; a port warning is not looked for. The end of the run closes no server and raises nothing. With a page (the default) every line and every act is as before: a test compares the start's and the loop's lines of a default run before and after this change by holding them word for word.
- E3 Wherever this watch writes its `url` and `port` (its state file, its registry row), `url` is null and `port` holds nulls, and every reader of them inside raqib that this watch itself calls takes a null without raising (the watch's own page data builder is not called for a page, but `watcher.page()` called by a test still returns text).
- E4 cli: `raqib watch --host --no-page` parses and reaches `host.command(..., no_page=True)`; `--no-page` without `--host` is a usage error (exit 2) that says `--no-page is --host's`; `--no-page` with `--port` or `--refresh` (any value, the default's 5 too: AC-13) is a usage error that says why; without `--no-page` a page still reloads every 5 s by default (a test). `raqib app` is not given the option. The usage text and the help name it.
- E5 docs/GUIDE.md: one sentence where `watch --host`'s options are told: what `--no-page` does and that the report and the events file are unchanged. A test holds it.
- E6 Gate green in the foreground; ASCII outside docs; tests/test_rhythm.py's guards and tests/test_own_tree.py pass unchanged; no new import in raqib/host.py.
Not in scope: raqib/service.py, the unit's text, docs/specs/SERVICE.md, docs/THREAT_MODEL.md, raqib/watch.py, raqib/ui.py, raqib/app.py, README.md, .github/workflows/, tools/rig/.
If an exit criterion needs a file outside Scope (a guard that holds the usage text, a registry, another test): STOP and say which file and which line. Do not change a guard test to pass.
Commit: `landed: M12.1p the host watch without its page` or `STOP: M12.1p <reason>`.
Read HANDOFF.md and do only the task it specifies.
