# Raqib — رقيب

An external watcher for AI coding agents. Raqib records what an agent does,
judges it with deterministic rules first, and lets a model raise suspicion,
never acquit.

## Install and watch
```bash
git clone https://github.com/omanras/raqib ~/raqib
pipx install ~/raqib          # or, in a venv: pip install ~/raqib
pipx ensurepath               # puts `raqib` on PATH (~/.local/bin); open a new terminal after it
raqib watch ~/my-project      # then use Claude Code in ~/my-project as usual; Ctrl-C ends the watch
```
`raqib doctor ~/my-project` says what is missing: one line per check, OK, MISSING or UNSURE; exit 1 if anything is
missing. Before the first watch it reports the hooks MISSING and exits 1, because `raqib watch` is what installs them.
You need Python 3.11 or newer and Claude Code. Raqib itself is stdlib only and is not on PyPI.

## Watch a project
`raqib watch /path/to/project` installs the hooks, keeps the trace outside the project (by default under
`~/.raqib/traces/`), takes the rules' scope from the project's `HANDOFF.md` when there is one, serves the read-only page
on 127.0.0.1 and opens it once.

High findings knock once settled, as do silence (no trace line for `RAQIB_GAP_SECONDS`, default 60 s), capture failures
and trace holes: OS notifications, one per rule per minute; lines already in the trace when watch starts are history,
shown but never knocked; `--no-notify` or a set `CI` turns the knocks off.

## Doctor
`raqib doctor [PROJECT]` says in one screen what `raqib watch` needs and is missing: one line per check, OK, MISSING or
UNSURE, and exit 1 if any line is MISSING.

## What an alarm looks like
```text
Raqib report
trace: tests/fixtures/docs/alarm-sample.log (1 records, 1 sessions)
sources: hook 1
findings: rules run on this trace (catalog raqib/rules/catalog)

ALARMS (A3, A5): 0
  (silence, a crash of the watch, a knock that did not arrive, and what could not be read, cited or kept:
  the trace's and the watch's own; every finding below also makes the RESULT an ALARM)

FINDINGS: 1
  [high] SILENCE-OPEN (SILENCE, demand) session fixture-silence-0001 seq 1
      source: hook
      session started but its trace ends at session_start seq 1 without session_end or stop
      seq 1: line 1  session_start - seq 1  2026-10-16T12:00:00.000Z  cwd="/work/example"

SUSPICION (model, raises only, A2): 0

RULES THAT DID NOT RUN: 1
  - DRIFT-FILES not-evaluated: needs context: scope

RULES (A6 fp_budget): 22
  id              class     kind      sev     fp_budget status
  SILENCE-GAP     SILENCE   demand    high    -         active
  SILENCE-OPEN    SILENCE   demand    high    -         active
  SILENCE-HALF    SILENCE   demand    high    -         active
  SILENCE-ORDER   SILENCE   demand    high    -         active
  SILENCE-EMPTY   SILENCE   demand    high    -         active
  CROSS-SOURCE    CROSS     anchor    high    0.1       active
  HEAD-UNMOVED    DRIFT     anchor    medium  0.1       active
  INDEX-UNTOUCHED DRIFT     anchor    medium  0.1       active
  AGENT-DARK-LIVE HOST      anchor    medium  0         active
  DESTRUCT-CMD    DESTRUCT  signature medium  0.25      active
  DRIFT-FILES     DRIFT     anchor    medium  0.1       active
  EDIT-NO-TEST    DRIFT     demand    medium  0.1       active
  HOST-RHYTHM     HOST      anchor    medium  0         active
  HOST-UNWATCHED  HOST      anchor    high    0         active
  LANDED-NO-GATE  DRIFT     demand    high    0.05      active
  NET-TOOL        NET       signature medium  0.25      active
  NEW-AGENT-UNKNOWN HOST      anchor    medium  0.4       active
  NEW-AGENT       HOST      anchor    high    0         active
  SCOPE-CWD-MOVED SCOPE     anchor    medium  0.1       active
  SCOPE-CWD-ROOT  SCOPE     anchor    medium  0.1       active
  SCOPE-PATH      SCOPE     signature medium  0.1       active
  SECRET-OUTPUT   SECRET    signature high    0.05      active

RESULT: ALARM (exit 1)
```

## Where it runs
On Windows: `pipx install C:\path\to\raqib` (or `py -m pip install C:\path\to\raqib`), then `raqib watch
C:\path\to\project`. Install on the side that runs the agent (Windows or WSL), not both. It needs tkinter: python.org
Python ships it; on Debian or Ubuntu `sudo apt install python3-tk`; without it, or without a display, `raqib app` exits
2 and says so (`raqib-app`: in a message box on Windows, its log in `~/.raqib/app.log`), and `raqib watch` still works
([ADR-0006](docs/specs/ADR-0006-the-window.md)). On Linux, and on Windows without Sysmon, a tree that lives between two
rounds is not seen, and the watch says so once: in its first lines where its own check at its start finds no Sysmon,
else in the line of the round the live reader's first check is made in, when that check finds none.

## Commands
| Command | Does |
|---|---|
| `raqib watch [PROJECT]` | install the hooks, tail the trace, knock, serve the page (above) |
| `raqib watch --host` | watch this host in rounds of discover |
| `raqib doctor [PROJECT]` | what `watch` needs and is missing, one line each (above) |
| `raqib report TRACE` | findings with their cited lines, rules that did not run, every rule's budget |
| `raqib ui TRACE` | the report as one static page: timeline, findings, silence bands |
| `raqib rules TRACE` | findings only, one JSON line each |
| `raqib suspect TRACE --backend ollama` | model suspicion |
| `raqib proxy` | relay another agent's model API calls and record its tool calls |
| `raqib os-sysmon` | record what Sysmon saw the agent's process tree do |

## More
[docs/GUIDE.md](docs/GUIDE.md): [Install and watch](docs/GUIDE.md#install-and-watch), [Watch a
project](docs/GUIDE.md#watch-a-project), [Doctor](docs/GUIDE.md#doctor), [Watch the host](docs/GUIDE.md#watch-the-host),
[The window](docs/GUIDE.md#the-window), [Choose the rules](docs/GUIDE.md#choose-the-rules), [How it
works](docs/GUIDE.md#how-it-works), [Manual steps](docs/GUIDE.md#manual-steps), [What it
catches](docs/GUIDE.md#what-it-catches), [What it cannot see](docs/GUIDE.md#what-it-cannot-see),
[Commands](docs/GUIDE.md#commands), [Watch another agent](docs/GUIDE.md#watch-another-agent), [Watch what the system saw
(os-sysmon)](docs/GUIDE.md#watch-what-the-system-saw-os-sysmon), [Find the agents on a host
(discover)](docs/GUIDE.md#find-the-agents-on-a-host-discover), [More](docs/GUIDE.md#more).

## Licence
Raqib is dedicated to the public domain: [CC0 1.0 Universal](LICENSE). To the
extent possible under law, its author has waived all copyright and related
rights in it. Use it, change it and pass it on, for any purpose, without
asking and without credit. It comes with no warranty; CC0 waives no patent
or trademark right.
