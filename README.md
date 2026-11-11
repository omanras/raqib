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
`raqib report TRACE` prints this; `raqib watch PROJECT` prints it for its own trace when it ends, after its summary.
```text
Raqib report
trace: tests/fixtures/docs/alarm-sample.log (5 records, 1 sessions)
sources: hook 5
findings: rules run on this trace (catalog raqib/rules/catalog)

ALARMS (A3, A5): 0
  (silence, a crash of the watch, a knock that did not arrive, and what could not be read, cited or kept:
  the trace's and the watch's own; every finding below also makes the RESULT an ALARM)

FINDINGS: 2
  [medium] DESTRUCT-CMD (DESTRUCT, signature) session demo-1 seq 2
      source: hook
      Bash runs rm at seq 2 (programs ["curl", "bash", "rm"])
      seq 2: line 2  pre Bash seq 2  2026-11-11T09:00:02.000Z  input_meta={"command_head": "curl", "command_programs": ["curl", "bash", "rm"]}  cwd="/work/demo"
      seq 2: line 3  post Bash seq 2  2026-11-11T09:00:04.000Z  ok=true  input_meta={"command_head": "curl", "command_programs": ["curl", "bash", "rm"]}  output_meta={"scan": "full", "secret_kinds": []}  cwd="/work/demo"
  [medium] NET-TOOL (NET, signature) session demo-1 seq 2
      source: hook
      Bash may reach the network at seq 2 (host -, program curl, programs ["curl", "bash", "rm"])
      seq 2: line 2  pre Bash seq 2  2026-11-11T09:00:02.000Z  input_meta={"command_head": "curl", "command_programs": ["curl", "bash", "rm"]}  cwd="/work/demo"
      seq 2: line 3  post Bash seq 2  2026-11-11T09:00:04.000Z  ok=true  input_meta={"command_head": "curl", "command_programs": ["curl", "bash", "rm"]}  output_meta={"scan": "full", "secret_kinds": []}  cwd="/work/demo"

SUSPICION (model, raises only, A2): 0

RULES THAT DID NOT RUN: 1
  - DRIFT-FILES not-evaluated: needs context: scope

RULES (A6 fp_budget): 22
  ... (22 rows: every rule, its kind, severity and budget)

RESULT: ALARM (exit 1)
```

## Where it runs
Raqib runs on Linux and Windows, on Python 3.11 or newer and its standard library only; the tests run on both. On
Windows: `pipx install C:\path\to\raqib` (or `py -m pip install C:\path\to\raqib`), then `raqib watch
C:\path\to\project`. Install on the side that runs the agent (Windows or WSL), not both. `raqib watch PROJECT` needs
Claude Code, whose hooks it installs. `raqib watch --host` needs no agent named: it finds the agents by what they do,
and on Windows it also reads Sysmon where it is installed ([what it misses without it](docs/GUIDE.md#watch-the-host)).
The window, `raqib app`, needs tkinter (`python3-tk`); `raqib watch` does not. On macOS the notifications and the page
opener are written for it, but the host watch has no live reader and no CI job runs there.

## Commands
| Command | Does |
|---|---|
| `raqib app [PROJECT]` | open Raqib as a desktop window: the host first, Watch this host, or a project |
| `raqib watch [PROJECT]` | install the hooks, tail the trace, knock, serve the page (above) |
| `raqib watch --host` | watch this host in rounds of discover |
| `raqib doctor [PROJECT]` | what `watch` needs and is missing, one line each (above) |
| `raqib report TRACE` | findings with their cited lines, rules that did not run, every rule's budget |
| `raqib rules [--set ID on\|off]` | list every rule; turn a rule on or off; `--add FILE`, `--remove NAME`: your own |
| `raqib discover` | find AI agents on a host by what they do |
| `raqib --version` | print raqib <version> and exit 0 |
| the rest: `ui`, `suspect`, `proxy`, `os-sysmon`, `check-rules`, `eval` | [in the guide](docs/GUIDE.md#commands) |

TRACE is a trace file, a `raqib.log.jsonl` of JSON lines; `raqib watch` keeps it under `~/.raqib/traces/` by default.

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
