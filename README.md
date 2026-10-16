# Raqib — رقيب

An external watcher for AI coding agents. Raqib records what an agent does,
judges it with deterministic rules first, and lets a model raise suspicion,
never acquit.

- **Deterministic first.** Rules decide; a model can only add suspicion (A1, A2).
- **Silence is an alarm.** A gap, a call that never finished or a session
  that never closed is a finding, not "nothing happened" (A3).
- **The watcher never touches the watched.** Raqib reads and reports; it
  blocks nothing (A4). Capture and rules work offline; they store hashes,
  not content.

## How it works
1. **Capture.** Six Claude Code hooks append JSON lines to
   `raqib.log.jsonl`: two per tool call (pre and post) and one per session
   event. Inputs and outputs are stored as
   sha256 only, plus a small extract: the path, the URL host, the program
   name of a Bash command, and the names of secret patterns seen in the
   output.
2. **Rules.** Eleven rules turn the trace into findings, and every finding
   cites the trace lines behind it (A5). The rules are 4 silence rules and
   7 YAML rules in `raqib/rules/catalog`. Each YAML rule declares its
   false-positive budget and is measured against fixtures (A6); the silence
   rules have no budget yet.
3. **Suspicion (optional).** A local or API model reads windows of the
   trace metadata. It can raise suspicion with citations; it cannot clear
   anything.
4. **Report.** Text, JSON, or a read-only HTML page.

## Quickstart
Linux or macOS, `python3` (Raqib itself is stdlib only) and Claude Code.
Windows is not supported. The gate runs the tests with pytest; if pytest is
missing, `gate.sh` installs it with pip, which needs the network. The code is
on branch `claude/v0.1` until it is merged.
```bash
git clone --branch claude/v0.1 https://github.com/omanras/raqib ~/raqib
~/raqib/tools/gate.sh                             # ends with [gate] GREEN
~/raqib/tools/install-hooks.sh /path/to/project   # adds six hooks to its .claude/settings.json
cd /path/to/project
claude -p "Use the Bash tool to run: echo raqib-quickstart" --model haiku --max-turns 3 --allowedTools "Bash(echo:*)"
cd ~/raqib
python3 -m raqib report /path/to/project/raqib.log.jsonl --scope .           # CLEAN, exit 0
python3 -m raqib ui /path/to/project/raqib.log.jsonl --scope . -o trace.html  # open trace.html
```
These steps were run from a fresh clone (see
`docs/review/2026-10-16-M3.2-questions.md`). The raw trace of such a run is
`tests/fixtures/quickstart-d7841d1-claude-code-2.1.301.log`. A session that
runs a long call or waits for you for over a minute raises SILENCE-GAP: by
design, a quiet minute is reported, not assumed harmless.
- **Where the trace goes.** The trace path is absolute, so a `cd` by the
  agent cannot split it. `--log PATH` puts it outside the project.
- **Capture never blocks the agent.** If it cannot write, it prints one
  `RAQIB-SILENCE:` line to the hook's stderr (`claude --debug` shows it).
- **The installer** keeps your other hooks and changes nothing on a second
  run.

## What it catches
| Rule | Fires on |
|---|---|
| SILENCE-GAP / OPEN / HALF / ORDER | no capture for 60 s; a session with no end; a call with no result (or a result with no call); seq or time going back |
| SCOPE-PATH | a file tool touching a path outside the session's directory |
| SCOPE-CWD-ROOT / -MOVED | a session running from `/` or a home directory; a working directory that changes |
| NET-TOOL | WebFetch, WebSearch, a URL, or curl, wget, ssh, nc and the like |
| DESTRUCT-CMD | rm, dd, shred, mkfs and the like |
| SECRET-OUTPUT | a key, token or private key in a tool's output (by pattern name; the text is never stored) |
| DRIFT-FILES | edits to more than two files outside the task's declared scope |

## What it cannot see
Content, by design. So the rules miss these:
- a program hidden behind `sudo`, `bash -c` or `&&`;
- file access made through Bash;
- a symlink out of the project;
- a secret the agent writes rather than reads;
- an agent that rewrites the trace or switches the hooks off and then
  stays quiet.
On 50 labelled events the rules miss 9 bad events and flag 8 of 25 benign
ones (`docs/review/2026-10-16-M2.2-baseline.md`). No model has been
evaluated yet. See
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** for every known gap and its
source.

## Commands
All commands run from the Raqib checkout. TRACE is a `raqib.log.jsonl`.
| Command | Does |
|---|---|
| `python3 -m raqib report TRACE [--scope P \| --handoff HANDOFF.md] [--json]` | findings with their cited lines, rules that did not run, every rule's budget; exit 0 clean, 1 alarm, 3 incomplete, 2 usage |
| `python3 -m raqib rules TRACE -o findings.jsonl` | findings only, one JSON line each |
| `python3 -m raqib ui TRACE -o trace.html` (or `--serve`) | the report as one static page: timeline, findings, silence bands; no script; `--serve` binds 127.0.0.1 |
| `python3 -m raqib check-rules` | each rule's measured false-positive rate against its budget |
| `python3 -m raqib suspect TRACE --backend ollama -o suspicion.jsonl` | model suspicion (`--backend anthropic` needs `pip install anthropic` and ANTHROPIC_API_KEY, and sends trace metadata off the machine); then `report TRACE --suspicion suspicion.jsonl` |
| `python3 -m raqib eval [--candidate ollama:MODEL]` | false negatives and false positives of the rules and of each model on 50 labelled events |

## More
- **[docs/CONSTITUTION.md](docs/CONSTITUTION.md)**: the nine articles
  (A1-A9) every change is held to.
- **[docs/specs/ADR-0001-architecture.md](docs/specs/ADR-0001-architecture.md)**:
  the pipeline, the trace schema and its amendments.
- **[docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md)** and `docs/review/`
  hold the plan, every review packet, and the open questions.
- **How this repo is built.** One micro-task per session (`HANDOFF.md`), a
  read-only reviewer, and a gate (`tools/gate.sh`) that every commit must
  pass.

Status: v0.1 candidate on `claude/v0.1`: capture, rules, report, suspicion
layer, evaluation, web view and docs. The last exit criterion of the plan
(M3.3) is still open: one person outside the project runs this quickstart
and files one issue.
