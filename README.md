# Raqib — رقيب

An external watcher for AI coding agents. Raqib records what an agent does,
judges it with deterministic rules first, and lets a model raise suspicion,
never acquit.

## Install and watch
```bash
git clone https://github.com/omanras/raqib ~/raqib
pipx install ~/raqib          # or, in a venv: pip install ~/raqib; puts `raqib` on PATH
raqib doctor ~/my-project     # one line per check, OK, MISSING or UNSURE; exit 1 if anything is missing
raqib watch ~/my-project      # then use Claude Code in ~/my-project as usual; Ctrl-C ends the watch
```
You need Python 3.11 or newer and Claude Code. Raqib itself is stdlib only and
is not on PyPI. On Windows: `pipx install C:\path\to\raqib` (or
`py -m pip install C:\path\to\raqib`), then `raqib watch C:\path\to\project`.
On Windows the path rules judge drive (`C:\`) and UNC paths in any case, with `\` or `/`; `/mnt/c/...` (WSL) and `C:\...` are different paths, and `--root /x` means `\x` on the current drive.
Install on the side that runs the agent (Windows or WSL), not both.

## Watch a project
`raqib watch /path/to/project` installs the hooks, keeps the trace outside the project (by default under `~/.raqib/traces/`), takes the rules' scope from the project's `HANDOFF.md` when there is one, serves the read-only page on 127.0.0.1 and opens it once.
High findings knock once settled, as do silence (no trace line for `RAQIB_GAP_SECONDS`, default 60 s), capture failures and trace holes: OS notifications, one per rule per minute; lines already in the trace when watch starts are history, shown but never knocked; `--no-notify` or a set `CI` turns the knocks off.
Ctrl-C, or a crash, prints the final report; `<trace>.watch.json` keeps the findings, the silence windows, the holes and a heartbeat ([ADR-0005](docs/specs/ADR-0005-one-command-watch.md)).

## Doctor
`raqib doctor [PROJECT]` says in one screen what `raqib watch` needs and is
missing: one line per check, OK, MISSING or UNSURE, and exit 1 if any line
is MISSING. It checks Python (and on Linux and macOS `python3` on PATH, which
the hooks run), `claude` on PATH and its version, the project's hook
settings (installed; foreign: a Raqib entry of another checkout or install;
or missing), the notifier, Sysmon on Windows, and whether the trace can be
written. It is read-only; the only program it runs is `claude --version`,
by absolute path (in an empty temporary directory, the only thing it
creates).
If the installed package moves on Linux or macOS, the hook command's own
`|| echo` prints one `RAQIB-SILENCE:` line, because `capture.py` is gone.
If the venv moves on Windows, the hook names its `python.exe` by path, so
Claude Code shows a hook error and no `RAQIB-SILENCE:` line is printed.
Either way doctor shows the hooks as foreign, and `raqib watch` replaces them.
A check that cannot be made on this host is UNSURE, counted apart and never a failure: today the Windows trace line, which says "not checked" because os.access cannot tell there and doctor writes nothing to find out.

## How it works
- **Deterministic first.** Rules decide; a model can only add suspicion (A1, A2).
- **Silence is an alarm.** A gap, a call that never finished or a session
  that never closed is a finding, not "nothing happened" (A3).
- **The watcher never touches the watched.** Raqib reads and reports; it
  blocks nothing (A4). Capture and rules work offline; they store hashes,
  not content.

1. **Capture.** Six Claude Code hooks append JSON lines to
   `raqib.log.jsonl`: two per tool call (pre and post) and one per session
   event. Inputs and outputs are stored as
   sha256 only, plus a small extract: the path, the URL host, the program
   names of a Bash command (never its arguments), and the names of secret
   patterns seen in the output.
2. **Rules.** Twelve rules turn the trace into findings, and every finding
   cites the trace lines behind it (A5). The rules are 5 silence rules and
   7 YAML rules in `raqib/rules/catalog`. Each YAML rule declares its
   false-positive budget and is measured against fixtures (A6); the silence
   rules have no budget yet.
3. **Suspicion (optional).** A local or API model reads windows of the
   trace metadata. It can raise suspicion with citations; it cannot clear
   anything.
4. **Report.** Text, JSON, or a read-only HTML page.

## Manual steps
The steps before `raqib watch` existed, from a checkout, one command at a time.
Linux, macOS; Windows: capture and installer (path rules since M5.1b). You need
`python3` (Raqib itself is stdlib only) and Claude Code. On Windows run
`python -I tools\install_hooks.py C:\path\to\project` and `python -I tools\gate.py`.
Install from the side that runs the agent (Windows or WSL), not both.
On Windows a missing `python.exe` is a hook error shown by Claude Code: no `RAQIB-SILENCE:` line, and not a block.
The gate runs the tests with pytest; if pytest is
missing, `gate.sh` installs it with pip, which needs the network.
```bash
git clone https://github.com/omanras/raqib ~/raqib
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
| SILENCE-EMPTY | a session that started and ended with no tool call and no turn, or ended with no start and no tool call (one with tool calls and no start is not judged yet: SILENCE-NOSTART, M4.3) |
| SCOPE-PATH | a file tool touching a path outside the session's directory |
| SCOPE-CWD-ROOT / -MOVED | a session running from `/` or a home directory; a working directory that changes |
| NET-TOOL | WebFetch, WebSearch, a URL, or curl, wget, ssh, nc and the like anywhere in a Bash command |
| DESTRUCT-CMD | rm, dd, shred, mkfs and the like anywhere in a Bash command |
| SECRET-OUTPUT | a key, token or private key in a tool's output (by pattern name; the text is never stored) |
| DRIFT-FILES | edits to more than two files outside the task's declared scope |

## What it cannot see
Content, by design. So the rules miss these:
- a program hidden behind `sudo`, `eval`, `python -c` or a second `bash -c`
  (pipes, `&&`, `;`, `$(...)` and one `bash -c` are read);
- code given to a shell on stdin, by a here-document or a here-string, or in
  a script file: only the shell or the script is recorded;
- file access made through Bash;
- a symlink out of the project;
- a secret the agent writes rather than reads;
- an agent that rewrites the trace or switches the hooks off and then
  stays quiet.
On 50 labelled events the rules miss 9 bad events and flag 8 of 25 benign
ones (`docs/review/2026-10-16-M2.2-baseline.md`). On the rule fixtures
`raqib check-rules` finds SCOPE-PATH firing on 0 of 10 benign files and
NET-TOOL on 1 of 10; a trace that expects findings is never benign
(`tests/fixtures/field/`). No model has been
evaluated yet. See
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** for every known gap and its
source.

## Commands
Once installed, `raqib COMMAND`; from a checkout without installing,
`python3 -m raqib COMMAND`. TRACE is a `raqib.log.jsonl`.
| Command | Does |
|---|---|
| `raqib watch [PROJECT]` | install the hooks, tail the trace, knock, serve the page (above) |
| `raqib doctor [PROJECT]` | what `watch` needs and is missing, one line each (above) |
| `raqib report TRACE [--scope P \| --handoff HANDOFF.md] [--json]` | findings with their cited lines, rules that did not run, every rule's budget; exit 0 clean, 1 alarm, 3 incomplete, 2 usage |
| `raqib rules TRACE -o findings.jsonl` | findings only, one JSON line each |
| `raqib ui TRACE -o trace.html` (or `--serve`) | the report as one static page: timeline, findings, silence bands; no script; `--serve` binds 127.0.0.1 |
| `raqib check-rules [--fixtures-root CHECKOUT]` | each rule's measured false-positive rate against its budget, on the fixtures of a checkout (an installed raqib has none: pass `--fixtures-root`) |
| `raqib suspect TRACE --backend ollama -o suspicion.jsonl` | model suspicion (`--backend anthropic` needs `pip install anthropic` and ANTHROPIC_API_KEY, and sends trace metadata off the machine); then `report TRACE --suspicion suspicion.jsonl` |
| `raqib suspect TRACE --backend anthropic --allow-fallback` | lets another model answer a window the requested model refuses; off by default, and such answers are labelled (`answered_by`) and counted |
| `raqib eval [--candidate ollama:MODEL]` | false negatives and false positives of the rules and of each model on 50 labelled events: a checkout's tests/fixtures/eval/events.json or --events FILE (an installed raqib has none and exits 2) |

## Find the agents on a host (discover)
`raqib discover` looks for AI agents it has never heard of
([ADR-0004](docs/specs/ADR-0004-agent-discovery.md), Amendments B and
D). It goes by what an agent does, not by its name: a process that talks
(an outbound TCP connection) and has a child, or writes a file outside
config space. No name list decides that. `raqib/discover/endpoints.yaml`
adds supporting evidence only, and lists its own evasions: model hosts,
networks and local ports, config-dir footprints, the act names that label
a child (bash, python, git, ...), and the hand-off criteria. Each
candidate comes with its cited lines and a suggested capture source
(ADR-0003):
- **hook:** a root image named claude, but not Claude Desktop;
- **proxy:** a CLI the catalog marks `proxy_capable`;
- **os:** everything else.

**AGENT-DARK** is an agent's config directory on disk with no active tree
in the window. Discover is offline and read-only, and it never signals or
attaches to a process.
```bash
raqib discover                      # Linux: /proc and /proc/net/tcp (one snapshot)
raqib discover --window 30 --save run1   # sample 30 s; keep the texts read
raqib discover --from run1 --json   # the same inventory again, from the saved texts and run.json
```
On Linux, connections come from `/proc/net/tcp` and `/proc/net/tcp6`,
with owners from `/proc/PID/fd`. These are kernel files that no PATH can
replace. Only when `/proc/net/tcp` cannot be read does discover run `ss`,
by absolute path (`/usr/sbin/ss`, `/usr/bin/ss`, `/sbin/ss`, `/bin/ss`)
with a minimal environment. The output names the path it read.

On Windows, M5.0 reads exported text, not the live host. In PowerShell,
in an empty folder:
```powershell
Get-CimInstance Win32_Process | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding utf8 win-process.csv
Get-NetTCPConnection | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding utf8 win-tcp.csv
Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding utf8 win-dns.csv
Get-ChildItem -Force C:\Users\*\, C:\Users\*\AppData\Roaming\Claude\ | ForEach-Object FullName | Out-File -Encoding utf8 footprints.txt
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /rd:true /c:5000 > sysmon.xml   # newest 5000; if Sysmon is installed
```
Then `raqib discover --from C:\path\to\that\folder`.

**What a candidate is not.** It is a tree that talks and has a child, not
proof of an agent. IDE terminals, package managers running install
scripts, CI runners, browsers with helper processes and updaters can all
be candidates. Talk over loopback counts too: an agent's local model is
on loopback. Discover declares no fp_budget in M5.0. The budget is set
from the first field runs (M5.4), not guessed.

**What it cannot see.** Every run prints the first five as holes; the
others are printed when they apply to the sources read:
- **liveness:** a child is seen only while it is alive at a snapshot;
- **sibling talkers:** an Electron network process or a local relay sits
  beside the child, not above it;
- **reparented children:** setsid, nohup, double fork, or an exited
  parent;
- **TCP only:** no UDP or QUIC, and no unix-socket relays;
- **one view:** one network namespace, and no processes hidden by
  hidepid.
- **config space:** writes into dot-directories (also `.ssh`,
  `.git/hooks`, `.github/workflows`), AppData (also the Startup folder),
  ProgramData, temp, or the program's own directory are not counted as
  acts.
- **no names on Linux:** Linux keeps no DNS name record offline.
- **no environment on Windows:** Windows exports carry no process
  environment.

**Exit codes.** An empty result still prints the window, the records read
per source, and every hole.
- **1:** a candidate, an AGENT-DARK footprint, an unread line, or nothing
  read.
- **3 (incomplete):** a process or connection source failed (even in one
  sample, and also when ss stood in for /proc/net/tcp), held no record
  (Sysmon: no event 1, or no event 3), or left a talking line without an
  owner. A missing footprint listing is only a hole. `--save` writes a
  `run.json` beside the texts, so `--from` replays an incomplete run as
  incomplete.
- **0:** every process and connection source was read and complete, and
  nothing was seen. That is not a clearance.

Fixtures are in `tests/fixtures/discover/`. The Linux ones are real and
redacted, made by `capture.py` there; the Windows ones are synthetic.

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

Status: v0.1 candidate: capture, rules, report, suspicion
layer, evaluation, web view and docs. The last exit criterion of the plan
(M3.3) is still open: one person outside the project runs this quickstart
and files one issue.
