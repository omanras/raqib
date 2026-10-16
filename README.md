# Raqib — رقيب

An external watcher for AI agents. Raqib records what an agent does, judges it
with deterministic rules first, and lets a model raise suspicion — never acquit.

- Deterministic first. Silence is an alarm. The watcher never touches the watched.
- Works offline. Stores hashes, not content, by default.
- Starts with Claude Code (hooks); other agents via proxy later.

## Quickstart (capture)
Needs Linux or macOS, `python3` (stdlib only) and Claude Code.
```bash
git clone https://github.com/omanras/raqib raqib && cd raqib
tools/gate.sh                                   # must end with [gate] GREEN
tools/install-hooks.sh /path/to/watched-project # adds six hooks to its .claude/settings.json

cd /path/to/watched-project
claude -p "Use the Bash tool to run: echo raqib-quickstart" --model haiku --max-turns 3 --allowedTools "Bash(echo:*)"
cat raqib.log.jsonl
```
These exact steps were run on 2026-10-16 from a fresh clone of commit
`b72f109` (branch `claude/v0.1`) with Claude Code 2.1.301. The builder ran the
`claude` line under `env -i` with a throwaway `HOME`, to keep it apart from its
own Claude Code session. The run wrote five lines; `ts` and `cwd` are left out
here, and the raw file is `tests/fixtures/quickstart-claude-code-2.1.301.log`:
```
{"seq":1,"phase":"session_start","tool":"-", ...}
{"seq":2,"phase":"pre","tool":"Bash","tool_use_id":"toolu_01QS...","input_sha256":"05a4...","input_meta":{"command_head":"echo"}, ...}
{"seq":2,"phase":"post","tool":"Bash","tool_use_id":"toolu_01QS...","output_sha256":"9728...","ok":true, ...}
{"seq":3,"phase":"stop","tool":"-", ...}
{"seq":4,"phase":"session_end","tool":"-", ...}
```
The `pre` and `post` lines share seq 2: they are one tool call. Inputs and
outputs are stored only as sha256 hashes. The trace path is absolute
(`<project>/raqib.log.jsonl` by default), so it does not move when the agent
changes directory. `--log PATH` puts it elsewhere, for example outside the
project's working tree; the agent runs as your user and could still reach it.

The hook never blocks the agent. If the log cannot be written, or python3 or
the Raqib checkout is gone, it exits 0 and prints one line beginning
`RAQIB-SILENCE:` to the hook's stderr. Run `claude --debug` to have Claude Code
write that stderr to `~/.claude/debug/<session>.txt`. A call that
Claude Code itself blocks fires PreToolUse only, so it shows up as a `pre`
with no `post` (see `tests/fixtures/blocked-calls-claude-code-2.1.301.log`).
Re-running the installer changes nothing; other hooks are kept.

## Report (rules)
From the Raqib checkout:
```bash
python3 -m raqib report /path/to/watched-project/raqib.log.jsonl --scope src --scope tests
python3 -m raqib rules TRACE -o findings.jsonl   # one finding per line (ADR-0001 section 6)
python3 -m raqib report TRACE --findings findings.jsonl
python3 -m raqib check-rules                     # measured false-positive rate vs budget (A6)
```
The report cites the exact trace lines behind every finding. It lists every
rule with its false-positive budget, and every rule that did not run. An
empty trace, a corrupt line or a finding with no matching line is an alarm.
Exit codes: 0 clean, 1 alarm, 3 incomplete (for example DRIFT-FILES without a
`--scope` or `--handoff HANDOFF.md`), 2 usage error. Here it is on the real
trace in which Claude Code blocked two calls:
```
FINDINGS: 2
  [high] SILENCE-HALF (SILENCE) session b3744113-... seq 2
      seq 2 of Bash has 1 pre and 0 post line(s): a post is missing
      seq 2: line 2  pre Bash seq 2  2026-10-16T20:49:37.878Z  input_meta={"command_head": "ls"}
  ...
RULES THAT DID NOT RUN: 1
  - DRIFT-FILES not-evaluated: needs context: scope
```

## How this repo is built
One micro-task per session (`HANDOFF.md`), a read-only reviewer, a judge that
can only say NEXT / REDO / STOP, and a gate every commit must pass. See
`docs/CONSTITUTION.md` and `docs/DEVELOPMENT_PLAN.md`.

Status: phase 1 (capture, install, rules and report work; the model layer comes next).
