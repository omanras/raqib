# Raqib — رقيب

An external watcher for AI agents. Raqib records what an agent does, judges it
with deterministic rules first, and lets a model raise suspicion — never acquit.

- Deterministic first. Silence is an alarm. The watcher never touches the watched.
- Works offline. Stores hashes, not content, by default.
- Starts with Claude Code (hooks); other agents via proxy later.

## Quickstart (capture)
Needs Linux or macOS, `python3` (stdlib only) and Claude Code. The code lives
on branch `claude/v0.1` until it is merged; `main` still holds only the kit
and the first capture hook, so clone the branch:
```bash
git clone --branch claude/v0.1 https://github.com/omanras/raqib raqib && cd raqib
tools/gate.sh                                   # must end with [gate] GREEN
tools/install-hooks.sh /path/to/watched-project # adds six hooks to its .claude/settings.json

cd /path/to/watched-project
claude -p "Use the Bash tool to run: echo raqib-quickstart" --model haiku --max-turns 3 --allowedTools "Bash(echo:*)"
cat raqib.log.jsonl
```
These exact steps were run on 2026-10-16 from a fresh clone of commit
`d7841d1` (branch `claude/v0.1`) with Claude Code 2.1.301. The builder ran the
`claude` line under `env -i` with a throwaway `HOME`, to keep it apart from its
own Claude Code session. The run wrote five lines; `ts` and `cwd` are left out
here, and the raw file is `tests/fixtures/quickstart-d7841d1-claude-code-2.1.301.log`:
```
{"seq":1,"phase":"session_start","tool":"-", ...}
{"seq":2,"phase":"pre","tool":"Bash","tool_use_id":"toolu_01VC...","input_sha256":"2b03...","input_meta":{"command_head":"echo"}, ...}
{"seq":2,"phase":"post","tool":"Bash","tool_use_id":"toolu_01VC...","input_sha256":"2b03...","input_meta":{"command_head":"echo"},"output_sha256":"9728...","output_meta":{"scan":"full","secret_kinds":[]},"ok":true, ...}
{"seq":3,"phase":"stop","tool":"-", ...}
{"seq":4,"phase":"session_end","tool":"-", ...}
```
The `pre` and `post` lines share seq 2: they are one tool call. Inputs and
outputs are stored only as sha256 hashes. `output_meta` names the secret
patterns the output matched (`secret_kinds`, never the text); `scan` is
`full`, `partial` (output over 1 MiB: only its start was scanned, so an empty
result is not reported as clean) or `none`. The trace path is absolute
(`<project>/raqib.log.jsonl` by default), so it does not move when the agent
changes directory. `--log PATH` puts it elsewhere, for example outside the
project's working tree; the agent runs as your user and could still reach it.

The hook never blocks the agent. If the log cannot be written, the log lock
is not free within 5 s, capture takes over 8 s, or python3 or the Raqib
checkout is gone, it exits 0 and prints one line beginning `RAQIB-SILENCE:` to
the hook's stderr. Run `claude --debug` to have Claude Code
write that stderr to `~/.claude/debug/<session>.txt`. A call that
Claude Code itself blocks fires PreToolUse only, so it shows up as a `pre`
with no `post` (see `tests/fixtures/blocked-calls-claude-code-2.1.301.log`); a
tool that fails fires PostToolUseFailure, a `post` with `"ok":false` (see
`tests/fixtures/file-tools-d7841d1-claude-code-2.1.301.log`).
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
RULES THAT DID NOT RUN: 2
  - DRIFT-FILES not-evaluated: needs context: scope
  - SECRET-OUTPUT partial: could not judge 1 line(s) (session:seq b3744113-...:4): ...
```
SECRET-OUTPUT is partial here because this trace predates `output_meta`: a
line the rule cannot judge is reported, never counted as clean.

## Suspicion (model layer)
A model can add suspicion on top of the rules; it can never clear anything (A2).
```bash
python3 -m raqib suspect TRACE --backend ollama --model llama3.1:8b -o suspicion.jsonl  # local (default)
python3 -m raqib suspect TRACE --backend anthropic -o suspicion.jsonl  # needs `pip install anthropic` and ANTHROPIC_API_KEY
python3 -m raqib report TRACE --suspicion suspicion.jsonl
```
The model sees only the trace metadata (tool, phase, path, URL host, program
name, secret-pattern names, ok), never hashes or raw content. That metadata is
marked as untrusted data. Its answer must be `{suspicion, reasons, cited_seq}`,
and code enforces the rest:
- an answer below `--threshold` (default 0.5) is dropped, never recorded as
  clean;
- a raised suspicion must cite seqs of its own window (A5);
- a failure, refusal or malformed answer becomes an error line, which the
  report shows as an alarm (A3).

The Anthropic backend uses `claude-opus-5-5` by default, with structured
outputs and server-side refusal fallback (`fallbacks: "default"`). With
`--backend anthropic`, the trace metadata leaves your machine.

## How this repo is built
One micro-task per session (`HANDOFF.md`), a read-only reviewer, a judge that
can only say NEXT / REDO / STOP, and a gate every commit must pass. See
`docs/CONSTITUTION.md` and `docs/DEVELOPMENT_PLAN.md`.

Status: phase 2 (capture, install, rules, report and the suspicion layer work; evaluation comes next).
