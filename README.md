# Raqib — رقيب

An external watcher for AI agents. Raqib records what an agent does, judges it
with deterministic rules first, and lets a model raise suspicion — never acquit.

- Deterministic first. Silence is an alarm. The watcher never touches the watched.
- Works offline. Stores hashes, not content, by default.
- Starts with Claude Code (hooks); other agents via proxy later.

## Quickstart (capture)
Needs Linux or macOS, `python3` (stdlib only) and Claude Code.
```bash
git clone <this repo> raqib && cd raqib
tools/gate.sh                                   # must end with [gate] GREEN
tools/install-hooks.sh /path/to/watched-project # adds six hooks to its .claude/settings.json

cd /path/to/watched-project
claude -p "Use the Bash tool to run: echo raqib-quickstart" --allowedTools "Bash(echo:*)"
cat raqib.log.jsonl
```
The `claude -p` call above was run with Claude Code 2.1.301 on 2026-10-16. It
wrote five lines (`ts` and `cwd` left out here; the full trace is
`tests/fixtures/quickstart-claude-code-2.1.301.json`):
```
{"seq":1,"phase":"session_start","tool":"-", ...}
{"seq":2,"phase":"pre","tool":"Bash","tool_use_id":"toolu_01WG...","input_sha256":"a970...","input_meta":{"command_head":"echo"}, ...}
{"seq":2,"phase":"post","tool":"Bash","tool_use_id":"toolu_01WG...","output_sha256":"9728...","ok":true, ...}
{"seq":3,"phase":"stop","tool":"-", ...}
{"seq":4,"phase":"session_end","tool":"-", ...}
```
One `pre` and one `post` line share seq 2: that is one tool call. Inputs and
outputs are stored only as sha256 hashes. If the log cannot be written, the
hook still exits 0 and prints one `RAQIB-SILENCE:` line to stderr; it never
blocks the agent. `--log PATH` writes the trace somewhere else, for example
outside the project, so it is not in the watched agent's working tree. The
agent runs as your user and could still reach it there.
Re-running the installer changes nothing; other hooks are kept.

## How this repo is built
One micro-task per session (`HANDOFF.md`), a read-only reviewer, a judge that
can only say NEXT / REDO / STOP, and a gate every commit must pass. See
`docs/CONSTITUTION.md` and `docs/DEVELOPMENT_PLAN.md`.

Status: phase 0, task M0.3 (capture and install work; rules come next).
