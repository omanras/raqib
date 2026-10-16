# Raqib — رقيب

An external watcher for AI agents. Raqib records what an agent does, judges it
with deterministic rules first, and lets a model raise suspicion — never acquit.

- Deterministic first. Silence is an alarm. The watcher never touches the watched.
- Works offline. Stores hashes, not content, by default.
- Starts with Claude Code (hooks); other agents via proxy later.

## Quickstart (phase 0 — not yet functional)
```bash
git clone <this repo> && cd raqib
tools/gate.sh                 # must be green
tools/install-hooks.sh <path-to-watched-project>   # M0.3
```

## How this repo is built
One micro-task per session (`HANDOFF.md`), a read-only reviewer, a judge that
can only say NEXT / REDO / STOP, and a gate every commit must pass. See
`docs/CONSTITUTION.md` and `docs/DEVELOPMENT_PLAN.md`.

Status: phase 0, task M0.1.
