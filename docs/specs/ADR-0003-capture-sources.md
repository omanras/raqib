# ADR-0003 - Capture sources: hook, proxy, os

Status: proposed by the Table, 2026-11-02. Becomes accepted when M5.2 lands.
Amendments appended, never edited in place.

## Problem
Raqib v0.1 captures through Claude Code hooks only, on Linux and macOS
only. Three limits follow:
- Only one agent is watched. Other agents (Kimi, Codex, Gemini CLI, any
  OpenAI-compatible loop) offer no hook, or a different one.
- The hook runs inside the watched agent's process. The agent therefore
  takes part in writing its own record. For an agent that has read the
  rules this is the weakest possible anchor (ADR-0002).
- Windows, where most of the commander's machines live, is unsupported:
  the installer and gate are bash, and `capture.lock()` silently does
  nothing when `fcntl` is absent, so two concurrent hooks can hand out one
  seq.

## Decision
A trace record gains one field, `source`, with three values. Every source
writes the same record shape (ts, seq, session_id, phase, tool, hashes,
input_meta, cwd) so `raqib/rules/` does not change for a new source; the
engine judges records, not agents (A8). Records without `source` read as
`hook` (v0.1 traces stay valid).

- **hook** - today's capture. The agent calls Raqib. Cheapest, richest
  input_meta, weakest anchor.
- **proxy** - a local HTTP reverse proxy between the agent and its model
  API (OpenAI-compatible chat/completions and Anthropic messages). A tool
  call in a response becomes a `pre`; the tool result in the next request
  becomes its `post`. The proxy forwards bytes unchanged, adds nothing,
  initiates nothing (A4). It records what the model *asked for*. One
  bounded exception to "no network from the capture path": the proxy
  relays the agent's own connection and opens none of its own; a failed
  upstream still yields a record (A3).
- **os** - the operating system's own record of the agent's process tree:
  on Windows, Sysmon/ETW process-create, file-create and network events;
  on Linux, auditd or eBPF (later). The agent does not write this record
  and cannot move it. It records what *happened*.

Sessions stay per source. Joining them is a rule, not capture logic:
CROSS-SOURCE (anchor): a proxy `pre` with no os process within a window,
or an os process with no proxy `pre` - asked and not done, or done and not
asked. The gap between intent and act is the strongest signal Raqib can
have, and no signature is needed to read it.

## Consequences
- Schema: `source` optional in readers (default hook), required from
  writers after M5.2. `raqib report` groups by source.
- Windows is a supported platform from M5.1: Python installer, `msvcrt`
  lock fallback, one path-normalising function, CI on windows + ubuntu.
- Ordering with Phase 4: M4.2 and M4.3 edit `raqib/hooks/capture.py`.
  Land M5.1 (no schema change) and M5.2 (adds `source`) first, then
  rebase M4.2/M4.3 on the new shape. Shared helpers (hashing, input_meta,
  command_head) move to `raqib/hooks/common.py` in M5.2 so proxy and hook
  cannot drift apart.
- The first non-Claude agent watched is Kimi, through `proxy`. Whether
  Kimi also offers hooks is a fact to check in M5.2, not assumed.

## Candidates (each its own HANDOFF)
- M5.1 Windows: installer in Python, lock fallback, paths, CI matrix.
- M5.2 proxy source + `source` field + common.py; Kimi quickstart.
- M5.3 os source on Windows (Sysmon) + CROSS-SOURCE anchor rule.
- Later: Linux os source (auditd/eBPF); MCP shim as a fourth source only
  if a watched agent exposes nothing else.

## Amendment A (the Table, 2026-11-03) - rulings on the M5.2 review (721126a)
- A-1 Recording never breaks relaying (catch-all + silence line; 64 MiB cap).
- A-2 `tool` / `tool_use_id` bounded; hashed with `tool_hashed` otherwise.
- A-3 Proxy sessions and pairing follow the conversation key (sha256 of
  model + messages[0]); start on first sight, stop on a no-tool answer,
  session_end at shutdown; `--cwd DIR`.
- A-4 Pre-proxy results are one `history` line per key. A-5 A re-sent
  result with another hash is a trace problem. A-6 Host/Origin refusal,
  folded silence lines, THREAT_MODEL names suppression, browsers, key in
  the clear. A-7 Missing common.py writes into the trace. A-8 Relay edge
  cases documented or refused. A-9 In-memory pre index. A-10 Golden hook
  line. A-11..A-13 as in docs/review/2026-11-03-M5.2-ruling.md.
