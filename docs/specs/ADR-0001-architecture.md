# ADR-0001 — Architecture of Raqib v0.1

Status: ratified by the commander at project open.

## 1. Pipeline
```
agent (Claude Code / any)  --hooks or proxy-->  CAPTURE  -->  trace.jsonl
trace.jsonl  -->  RULES (deterministic)  -->  findings.jsonl
trace.jsonl + findings.jsonl  -->  SUSPECT (model, A2)  -->  suspicion.jsonl
all three  -->  REPORT / UI (read-only)
```
Each stage reads files and writes files. No stage calls the next in-process.
This is what makes every stage testable with fixtures and replayable offline.

## 2. Capture sources
- v0.1: Claude Code hooks (`PreToolUse`, `PostToolUse`, `Stop`, `SessionStart`,
  `SessionEnd`) installed via `.claude/settings.json` of the *watched* project.
- later: an OpenAI-compatible HTTP proxy for other agents (out of v0.1 scope).

## 3. Trace line schema (JSON, one per line)
```
ts           ISO-8601 UTC
seq          monotonically increasing int per session (Pre and Post share seq)
session_id   from hook input
phase        "pre" | "post" | "stop" | "session_start" | "session_end"
tool         tool name ("Bash", "Edit", ...) or "-" for session events
input_sha256 sha256 of canonical JSON of tool_input (never the raw content)
input_meta   small, rule-relevant extract: {path?, command_head?, url_host?}
output_sha256 (post only)
ok           (post only) bool
cwd          working directory at capture
```
Raw inputs/outputs are NOT stored by default (privacy); `RAQIB_KEEP_RAW=1`
stores them in a separate `trace.raw.jsonl` for lab use only.

## 4. Rules
YAML, one file per rule, fields: id, title, class (SCOPE|NET|DESTRUCT|SECRET|
SILENCE|DRIFT), match (declarative over trace fields), severity, fp_budget,
fixtures (positive[], negative[]). The engine is a pure function
`(trace lines) -> findings`. No rule may consult a model.

## 5. Suspicion layer
Input: a window of trace lines + any findings. Output JSON forced by schema:
`{"suspicion": 0..1, "reasons": [str], "cited_seq": [int]}`.
Code enforces A2: suspicion below threshold is discarded, never recorded as
"clean". The model backend is pluggable (Ollama local by default).

## 6. Findings
`{ts, rule_id, severity, cited_seq[], summary}` — a finding without
`cited_seq` is rejected by the engine (A5).

## 7. Non-goals for v0.1
Blocking or steering the agent (A4); multi-host; auth; cloud storage.
