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

## Amendment A (2026-10-16) — answers to the M0.1 questions
- A-1 `command_head` := basename of the first whitespace-separated token of
  `tool_input.command`, skipping leading `NAME=value` assignments; Bash only;
  max 64 chars. Written into `input_meta`.
- A-2 Pairing: `tool_use_id` (from the hook input) is the primary pairing key
  and is carried on every tool trace line; fallback to
  (session_id, tool, input_sha256, oldest-unmatched) only when it is absent.
  Field `tool_use_id` is added to §3.
- A-3 Session events (SessionStart, SessionEnd, Stop) produce a trace line
  with phase session_start|session_end|stop, tool "-", no hashes, no
  input_meta. Owned by M0.3.
- A-4 PostToolUseFailure is captured as phase "post" with ok=false and an
  `error_class` string (exception/class name if present, else "failure").
  M0.3 installs this hook too (six hooks, not five).
- A-5 RAQIB_KEEP_RAW stays unimplemented until a rule needs raw content.
- A-6 Windows file locking is out of scope for v0.1 (Linux/macOS only);
  README states it.
- A-7 tools/gate.sh installs pytest if missing. raqib/ itself stays stdlib-only.
- A-8 Push policy for builder sessions: push allowed only to `claude/*`
  branches; never to `main`; never with --force. Merging into main is the
  commander's act after the gate.

## Amendment B (2026-10-17) — R#002 rulings on claude/v0.1
- B-1 Bash program names (`command_head`) are read with shell quoting
  (POSIX word splitting of the command string), not naive whitespace splitting.
- B-2 Output lines carry a secret-scan state field: the names of matched
  secret patterns, never their text; absence of the field means "not scanned".
- B-3 The Anthropic SDK is an optional dependency imported lazily and only
  inside `raqib/suspect/backends.py`; the gate fails if any other module
  imports it. All other runtime code stays stdlib-only.
- B-4 Judge STOP rule on SECRET findings applies to non-fixture content only;
  fixtures under `tests/fixtures/` exist to trigger rules and are exempt.
- B-5 Anthropic server-side fallback is OFF by default (`--allow-fallback`
  opts in). When on, fallback answers are labelled with the serving model and
  counted separately. A watcher must know which model judged (A5, R-27).

## Amendment C (the Table, 2026-11-03) — rulings on the M5.1b STOP (4531e1f)
- C-1 A Windows cwd outside SCOPE-CWD-ROOT's list is a judged negative;
  the list gains the Windows roots named in the ruling, including UNC share
  roots; no new engine construct.
- C-2 Unplaceable Windows forms (`\x`, `C:x`) are partial; POSIX-absolute
  and MSYS `/c/...` paths under a Windows cwd fire SCOPE-PATH (MSYS form
  recorded as a known false-positive source).
- C-3 `--root` keeps the host's abspath semantics.
- C-4 Scope widened to README.md:17, THREAT_MODEL section 7, test_docs.
Full text: docs/review/2026-11-03-M5.1b-ruling.md.

Builder note (2026-11-03, M5.1b; Amendment C stays as written). As built:
section 4's rule paths are placed by one function, `norm_path()` in
`raqib/rules/engine.py`. Drive-letter and UNC paths (UNC by backslashes
only, C-12) are compared with `\` and `/` alike and ASCII case folded (A-Z
only, C-11); POSIX paths are unchanged and case-sensitive;
a path of one system is never under a directory of the other, so
`/mnt/c/...` and `C:\...` differ (ruling 2026-11-02 Q-6). The `\\?\` and
`\\.\` prefixes are stripped first, before a drive path or `UNC\` only
(C-9). Context `root` is accepted when
absolute on either system. A-6 is not touched by this note.
Record: docs/review/2026-11-03-M5.1b.md.

- C-7..C-9 (dated note, 2026-11-03, second STOP dad6065): README.md lines
  17/68/122 in Scope ("0 of 10"); the Git Bash fixture is a positive; the
  `\\?\` and `\\.\` prefixes are stripped by norm_path.
