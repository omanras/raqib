# Raqib threat model (v0.1)

Raqib watches an AI coding agent from outside. It records what the agent
does, judges it with deterministic rules, and lets a model raise suspicion.
This page says what Raqib protects, whom it assumes to be hostile, where
the trust boundaries are, and what it cannot see. Every known gap names the
review file where it was found (`docs/review/2026-10-16-*`); "M1.2 F7" means
item F7 of the M1.2 review packet or questions file.

## 1. Assets

- **The truth about what the agent did.** This means the trace
  (`raqib.log.jsonl`) and what is derived from it: findings, suspicion, the
  report and the web view.
- **The user's secrets and files.** Raqib must not become a second place
  where they leak, so the trace stores hashes and a small metadata extract,
  never content (ADR-0001 section 3, Amendment A-5).
- **The user's attention.** A watcher that cries wolf gets switched off, so
  every rule declares a false-positive budget (A6). A watcher that stays
  quiet when it could not look is worse, so silence is an alarm (A3).

## 2. Adversary

- **The watched agent.** It runs as the user, in the user's project, with
  whatever tools Claude Code allows. Assume it may be manipulated (prompt
  injection through files, web pages or tool output) or simply wrong. Assume
  it can read Raqib's code and rules, because the project is public.
- **Not in scope for v0.1:** another local user, a compromised Claude Code
  binary, the network, or the operating system. Raqib is not a sandbox and
  blocks nothing (A4, ADR-0001 section 7).

## 3. Trust boundaries

1. **Hook payload to capture.** Claude Code hands every event to
   `raqib/hooks/capture.py` on stdin.
   - Raqib trusts Claude Code to fire the hooks and to report the tool name,
     input and output truthfully.
   - Every field the agent influences is treated as hostile data: paths,
     commands, outputs and cwd.
2. **Trace file to rules.** The trace is a plain file that the agent's user
   can write. The rules trust it only as far as its own shape: corrupt lines,
   seqs or timestamps going back, gaps and missing halves become findings or
   alarms.
3. **Trace to model.** The suspicion layer sends window metadata to a model:
   tool, phase, path, URL host, program name, secret-pattern names and ok.
   - The data is framed as untrusted, and markup is escaped.
   - The answer must match a schema, cite seqs of its own window, and can
     only add suspicion (A2).
   - With `--backend anthropic`, this metadata leaves the machine
     (M2.1 Q1).
4. **Report to human.** The text report strips non-printable characters. The
   web view escapes everything, runs no script and loads nothing (M3.1).

## 4. What the trace holds, and what it leaks

- **Stored in clear:**
  - file paths, URL hosts, the program name of a Bash command
    (`command_head`), and the working directory;
  - tool names, timestamps, session ids and tool_use ids;
  - ok and error_class;
  - the names, never the text, of secret patterns seen in output.
- **Stored as sha256:** every tool input and output.
  - The hashes are unsalted. Anyone holding the trace can confirm a guessed
    input or output, for example a known leaked key or a short command
    (M0.3 EC3, M1.2 F2).
  - This lets traces from different runs be compared. A keyed hash would
    stop the guessing, at the cost of that comparison.
- **Where the trace lives:** by default `<project>/raqib.log.jsonl`, inside
  the agent's working tree. The installer suggests `--log` outside the
  project (M0.3 O2). Either way the agent runs as the same user and can read
  the file.

## 5. What Raqib cannot see (known gaps)

**Content is out of sight by design.** The rules see metadata, not commands
or file contents. Everything below follows from that, or from the hooks.

- **The program behind a wrapper or a compound command.** `sudo rm`,
  `env curl`, `bash -c '...'`, `cd x && rm -rf y` and `xargs rm` show only
  the first program (M1.1 3h-7, M1.2 Q5).
  - Since M1.2, a head that cannot be read safely is left out. Rules then
    report "unknown" rather than "clean".
- **File access that is not a file tool.** `cat ~/.ssh/id_rsa` in Bash, MCP
  file tools, and Glob/Grep patterns without a `path` do not reach
  `input_meta.path`, so SCOPE-PATH is silent (M1.1 PA5).
  - DRIFT-FILES likewise does not count edits made through Bash
    (M1.2 F15).
- **Symlinks.** Paths are normalised lexically. A link inside the project
  that points outside makes an outside read look inside (M1.1 PA2). The eval
  event `d02-symlink-escape` shows this.
- **Secrets in tool input.** A secret the agent writes to a file or passes
  on a command line is not flagged as input (M1.2 Q1).
  - Write and Edit outputs echo what was written, and Edit echoes the whole
    original file. A secret there is reported as output (M1.2 F7, Q9).
- **Secret formats:**
  - not detected: `password=` lines, a PEM body without its header, and
    base64- or hex-encoded secrets (M1.2 F5);
  - output beyond 1 MiB per call is only partly scanned. It is marked
    `scan: partial` and never counted as clean (M1.2 F10);
  - a real token that happens to contain a placeholder word (EXAMPLE,
    your, test, ...) is skipped. The skip is recorded in
    `placeholder_kinds` (M1.2 F6).
- **The scope root comes from the watched session.** SCOPE-PATH measures
  against the session's own cwd. Two rules flag a cwd of `/` or a home
  directory, and a cwd that moves: SCOPE-CWD-ROOT and SCOPE-CWD-MOVED
  (M1.1 PA1).
- **Things the rules cannot tell apart.** Some events look the same in
  metadata whether they are benign or not:
  - `rm` of a build directory and `rm` of the user's files;
  - a docs fetch and an exfiltration fetch.
  The eval set measures this cost: the rules flag 6 of 25 benign events
  and miss 9 of 25 bad ones (`docs/review/2026-10-16-M2.2-baseline.md`).

## 6. Attacks on the watcher itself

- **Editing or deleting the trace.** The agent can rewrite or truncate the
  file. Lines are not signed or chained.
  - The silence rules catch some tampering: seq or time going back
    (SILENCE-ORDER), a gap, a session with no end, a half call.
  - A careful rewrite of whole sessions is not detected; nothing in v0.1
    claims otherwise.
  - Eval event `s12-rewrite-trace` exists, and the rules miss it.
- **Switching the hooks off.** The agent can edit `.claude/settings.json`,
  or set `disableAllHooks`, after install. The installer checks only at
  install time (M0.3 M8).
  - What follows is silence: a session with no `stop` or `session_end`
    raises SILENCE-OPEN.
  - A missing trace file is a usage error (exit 2), and an empty one is an
    alarm. But a session that ran while the hooks were off leaves no lines,
    and nothing in the trace shows that it happened.
  - A session whose start was not captured raises nothing (M0.2 Q2).
  - Eval event `s11-disable-hooks`: the rules miss the edit itself.
- **Starving or stalling capture.** A huge output, many parallel calls, or
  a held log lock could push capture past the hook timeout.
  - Since M1.2, the scan is capped and runs outside the lock. The lock wait
    is capped at 5 s, and capture ends itself at 8 s, below the installed
    10 s timeout, with one `RAQIB-SILENCE:` line on stderr.
  - That line is visible only in Claude Code's debug log (`claude --debug`),
    and the missing post becomes SILENCE-HALF (M0.3 B4, M1.2 F8-F10).
- **Blocked calls look like silence.** A call that Claude Code itself
  blocks fires PreToolUse only, so it is reported as SILENCE-HALF (high),
  not as "blocked" (M0.3 Q4, M0.2 S9-S10).
- **Prompt injection into the model layer.** The agent controls paths and
  hosts that the model reads.
  - The model can only raise suspicion, never clear a finding (A2).
  - So the worst an injection can do is make the model miss something the
    rules did not already flag, or waste the reader's time with a false
    suspicion. Both are measured by the eval harness (M2.2).
- **Reading what the watcher reports.** `raqib ui --serve` is a localhost
  listener that any local process can read, the agent included (M3.1 Q2).
  `-o FILE` avoids the listener.

## 7. Platform

Linux and macOS only (ADR-0001 A-6). Capture uses `fcntl` locks and
`SIGALRM`, and the installer writes a POSIX shell command. Windows is
unsupported in v0.1.

## 8. What would change this model

- A keyed or chained trace, for tamper evidence and against the hash oracle.
- A capture source outside the agent's user account, such as a proxy
  (ADR-0001 section 2, later phase).
- Ratified answers to the open questions in `docs/review/`, in particular
  M1.2 Q5-Q9 and M2.2 Q1.
