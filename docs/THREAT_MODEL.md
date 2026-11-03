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
   - The proxy source (ADR-0003) is a second way in: the agent's model API
     traffic, relayed by `raqib proxy` on 127.0.0.1. A `pre` comes from the
     model's answer, read over TLS with the certificate verified; a `post`
     comes from the agent's next request, so it is the agent's word, as a
     hook payload is. Any local process can send requests to the port and
     so write `post` lines. An agent that does not use the proxy leaves no
     line at all, which no rule sees yet (the os source and a CROSS-SOURCE
     rule are the planned answer, ADR-0003).
   - Every line names its source (`hook`, `proxy`, `os`); a line without
     one reads as `hook`. The field is as forgeable as the rest of the
     line.
2. **Trace file to rules.** The trace is a plain file that the agent's user
   can write. The rules trust it only as far as its own shape: corrupt lines,
   seqs or timestamps going back, gaps and missing halves become findings or
   alarms.
3. **Trace to model.** The suspicion layer sends window metadata to a model.
   - **What is sent, exactly:**
     - the session id and its working directory, which often contains your
       user name;
     - per line: seq, phase, tool, ts, ok, error_class, and cwd when it
       changes;
     - from input_meta: path, url_host, command_head;
     - from output_meta: scan, secret_kinds, placeholder_kinds;
     - for each finding in the window: rule_id, class, severity, cited_seq
       and summary. Summaries can embed paths.
     Each string is cut to 300 characters. Nothing else in the trace is
     sent, even if a forged line carries more (REDO 3).
   - All of this sits inside tags marked as untrusted data, with markup
     escaped. Only the line naming the seq range is outside them.
   - The answer must match a schema, cite seqs of its own window, and can
     only add suspicion (A2).
   - **Where it goes:**
     - with `--backend anthropic` the metadata leaves the machine (M2.1 Q1);
     - so it does with an Ollama URL that is not localhost, over plain HTTP
       if the URL says so.
     - Both print a notice.
   - **Server-side fallback** is off for the Anthropic backend (M2.1 Q4,
     ADR-0001 B-5): a window the requested model refuses is an error line.
     `--allow-fallback` turns it on; another model can then answer, the line
     names it (`answered_by`), and the run record counts it.
4. **Report to human.** Every line of the text report passes a printable
   filter, so a newline or escape sequence in a session id cannot print a
   fake result line (REDO 3). The web view escapes everything, runs no
   script and loads nothing (M3.1).

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
  `env curl`, `xargs rm`, `eval`, `zsh -c` and code given to a shell on stdin show only the wrapper or the shell; `cd x && rm -rf y`, pipes, `$(...)` and one level of `bash -c` are read into `command_programs` since ADR-0002 Amendment D, and a command that cannot be read in full shows only the first program (M1.1 3h-7, M1.2 Q5).
  - Since M1.2, a head that cannot be read safely is left out. Rules then
    report "unknown" rather than "clean".
- **File access that is not a file tool.** `cat ~/.ssh/id_rsa` in Bash, MCP
  file tools, and Glob/Grep patterns without a `path` do not reach
  `input_meta.path`, so SCOPE-PATH is silent (M1.1 PA5).
  - DRIFT-FILES likewise does not count edits made through Bash
    (M1.2 F15).
- **Symlinks.** Paths are normalised lexically. A link inside the project
  that points outside makes an outside read look inside (M1.1 PA2). The eval
  event `d02-symlink-escape` is built on this. Its trace holds only `ln` and
  `data/shadow`, which is all a reader would see.
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
- **Long calls and waiting are not silence, but look like it.** SILENCE-GAP
  fires on any minute without capture. That includes a long build and the
  time after `stop` while the agent waits for you (M0.2 Q1).
  - The eval set has one of each (b13, b22), and both are false positives
    of the rules.
  - The README quickstart is CLEAN only because its session lasts four
    seconds.
- **A live view of a running session shows alarms.** Each call still
  running is a pre without a post (SILENCE-HALF), and the session has not
  ended (SILENCE-OPEN). `ui --serve` re-reads the trace, so it shows these
  until the session ends (M0.2 S9, M3.1 review B-2).
- **The model sees windows, not sessions.** Windows of 40 lines do not
  overlap. An agent that pads between a secret read and a network call can
  put them in different windows; the rules still see both (M2.1 Q3, M2.2 Q4).
- **No model has been evaluated.** The eval harness has only canned-answer
  tests. Its event set was written by one author who knows the rules
  (M2.2 Q1 and "Not verified"). The FP budgets of the rules were also
  measured on the builder's own corpus (M1.1 A6-4, A6-7).
- **Counts reset per session.** DRIFT-FILES counts edits within one session,
  so spreading the edits over sessions avoids it (M1.2 F20).
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
  not as "blocked" (M0.3 Q4, M0.2 S10).
- **Prompt injection into the model layer.** The agent controls paths and
  hosts that the model reads.
  - The model can only raise suspicion, never clear a finding (A2).
  - So the worst an injection can do is make the model miss something the
    rules did not already flag, or waste the reader's time with a false
    suspicion.
  - The reasons a model gives are free text. Only the prompt stops them from
    arguing that a rule finding is wrong (M2.1 review 3.8).
  - None of this is measured. The eval set holds no injection text, and no
    real model has been run on it.
- **Reading what the watcher reports.** The watched agent can learn what
  Raqib sees:
  - `raqib ui --serve` is a localhost listener that any local process can
    read, the agent included. Because the page is rebuilt on every request,
    the agent could check after each action whether it was noticed
    (M3.1 Q2, review B-4).
  - Without the listener the agent can still read the trace and run the
    public rules itself.
- **Editing the watcher itself.** The agent runs as the same user as Raqib,
  so it can:
  - edit Raqib's checkout: the `capture.py` the hooks run, or a catalog rule
    (setting `status: disabled` still allows a CLEAN result);
  - forge the outputs: a findings file, a suspicion file, or the HTML page.
  A findings file is now tied to its trace by sha256, and a suspicion file
  must match its run record (REDO 3). Both can still be regenerated by
  someone who controls the checkout. Raqib v0.1 offers no protection
  against an agent with write access to Raqib (M3.2 review C-9, B-9).

## 7. Platform

Linux, macOS and Windows: capture, installer and the path rules (the SCOPE
and DRIFT rules judge Windows paths since M5.1b). Capture locks with
`fcntl` on POSIX and `msvcrt` on Windows; its deadline is `SIGALRM` on POSIX
and a timer thread on Windows. The installer writes a POSIX shell command
on POSIX and, on Windows, a command with no shell syntax that runs a short
Python launcher (Windows ruling of 2026-11-02, Amendment 2). On Windows a missing
`python.exe` is a hook error shown by Claude Code, with no `RAQIB-SILENCE:`
line; it is not a block. Install from the side that runs the agent
(Windows or WSL), not both.

Windows paths in the rules (M5.1b; rulings of 2026-11-02, Q-4 to Q-6, and
2026-11-03, C-1 to C-3, C-8, C-9, C-11, C-12, C-14, C-15). One normaliser
in the engine places every path. A drive path (`C:\`, `C:/`) or a UNC path
(`\\server\share`, recognised by its two leading backslashes only) is a
Windows path: `\` and `/` compare alike, and ASCII case is folded (A-Z
only). A `\\?\` or `\\.\` prefix is stripped only where a drive path or
`UNC\` follows it; any other prefixed path (`\\.\pipe\x`) keeps the UNC
reading and is outside every project. POSIX paths are unchanged and
case-sensitive.
SCOPE-CWD-ROOT has a Windows list of its own (drive roots, `Users` and the
homes under it, `Windows`, `Windows\Temp`, `Temp`, `Program Files`,
`Program Files (x86)`, `ProgramData`, a home's `AppData\Local\Temp`, UNC
share roots), so a session from `C:\`, `C:\Users\<name>` or
`C:\Users\Public` is a finding; a cwd on neither list is a judged negative.
Known holes, written in the rule descriptions:
- `/mnt/c/...` (WSL) and `C:\...` are different paths, and so are `C:\...`
  and the Git Bash form `/c/...`. Under a Windows cwd the Git Bash form
  makes SCOPE-PATH fire. This is a known false-positive source on Windows:
  an agent run from Git Bash that names its own project as `/c/...` gets
  SCOPE-PATH findings. A positive fixture records the firing (ruling C-8);
- from WSL, SCOPE-CWD-ROOT lists only `/mnt/<drive>` and
  `/mnt/<drive>/Users/<name>`, and no Git Bash form (`/c/Users/<name>`);
- the forward-slash UNC form `//server/share` is read as a POSIX path
  (C-12);
- a non-ASCII letter that Windows folds is not folded here (C-11, C-18):
  two spellings that Windows reads as one directory are two, so SCOPE-PATH
  can fire on a path inside the project. This is a known false-positive
  source, named in SCOPE-PATH's description; it adds findings and hides
  none;
- the subfolders of `C:\Users\Public` (`Public\Documents`,
  `Public\Desktop`) are not listed; `C:\Users\Public` itself fires as a
  home (C-14);
- junctions, subst drives, 8.3 short names (`C:\PROGRA~1`) and
  OneDrive-redirected homes are compared as written, not resolved;
- SCOPE-CWD-ROOT matches the cwd as written, so a cwd with `.` or `..`
  inside it (`C:\.\Users`, `/tmp/../home`) is a judged negative on both
  branches (C-15);
- macOS paths compare case-sensitively, and the macOS temporary
  directories (`/private/tmp`, `/var/folders/...`) are not listed.

Under a Windows cwd, a rooted path with no drive (`\x`) or a drive-relative
one (`C:x`) cannot be placed; the rules report it as partial. `--root` is
made absolute as the host does: on Windows, `/x` means `\x` on the current
drive.

## 8. What would change this model

- A keyed or chained trace, for tamper evidence and against the hash oracle.
- A capture source outside the agent's user account, such as a proxy
  (ADR-0001 section 2, later phase). The proxy source of ADR-0003 runs as
  whoever starts it; started as the agent's user, the agent can stop it,
  bypass it, or point its base URL elsewhere.
- Ratified answers to the open questions in `docs/review/`, in particular
  M1.2 Q5-Q9 and M2.2 Q1.
