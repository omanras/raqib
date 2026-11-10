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
   - The proxy source (ADR-0003 and its Amendment A) is a second way in:
     the agent's model API traffic, relayed by `raqib proxy` on 127.0.0.1.
     A `pre` comes from the model's answer, read over TLS with the
     certificate verified against the trust store, which
     `SSL_CERT_FILE` and `SSL_CERT_DIR` in the proxy's environment can
     replace; `HTTPS_PROXY` is not used. A `post` comes from the agent's
     next request, so it is the agent's word, as a hook payload is.
   - Sessions are conversations: the session id is the conversation key, a
     hash of the model and the first message, so an agent that changes its
     first message starts a new session, and results it sends there pair
     with nothing.
   - Who can send: the proxy refuses a Host other than its own listen
     address and any request with an Origin header, which keeps browser
     pages out. Any other local process can still send requests, and a
     forged `post` sent first suppresses the real one: the real result then
     reads as re-sent with a different hash (a RAQIB-SILENCE line), and the
     forged one stays the post.
   - Key exposure: the API key travels in the clear to whatever process holds the port:
     when the proxy is not running, another program can take the port and
     receive the agent's key. The README says to set the base URL back and
     to prefer a fresh port per run.
   - The proxy writes no header value except, when an answer cannot be
     read, its Content-Type and Content-Encoding (bounded, redacted) in a
     RAQIB-SILENCE line.
   - An agent that does not use the proxy leaves no line at all, which no
     rule sees yet (the os source and a CROSS-SOURCE rule are the planned
     answer, ADR-0003).
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
  - file paths, URL hosts, the program names of a Bash command
    (`command_head`, `command_programs`), and the working directory;
  - of a Bash command's arguments, two things only (ADR-0002 Amendments G
    and H): the file name of the script a python (python, python3,
    python.exe, py, py.exe), bash or sh call runs, also behind timeout,
    nohup or env, or that `.` or `source` reads (`command_scripts`, the
    basename of its script operand, split on / and on a backslash), and the
    first word of the first non-empty `git commit` message when it is a
    lower-case word ending in a colon, at most 16 characters, such as
    `landed:` (`commit_prefix`). A script's file name can say what the
    script is for; nothing else of a command line is kept;
  - tool names, timestamps, session ids and tool_use ids;
  - ok and error_class;
  - the names, never the text, of secret patterns seen in output;
  - on the hook's session_start, stop and session_end lines (ADR-0002
    Amendment J): `git_head`, the 40-hex commit the cwd's HEAD named, and
    `git_error`, one word of a closed set saying why a value could not be
    read. A commit id names a commit: anyone holding the trace can tell
    which commit of a public repository a session ran on. No path, ref
    name or user name of the repository is kept.
- **Stored as sha256:** every tool input and output, and on the same
  boundary lines the raw bytes of the git index (`git_index_sha256`).
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
  The eval set measures this cost: the rules flag 9 of 25 benign events
  and miss 9 of 25 bad ones (`docs/review/2026-10-16-M2.2-baseline.md` and
  its dated note of 2026-11-03: EDIT-NO-TEST adds b11-refactor).
- **The two demands of a landing read names and ok only (ADR-0002
  Amendments G and H).** LANDED-NO-GATE asks for an ok run of `gate.sh` or
  `gate.py` on or before a `landed:` commit; EDIT-NO-TEST asks for an ok
  run of pytest, python, python3, `gate.sh` or `gate.py` after an edit under
  `raqib/` or `tests/` and before the next stop or session end. Both are
  demands: an agent that knows them passes by complying, except through
  their listed holes. Every hole of each rule's `holes:` list, as the rule
  states it (ruling H-8; also quoted in the ADR-0002 note):
  - LANDED-NO-GATE:
    - a stale gate: any earlier ok gate run in the session counts, even one
      before later edits;
    - operators are not recorded: tools/gate.sh || git commit ... and
      tools/gate.sh; git commit ... look like tools/gate.sh && git commit ...,
      whatever the gate's status;
    - a RED gate piped into another program (tools/gate.sh 2>&1 | tail -5) is
      an ok line: a pipeline's status is its last program's;
    - a gate started in the background (the Bash tool's run_in_background) is
      ok when it starts; its verdict comes later through another tool;
    - names are basenames: any program or script called gate.sh or gate.py
      counts as the gate;
    - a commit with no commit_prefix is not judged: --amend, -F, -C, -c, a
      here-document with an unquoted delimiter or with CRLF line ends, a
      message whose first word is not literal, a commit after the first one in
      a command, an abbreviated option, a git option before the subcommand
      that is not literal (git $OPT commit), git merge, git commit-tree, an
      alias, git.exe, a wrapper in front (sudo, env, xargs), a command capture
      cannot read in full, and a first word that is not a lower-case word
      ending in a colon (STOP:, Landed:);
    - --no-message, which makes git forget the messages before it, is not
      read: the prefix is that of the first non-empty -m, so git commit -m wip
      --no-message -m 'landed: x' is not judged;
    - a commit whose post line never came is not judged: unknown (partial),
      SILENCE-HALF has the call;
    - a gate run after the commit on the same line counts (git commit -m
      'landed: x' && tools/gate.sh): the line is the evidence;
    - the trigger is the line's ok, not the commit's: a failing command after
      the commit on the same line (git commit -m 'landed: x' && false) makes
      the line not ok, so the landing is not judged;
    - a call that names the gate without running it counts as a gate run: bash
      -n tools/gate.sh (a syntax check), python -V tools/gate.py, python -I
      tools/gate.py --rule-kinds-child (the kinds check only);
    - a Bash line capture cannot read at all (no command_programs and no
      command_head) and no gate run in the session make the landing unknown
      (partial), not a finding (H-2: a true gate line wins over such a line);
  - EDIT-NO-TEST:
    - a test or gate run piped into another program (pytest | tail) is an ok
      line: a pipeline's status is its last program's;
    - operators are not recorded: pytest || true is an ok line whatever the
      tests did;
    - a run started in the background (the Bash tool's run_in_background) is
      ok when it starts;
    - any python or python3 call counts as a test run (python3 -c 'print(1)',
      python3 --version), and any program or script called pytest, gate.sh or
      gate.py;
    - edits made through Bash (sed -i, a redirect, cp, mv) are not triggers:
      only Edit, Write, MultiEdit and NotebookEdit are;
    - an edit whose path cannot be read (no input_meta.path) is not a trigger;
    - a session that never reaches a stop or a session_end leaves its edits
      unjudged (partial); SILENCE-OPEN has the session;
    - an edit whose post line never came is not judged: unknown (partial),
      SILENCE-HALF has the call;
    - with no context root, raqib/ and tests/ are placed against each line's
      cwd: an edit made while the cwd is elsewhere is not under them
      (SCOPE-CWD-MOVED has the move);
    - a call that names the gate without running it counts as a test run: bash
      -n tools/gate.sh (a syntax check), python -I tools/gate.py
      --rule-kinds-child (the kinds check only);
    - a Bash line capture cannot read at all (no command_programs and no
      command_head) after an edit, with no test run after it, makes the edit
      unknown (partial), not a finding (H-2: a true test line wins over such a
      line).

### The tree anchor (HEAD-UNMOVED, INDEX-UNTOUCHED; ADR-0002 Amendment J)
Rulings: ADR-0002 Amendment J (the Table's ruling of 2026-11-03 on the tree anchor).
- **What it sees.** At session_start, at every stop and at session_end the
  hook reads the files under `<cwd>/.git` and records the head commit, the
  sha256 of the index's raw bytes and why either could not be read. It runs
  no `git` (a test holds the reader to that) and reads at most HEAD, the
  one ref HEAD names (the loose file, else packed-refs), and the index, each
  once, the small files capped at 1 MiB and the index at 64 MiB, within one
  50 ms budget. Two code rules (raqib/rules/tree.py) compare the session's
  last stop or session_end with its session_start: ok edits under the start
  cwd and the same head (HEAD-UNMOVED: never committed), or the same index
  bytes (INDEX-UNTOUCHED: never staged). Both may fire on one session.
- **What it cannot see.** The anchor is the cwd's own `.git`, as files:
  - edits outside the repository, or in a second repository, are not
    triggers; a nested repository or a submodule edited from the parent's
    cwd is judged against the parent's `.git`;
  - a linked worktree (its gitdir absolute, or relative above the cwd) and
    a submodule (`gitdir: ../.git/modules/<name>`) are never followed, and
    a worktree's commondir is not read: the session is unknown;
  - `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `git -C` or `--git-dir`
    in the agent's commands act on another repository or index than the
    one the hook reads;
  - an index rewritten by the agent: any write to `.git/index` (`git add`
    of another file, `git update-index`, `git read-tree`, and the
    `git status` or `git diff` that refreshes stat data with nothing
    staged) counts as touched (J-9, a false negative); the head moved by an
    empty commit, a commit of other files, a checkout or a hash written
    into `.git/HEAD` counts as moved.
- **The hook opens nothing outside the project directory (J-6 as K-2
  amends it, CLAUDE.md rule 5).** A `.git` file's `gitdir:` is followed
  once and only when it is relative and resolves under the cwd; `..` above
  it, an absolute, UNC (`\\host\share`, `//host/share`) or device path, a
  drive or a stream gives git_error "gitdir", and nothing is opened there.
  No symlink (or Windows junction) is followed at any component below the
  cwd; a FIFO or device in place of a file is not opened. A named hole: a
  file system mounted under the project directory (a network share) looks
  like a directory, and the hook cannot tell the two apart, so it reads
  such a mount as it reads any directory.
- **Not judged, unknown (J-3).** A session whose session_start carries no
  git keys (a trace written before Amendment J, the proxy, the os source)
  or that has no repository at either end is not judged and writes no
  note. A null value for any other reason, a moved cwd, a missing close, a
  missing start or an edit before the start record (K-4) make the
  session's edits unknown (a partial note), never a finding. A git_error
  outside the closed set is never echoed into a note.
- **False-positive sources:** an edit of a path git ignores (build output,
  `.env`) and work left for a human to commit are never committed by
  design, so the rules fire on them; the budget is 0.1 each.
- Every hole of each rule's HOLES list, as the rule states it (J-10; also
  quoted in the ADR-0002 note):
  - HEAD-UNMOVED:
    - the rule sees that the head moved, not why: an empty commit, a commit of
      other files, a checkout or switch, a reset, or a hash written into
      .git/HEAD or a ref all count as moved;
    - an unborn branch (no commit yet) is git_error "no ref": a session in a
      fresh repository is unknown (partial) (J-7);
    - a symlinked .git or a link below it, a gitdir that is absolute, above
      the cwd, UNC or a device path, a head in a SHA-256 repository, or a head
      not read within 50 ms is null: unknown (partial);
    - a reftable repository (HEAD names refs/heads/.invalid; its refs are in
      reftable/, which is not read) is unreadable: unknown (partial) (K-3);
    - a packed-refs file over 1 MiB is unreadable: a head that is only there
      is unknown (partial) (K-3);
    - only cwd/.git is read: a session started in a subdirectory, a second
      repository, a nested repository or a submodule edited from the parent's
      cwd is judged against the cwd's .git or not at all;
    - GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, git -C or --git-dir in the
      agent's commands act on another repository or index than the one the
      hook reads (K-3);
    - a linked worktree, whose .git file names an absolute gitdir or
      (worktree.useRelativePaths) a relative one above the cwd, and a
      submodule (gitdir: ../.git/modules/<name>) are never followed (J-6,
      K-2), and a worktree's commondir is not read (J-7): the session is
      unknown (partial);
    - a file system mounted under the project directory (a network share)
      looks like a directory to the hook, which reads it as one (K-2);
    - a Windows device name written with a space before its extension (CON
      .txt) is not refused by name; it is lstat'ed and never opened, since it
      is not a regular file (K-3);
    - edits whose path is not under the start line's cwd are not triggers:
      edits outside the repository, in a second repository, or with no
      readable path (J-4);
    - edits made through Bash (sed -i, a redirect, cp, mv) are not triggers:
      only Edit, Write, MultiEdit and NotebookEdit are;
    - a session with no stop or session_end after an edit leaves that edit
      unjudged (partial); SILENCE-OPEN has the session;
    - an edit before the session's first session_start is unjudged (partial:
      edit before the start record), never dropped (K-4);
    - the start is the session's first session_start line: a session resumed
      after the human committed or staged counts that as a move.
  - INDEX-UNTOUCHED:
    - the index is hashed as raw bytes: git status, git diff or any command
      that refreshes stat data rewrites it with nothing staged, and that
      counts as touched, a false negative (J-9);
    - staging any file counts, not the edited ones: git add of another file,
      git add -N, git update-index, git read-tree;
    - a commit rewrites the index: a commit of other files counts as touched;
    - a repository with no index yet (nothing ever staged) is null: unknown
      (partial) (J-7);
    - a symlinked .git or a link below it, a gitdir that is absolute, above
      the cwd, UNC or a device path, an index over 64 MiB, or an index not
      hashed within 50 ms is null: unknown (partial);
    - only cwd/.git is read: a session started in a subdirectory, a second
      repository, a nested repository or a submodule edited from the parent's
      cwd is judged against the cwd's .git or not at all;
    - GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, git -C or --git-dir in the
      agent's commands act on another repository or index than the one the
      hook reads (K-3);
    - a linked worktree, whose .git file names an absolute gitdir or
      (worktree.useRelativePaths) a relative one above the cwd, and a
      submodule (gitdir: ../.git/modules/<name>) are never followed (J-6,
      K-2), and a worktree's commondir is not read (J-7): the session is
      unknown (partial);
    - a file system mounted under the project directory (a network share)
      looks like a directory to the hook, which reads it as one (K-2);
    - a Windows device name written with a space before its extension (CON
      .txt) is not refused by name; it is lstat'ed and never opened, since it
      is not a regular file (K-3);
    - edits whose path is not under the start line's cwd are not triggers:
      edits outside the repository, in a second repository, or with no
      readable path (J-4);
    - edits made through Bash (sed -i, a redirect, cp, mv) are not triggers:
      only Edit, Write, MultiEdit and NotebookEdit are;
    - a session with no stop or session_end after an edit leaves that edit
      unjudged (partial); SILENCE-OPEN has the session;
    - an edit before the session's first session_start is unjudged (partial:
      edit before the start record), never dropped (K-4);
    - the start is the session's first session_start line: a session resumed
      after the human committed or staged counts that as a move.

### The os source (Sysmon; ADR-0003 Amendment C)
Rulings: ADR-0003 Amendments C and D.
- **The only record the agent does not write.** A hook line is written by a
  hook that runs in the agent's own process tree, and a proxy line is read
  from what the agent's model answered; an agent that controls its process
  can shape both. An os line is written from Sysmon's events, which
  Sysmon's driver logs for the whole tree. The agent can read CROSS-SOURCE,
  but it cannot move that record, which is why the rule is an anchor. That
  holds only up to the read:
  - an export given with `--from` is trusted as Sysmon's, so whoever can
    write that file can forge os lines;
  - once appended, os lines sit in the same trace as the hook's, a file the
    agent's user can write: an agent that rewrites the trace can rewrite
    them too (section 6);
  - an agent with administrator rights can stop Sysmon, unload its driver
    or clear its log before os-sysmon reads it. Sysmon's own state and
    configuration events (4 and 16) are not read, so such a stop or change
    is not seen; what remains is a gap in the os lines, or no export.
- **What os lines still miss:**
  - in-process actions: what a process of the tree does inside itself (a
    file read, a computation, a request over a connection already open)
    starts no process and creates no file, so it is no event 1, 11 or 3.
    File reads are never logged, and event 11 is file creation only;
  - memory-only tools: a tool run inside the agent's own interpreter, or by
    a server that was already running outside the tree (an MCP server
    started before the agent, a daemon), leaves no os line under the root;
  - Sysmon configuration gaps: without `-n` there is no event 3 (the report
    is then INCOMPLETE, not CLEAN), and a configuration's exclude rules
    drop events with no trace, so an excluded image reads as if nothing
    happened. Raqib cannot tell an excluded event from no event; it names
    the event ids an export does not hold (per export). The commander's
    configuration is a field test;
  - the log's size: the live read holds what the channel still keeps; events
    already rolled out are gone;
  - the tree: a process started for the agent by something outside the
    tree (a service, a scheduled task, WMI) is not in it. The root is the
    latest process that held the pid in the export (or the one `--root
    PID:GUID` names); earlier holders are named in one silence line and
    their trees are not read;
  - cwd: with no `--cwd` and no event 1 of the root in the export, os lines
    carry no cwd, and the SCOPE-CWD rules report them as partial;
  - UDP connections are written like TCP ones (the protocol is in the hash
    only);
  - the live output's encoding (read as UTF-8, or UTF-16 with a BOM or NUL
    bytes) is checked on fixtures, not on a real host.
- **What CROSS-SOURCE does not judge, by ruling:**
  - C-2, both directions: a trace with no os line (Linux, macOS, or
    os-sysmon not run) gets no finding and no note, and the report's
    `sources:` line shows the absence; a trace with os lines and no hook or
    proxy line is INCOMPLETE, by a partial note or, when every os process
    is the agent's own, "nothing to judge";
  - time outside both sources: a shell call before, after or between os
    sessions is history (not judged, no note); an os process outside every
    hook or proxy session is a partial note;
  - the agent's own direct children (helpers such as a search tool's `rg`,
    `git`, MCP servers, and the shell it starts) on the done side. An agent
    that runs its acts as direct children rather than through a shell is
    a known hole;
  - a session of os lines only, for SILENCE-GAP and SILENCE-ORDER: os lines
    carry the time of the act, so an idle os source is not judged; reruns
    append the same events again, as visible duplicates.
- **Holes of CROSS-SOURCE:**
  - names only: a program is matched by its file name, so a renamed binary
    (curl copied to `ls.exe`) passes as the program it is named for;
  - descendants are asked with their parent: whatever an asked process
    starts, at any depth and any time later, is asked. Programs that start
    children of their own include npm, npx, yarn, pip, python, node, git
    (hooks, aliases: sh), make, cargo, go, mvn, gradle and docker; an act
    started under one of them passes as part of it;
  - a shell started below the shell call within 10 s of any shell call is
    asked (a subshell, an MSYS bash fork for a pipeline), and so is
    everything it starts; the real shape of an MSYS fork under Sysmon is
    checked only by the field test;
  - a shell call whose programs are unknown (command_unread) leaves the
    processes in its window partial, and the note names that call.
- **False-positive sources of CROSS-SOURCE:** a tool that only has a shell
  word (bash, shell, cmd, command) in its name and starts no process gives
  "asked, not done"; an act started more than 10 s after its call, or a
  call written more than 10 s after its act, is a finding. Its budget is
  0.1 until the field test.

### The host watch (`raqib watch --host`; ADR-0007, Amendment P)
Rulings: ADR-0007 Amendments C, H, I, M, N, P. True of the tree as P-1, P-2 and
P-3 leave it (the task after the second field run).
- **What a round sees.** One sample: on Windows one read of the OS API
  (processes and their parents, TCP connections with their owner), on
  Linux one `/proc` snapshot (or `--window S` seconds of them). A tree is
  in the round when its root talks at that instant (a candidate) or a
  user-directory program runs a shell that runs a command (an act-root).
  Since P-2 the round also keeps its process sample: a tree seen in an
  earlier round whose root process is still in the sample and does not
  talk now is **quiet** (listed with that word, its source kept attached,
  neither gone nor back, no hole); it is **gone** only when its root is not
  in the sample. A round read from an export with no process sample calls
  such a tree gone, and says so once.
- **What lives between two rounds is still a hole.** A tree that starts,
  talks, acts and ends between two samples is never a tree of any round,
  and a child that lives only between two samples is never a host-source
  act. Where Sysmon is, an attached tree's os source sees every child it
  creates (event 1), whatever the rounds see; reading the channel into the
  round itself is the next task (ADR-0007 P-4). Linux, and a Windows host without
  Sysmon, keep the hole.
- **What the os lines are judged by.** NET-TOOL and DESTRUCT-CMD judge an
  os process line by its image name (P-1: `input_meta.image`, discover's
  normalised form, `curl.exe` -> `curl`). Still unseen: a shell builtin
  (cmd's `del`, `rd`, `copy`), which starts no process; a PowerShell
  cmdlet (`Invoke-WebRequest`, `Remove-Item`, and Windows PowerShell 5.1's
  `curl` and `wget`, which are aliases of a cmdlet), which runs inside the
  shell's own process; a renamed copy of a listed program; and everything
  that is an argument (the destination, the target, `vssadmin list` versus
  `vssadmin delete`), since the command line is only hashed. An os line
  written before P-1 has no image: the rules say they could not judge it,
  and the host watch says it once per source; the name is never guessed.
- **Benign programs.** A tree whose root is a listed benign image under a
  listed directory of the system drive is listed `benign`, never knocked.
  Windows Defender's engine (`MsMpEng.exe`) is benign only under the system
  drive's ProgramData\Microsoft\Windows Defender or Program
  Files\Windows Defender (P-3). An agent with administrator rights
  can put a program of a benign name there and is then listed as benign;
  a copy anywhere else knocks.
- **The person's hands (ADR-0007 P-5).** Text an agent hands to a person
  (the clipboard, a chat, a file) which the person then runs is the
  person's act: it runs under the person's own shell, outside every agent
  tree, and no rule of the agent's tree sees it. There is no timing rule
  for it, because none is sound: a pasted burst of lines and a batch file
  run from the same prompt write the same process record. The clipboard's
  text is never read by Raqib and will not be (section 1: Raqib must not
  become a second place where secrets leak). Which process wrote the
  clipboard (Sysmon event 24) is a candidate rule (ADR-0007 P-5), not built.
- **Raqib watches and stops nothing (A4; ADR-0001 section 7).** No process
  is signalled, suspended, attached to or killed, and nothing is blocked:
  a finding is a record and a knock after the act, never a prevention. The
  only programs the watch starts are its own read-only helpers (the os
  source's `wevtutil`, the notifier); the only writes are under
  `~/.raqib`, and the hook settings of a project only with
  `--attach-hooks`.

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

The git reader of the tree anchor (ADR-0002 J-8) measures its 50 ms budget with
`time.monotonic`, which on Windows before Python 3.13 ticks about every
15.6 ms, so the budget is measured in such steps there. A read that blocks
(a hung network file system) is not cut short by the budget: capture's
deadline ends that capture with `RAQIB-SILENCE`, and the boundary line is
lost (an alarm, A3). Windows has no `O_NOFOLLOW`: a link swapped in between
the reader's lstat and its open is followed there. On Windows the reader
opens HEAD, the ref, packed-refs and the index without FILE_SHARE_DELETE
and holds each open for up to the 50 ms budget: in that window a git that
renames `index.lock` over the index (or a ref's lock over the ref) fails
and retries, as git on Windows does for any reader (ruling K-7). A boundary
line takes up to about 70 ms longer than before (K-9).

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
