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
    name or user name of the repository is kept;
  - under `raqib watch --host` (ADR-0007): the os source's program names
    (the image and the parent's image, normalised, never an argument) and
    paths of created files, redacted; and in `~/.raqib/host/inventory.json`
    (the latest round only) the round's process sample, each process as
    pid, image name and start time (no command line, no path), which
    names every program running on the machine at that instant.
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
- **The events file of the host watch** (`~/.raqib/host/events.jsonl`,
  beside its record; ADR-0011 Amendment F): one `raqib-event/1` line for
  each thing the watch judged that is new or changed (a tree, a finding, a
  source finding, a hole, a blind spot, a note, a knock), the watch's start
  and end, and a heartbeat on a fixed beat (`--beat S`, 60 s by default).
  `docs/specs/EVENT.md` is the contract: an event holds only what its entry
  holds and the report prints, plus the rule's own ids and the watch's facts
  (its run, platform, version and the host's name, read once from the system
  without a network call, or given with `--event-host`). It never holds a
  command line, a file's content, a row of a sample or a cite's text; it
  does hold paths as the report says them, so the account's name where the
  machine's path holds it.
  - It is local and appended (flushed line by line); nothing is sent
    anywhere. A collector's own agent may tail it; that agent, not Raqib,
    is then the sender, and the file is what it may read.
  - It lives under the same user as the agent, as the record does: an agent
    can read it, and can truncate or rewrite it. The numbers `n` rise by
    one per event in a run and the heartbeat is on a fixed beat, so a gap or
    a silence is visible to whoever reads it; the report and the state say
    how many events were written, not built and not written. A line that
    cannot be written is a hole of the watch, never a silence, and what it
    left unsaid is said at the next pass; a line is never appended to a
    fragment, whoever left it (the file's end is looked at before every
    line, and a file that does not end in a newline gets one first). Raqib
    itself never rewrites, rotates or truncates the file.
  - A watch that was stopped or killed writes no end: a run with a start
    and no end, whose last line is older than two beats, was stopped or
    killed, and that silence is the collector's alarm. Every event carries
    its beat (`watch.beat`), so the file alone says how long two beats are.
    A last line with no newline may still be being written; a line in the
    middle that is not whole JSON is a torn write, skipped and counted.
  - Every pass of the watch looks at every entry that can change, so a
    changed thing (an act's standing moved to another tree, a fold decided,
    a finding that grew) is said in the pass after the change, not a beat
    later; an alarm taken back is a later rev of the same thing (`alarm`
    false), and an act whose other half has no line keeps its alarm.

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
- **A Sysmon that stamps its events behind the time they were logged
  (ADR-0007 Amendments AM and AN).** On a machine that had been
  suspended for about that long (a virtual one), Sysmon's own UtcTime of
  an event was seen weeks before the time the log gives it
  (System/TimeCreated): its network events were seen 26 days behind
  while its process and file events were not. The cause is not
  established: the suspension is what was seen beside the lag, and which
  Sysmon versions do this was not checked. Taken as it stands, every
  connection would be before the watch's start: history, never knocked,
  and a round's window would start weeks back. So the time Raqib uses
  for a Sysmon event - before or after the watch's start, the order of a
  tree's lines, a beat, a window - is the time it was logged wherever
  that is read and UtcTime is more than 60 s from it; where the two agree
  within 60 s, or the export has no TimeCreated, UtcTime as before, to
  the byte. An os line timed from the log says so: input_meta.time_from
  "logged", input_meta.time_skew_s, the skew in whole seconds (positive:
  UtcTime is behind), and input_meta.time_record, the EventRecordID it
  was measured on, where read. The lag itself is a note, said once per
  event kind per watch ("Sysmon's event 3 carries a time 26 days 7 hours
  behind the time it was logged (... s): the logged time is used
  (measured on record N)", the record where its number is read): not a
  hole and not a knock, since the event is kept, at its logged time, and
  a watch on such a machine can still end CLEAN. A TimeCreated that is
  there and does not parse is said once per event kind by each reader (a
  RAQIB-SILENCE line once for a follow's life, a problem of each round's
  record: on a machine where every such time is unread, a hole in every
  round): that event's
  UtcTime is then used, unchecked; an export with no TimeCreated at all
  is no word, as before. An event whose UtcTime does not parse and whose
  logged time does is timed from the log (time_from "logged", no
  time_skew_s), said once per kind, not dropped. Within one read of the
  channel an event joins its tree by its ProcessGuid whatever order the
  two clocks sort it in: an act sorted before its own process's start,
  or a child's start sorted before its parent's, is still the tree's;
  the lines are still written in time order (a child's line before its
  parent's has no parent_seq), and an event known by its pid alone is
  placed as before. Where the logged time is wrong for the act, Raqib
  says more, never less: a process whose start (event 1) was logged more
  than 60 s after it does not match its sampled CreationDate and is
  listed as two processes (the round says the pid held one more beside
  the sampled one); an
  event that happened before the watch's start and was logged more than
  60 s after it is live, and can be knocked; an os process line timed so
  can fall outside CROSS-SOURCE's hook window, a "done, not asked"
  finding where hooks are present. What is not covered: an event whose
  logged time is itself wrong (the log's clock) is taken as the log gives
  it; a lag of 60 s or less is not corrected; the note gives the first
  skew of a kind, and a second, different lag of that kind later in the
  watch is not said again; an act whose process's start is read in a
  later read of the channel than the act is not joined back; the beats
  the final poll reads after the last round are counted in the report,
  not judged by HOST-RHYTHM; where its two times agree, a process's start
  (event 1) matches a sampled CreationDate exactly as before.

### The host watch (`raqib watch --host`; ADR-0007, Amendments P and R)
Rulings: ADR-0007 Amendments C, H, I, M, N, P, R, T, V, X. True of the
tree as P-1..P-4, R-2..R-9, T-2..T-8, V-1..V-6 and X-1..X-9 leave it (R-1
is amended by T-2, T-1 restated by V-1).
- **What a round sees.** One sample, and on Windows with Sysmon the
  channel's events since the previous round (ADR-0007 P-4, below): on
  Windows one read of the OS API
  (processes and their parents, TCP connections with their owner), on
  Linux one `/proc` snapshot (or `--window S` seconds of them, whose last
  snapshot is the round's process sample). A tree is in the round when its
  root talks at that instant and has a child (a candidate) or a
  user-directory program runs a shell that runs a command (an act-root).
  A tree seen in an earlier round whose root process is still in the
  sample and is not in the round is `quiet (its root alive in round N; not
  seen talking with an act at the sample; source kept)`: "source kept"
  only when its source is attached and running, else the source's real
  state. A root that talks with no child at that instant is quiet too: the
  words say what the sample showed, not that it was silent. It is gone
  only when its root is not in the sample. In a round whose connection
  record was not read no tree can be seen talking, so a tree absent from
  it whose root is alive keeps the state it had, `not judged this round
  (connections unread)`. A round read from an export with no process
  sample calls such a tree gone (or keeps it, when the round's connections
  were not read either), and says so once. A round whose process list was
  not read has an empty sample: every tree absent from it is gone, its
  source is stopped and attached again when it is next seen.
- **One server is one os destination (ADR-0007 Amendments AU and AW).**
  The os source keeps no address or host name of a connection in clear,
  but its line is not hashes only: the port and whether the address is
  private are in clear beside the connection's own identity, a hash of
  the host name Sysmon gave, the address, the port and the protocol.
  Under the host watch the line also holds the server's hash (the address
  in canonical form, the port and the protocol alone): it is written only
  where its caller asks for it, and the host watch's os follow asks;
  `raqib os-sysmon` on its own and every other caller do not. The
  server's hash has no salt and, the port being in clear on the same
  line, an IPv4 address can be found from it by trying them all (2^32
  hashes for each protocol, far fewer for a private one; one hash
  confirms a known server); an IPv6 address can only be guessed. For a
  connection the host's sample saw, that reveals nothing more than lies
  beside it: the host's own record of the tree, in the same directory,
  holds that remote address in clear. For a connection that opened and
  closed between two samples, or one read from before the tree was
  attached, the os line is the only record, and its address, which was
  bound to the name Sysmon gave it, can now be found this way: a reader
  of the watch's own files on the watched machine learns an address that
  machine connected to. A salt kept only in the running watch's memory
  would end that and is recorded as a task of its own.
  The rhythm counts the server's hash, so one server is one os
  destination whether or not Sysmon named the host on an event (it names
  it on some events of one server and not on others). A connection the
  host's sample saw to an address and port and the os source's
  connection to that server are two destinations: one connection both
  sources saw is one talk on each, never two cycles on one. What is not
  covered: another address of one server (an address pool, DNS round
  robin, the IPv4 and IPv6 of one name) is another destination, and so
  is another protocol to it (tcp and udp on one port are two); two
  servers behind one address and port (an edge of a content network, a
  forward proxy) are one destination, as they always were for the
  sample's talks; a
  connection line without the server's hash (written before it was
  recorded, by a caller that did not ask for it, or whose address, port
  or protocol did not parse) keeps the destination of its own identity,
  said once per source with its count (a source attached again is a new
  one, and says it again), so there one server named on some events and
  not on others is two destinations, and such a line and a line with the
  server's hash to one server are two destinations too.
- **A process under a tree the watch holds is that tree's (ADR-0007
  Amendments AY and AZ).** The inventory's anchor is that every process
  goes to its nearest talking ancestor. It has one exception in the
  watch, for the children the round's process sample shows: a process
  with the root of a tree the watch already holds as quiet or kept - the
  same tree by its key, its root in the round's process sample -
  strictly above it on its path is that tree's, and no ancestor's (the
  held root nearest it). The held root itself stays its parent's child:
  the ancestor keeps that act and is the tree the inventory made it - a
  candidate that talks and, where it is new, an arrival like any other.
  The watch decides it in one place, before any line of the round is
  written or counted from the sample; the beats of the os and hooks
  sources are not decided there. A process is given only where the held
  tree's own host record could be written when the round began (a source
  that keeps one, whose write has not failed, that did not end with a
  hole - an os follow's host record is tried again every round, so its
  failed write does not stop the giving - of a tree the sample holds);
  a process given in a round whose write then fails is given back, and
  from the next round is judged where the inventory puts it. There it is in that record (a HostChild
  line that names the tree the inventory had it under, judged there by
  the rules that judge a tree's children), an act beat of its ring, and
  in a line of the round by the road of a tree not in the round; the
  tree stays quiet, and no arrival is said again. Where the record
  cannot be written, the process stays where the inventory put it and is
  judged there, and the watch says so once for the tree. A process once
  given is new on no other tree while its pid is in the samples: when
  its tree's root ends and the system gives it a new parent under the
  ancestor, it is not judged there again (a round with an empty sample
  ends that, and where a start time was not read, another process that
  took the pid is taken for it). So an agent the watch already holds -
  one a sample has seen talking - whose connection to its model is
  closed at the sample no longer gives the children the sample shows to
  a talking ancestor (a CI runner's worker that talks to its server all
  the time) as that ancestor's cycles: a false HOST-RHYTHM at high on
  the wrong tree, and the agent's commands judged on it. What is not
  covered: where the ancestor has an os source, its follow is rooted at
  the ancestor; it leaves out the events under the root of another tree
  the watch holds with an os follow of its own while that follow runs
  (the root's own creation stays the ancestor's, and its record says once
  from which record it leaves that subtree out), but it still holds, and
  the ancestor's rhythm and its os findings still read, the agent's
  commands before the agent's tree is known (an event written then stays),
  after the agent's follow has ended, and where the agent's tree has no os
  follow of its own, or the round's process sample does not show the
  agent's root under the ancestor's (on Windows with Sysmon, the same
  false cycles there); the agent's acts with no talk seen make no cycle, so
  where no source sees a connection that opens and closes between two
  samples (Linux) the agent is still not found by rhythm - where a
  sample saw it talk it is found as an arrival, and its commands are
  judged on its own tree; an agent no sample ever saw talking is no tree
  at all, is not held, and its commands stay the talking ancestor's, with
  the false cycles they make there, as before; an agent that is started
  anew for each job gives the ancestor one act for each new root; a tree
  whose root is not in the sample is gone, and its orphans that were
  never given go to the nearest talking ancestor as before; a round with
  no process sample decides nothing; a file write carries no path in the
  inventory and stays the talking ancestor's; two held trees of one root
  pid are given nothing; and a path holds the system's own pids, so two
  processes of one pid in one inventory are not told apart on it.
- **A beat is judged in the round that reads it (ADR-0007 Amendments AP
  to AS).** A tree that is not in the round - quiet at the sample, or
  kept by a round whose connections were not read, or gone from the
  sample - and whose own source (its os follow or its hooks trace) gained
  a beat since the last round gets its HostTree line of that round,
  written by the same code as a candidate's, its class its own state
  (`quiet`, `kept`, `gone`) and its rhythm from the same ring with the
  same K, W and R. HOST-RHYTHM judges it, so an unnamed tree whose
  talk-then-act cycles all fall between two samples, or in its last
  intervals before it exits, is judged in the round that reads them.
  The tree's ring has one entry for every round from its first line on
  that reached its sample: a round in which it had no line has an empty
  entry with that round's own interval, so a beat is put into the round
  whose interval holds its time and a cycle cites the round of its beats
  (with no seq where that round had no line). A round that ended before
  its sample has no entry: its beats are in the next round's entry, whose
  interval holds them, so R rounds can be fewer than R entries. A beat
  older than the ring's oldest interval (a follow that is late, or
  attached again) is put into the oldest entry and counted in the
  window. A line of a tree that is
  not in the round says what its round read: no acts, endpoints or
  cites of an earlier sample, and the count and cites of the beats it
  read from its sources. Such a line is not an
  arrival: NEW-AGENT, NEW-AGENT-UNKNOWN and HOST-UNWATCHED read a
  candidate's line only, and the tree's history, first round and
  candidate state do not change. It takes the sources' beats only: the
  tree's connections and children as the last sample knew them are not
  read again or reset, so when the tree is next in a round a connection
  or child is new or old exactly as before. A named tree's rhythm is
  still not HOST-RHYTHM's; a benign tree's is judged. What is not
  covered: a quiet or gone tree with no source of its own (the host
  source only) has no beat between samples and no line; a source's beats
  are counted one round late, so those the final poll reads after the
  last round (of a tree alive at the end, of one whose os follow was
  stopped in the last round or two, or of a gone tree on a hooks trace
  that another session still writes) are counted and said in the report,
  not judged; several cycles inside one round's interval still count as
  one. The hooks source is the project's trace, not the tree's: every
  tree attached to it reads every session's Bash calls in that project
  as its own acts, a candidate, a quiet and a gone tree alike, so a gone
  tree goes on having lines while another session in the project runs a
  command; each is cited exactly, by the line of the session that made
  it. The seams of a source's life are not covered either: an os follow
  that is stopped because its tree is gone makes no last pass, so the
  events between its last pass and its stop are in no source; a tree
  that is attached again (gone for one round and back, or after a follow
  that ended) loses the beats its earlier source held that no round had
  read, one round's at most; and a quiet tree that a round with an empty
  process sample calls gone is attached again only when it is next a
  candidate. The rig's X12 reads a beat left for the final poll as
  missed, on any machine; where the machine has no Sysmon and the count
  is 0 it is not judged (n/a): no tree had a source with beats there, so
  the 0 measured nothing.
- **The start time decides, where it was read.** A tree is keyed by its
  root's pid, image and start time (Windows: the process's creation time;
  Linux: the start in clock ticks since boot that `/proc/PID/stat` gives,
  which a step of the wall clock does not move; beside the key the report
  shows the start as a time, shown as a time where the clock tick rate is
  known, computed from the ticks and `/proc/stat`'s btime for display
  only, so after a step of the clock the time shown moves and the key
  does not). The match is exact: where the start is unread
  in both the tree's key and the sample (an older snapshot, a process whose
  stat is hidden, Windows when the process's times are denied), a process
  of the same image that holds the pid now is taken for the tree: it is not
  new, and an ended tree is quiet, not gone; its quiet line ends "start
  time unread: a process of the same image holds the pid". The processes
  whose start could not be read are counted once per round, as a hole.
- **What lives between two rounds: narrowed where Sysmon is read
  (ADR-0007 P-4), a hole everywhere else.** Where the Sysmon channel is
  readable, each round also reads the channel's events 1, 3, 11 and 22
  since the previous round (one wevtutil of Raqib's own, absolute path,
  SystemRoot only, a timeout, ended and recorded; the query is bounded by
  the last EventRecordID read, and the first read by the moment the live
  reader was made, the CLI's or the window's) into the same discover run
  as the sample. A tree that starts, talks, acts and ends between two
  samples is then a tree of that round, listed as `brief` (seen in the
  channel, not at the sample) and sourced by pid and ProcessGuid, so its
  acts are judged by the catalog. A tree the catalog names knocks
  NEW-AGENT each time, brief or not. A tree it does not name that is a
  candidate only by what the channel gave (never at a sample) is listed
  `by the channel`, sourced, its acts judged, but it is no
  NEW-AGENT-UNKNOWN finding and no knock (AA-1; NEW-AGENT-UNKNOWN's match
  says it, AB-5): the report counts such trees by image path (one per
  tree, however many rounds it is listed, AB-1; by name where no path was
  read, said), with the five latest trees cited, until a field run
  measures how many ordinary programs do this; a watch whose only news is
  such trees ends CLEAN (exit 0) and its CLEAN and RESULT lines say how
  many (AB-2); an unknown tree that is a candidate at a sample knocks
  NEW-AGENT-UNKNOWN as before, once. Reading the channel does not change
  how a footprint is judged (AD-1, superseding AB-4 and AC-1): in a round that reads the
  channel, a footprint's state, link, live window and streak - so every
  AGENT-DARK and AGENT-DARK-LIVE knock and note - are those of the same
  round built without the channel's records (discover makes that build
  and its inventory carries its footprints; a link names the tree of the
  channel's round that holds the linking tree's root, and a tree of the
  round only by the channel is, for the footprints, quiet or kept as that
  build has it). No tree known or grown only by the channel - unknown,
  named or benign - links a footprint, makes it live or takes a link
  away. What this gives up: a footprint whose agent ran only between
  rounds is judged dark as before the rounds read the channel, though the
  tree was seen; joining the two is a later task (M7.12). History is what the first
  round's sample shows (AC-3): a candidate at round 1's sample is history
  unless its start was read and is at or after the watch's start, with or
  without events of it in the channel; a process older than the watch that
  is a candidate in round 1 only by the channel's events (round 1 reads
  none older than the watch's start, though the window's round 1 waits for
  its look and so reads a wider first span) is not history: unknown, it is
  listed by the channel and counted, and a later candidacy at a sample
  knocks once; named, it knocks NEW-AGENT in round 1. A tree known by its
  ProcessGuid in round 1 whose pid and image are those of a tree of round
  1's sample whose start was not read takes that tree's history (AD-2):
  the two are taken for one process, though they are still listed as two
  trees, in round 1 and in the first round of any tree whose start is
  unread (recorded with the tree-key task, M7.12). A ProcessGuid keys a tree: a reused
  pid is another tree; a tree seen in the channel in one round and in the
  sample in another is one tree when the records tell (a sampled
  CreationDate and a Sysmon 1 time within 2 s; or every event of the guid
  within the tree's life, from its start, or its first sight where its
  start was unread, to its last sample - this round's sample when its root
  is in it (AB-7); within one round's discover run, a start unread on one
  side joins only the one process of its pid and image on both sides,
  said, and a guid never joins a sampled process whose start was unread).
  The read is checked against what it asked: a record not above the bound,
  or older than the start, is dropped and said; a record at or below the
  bound restarts the read at once (the record numbers restarted: a cleared
  channel?), and two reads in a row of only records older than the read's
  start restart it (a clock that stepped back), said. When a stopped or cleared
  channel is said: in the third of three rounds in a row, each with a
  process the sample shows created a round earlier, whose reads held no
  event 1 at all, after the channel gave event 1 in this watch; then the
  read restarts from the round's time and says what it skips. When it is
  not said: on a quiet desktop that creates no process for a round, a
  stopped or cleared channel reads as quiet rounds - a hole that remains,
  and the narrowing holds only while the channel delivers. An image whose
  event 1 does not come while the channel gives others is a note ("left
  out by its configuration, or late"), withdrawn when an event 1 of that
  image comes ("an event 1 of <image> came") and said again at its next
  miss, so the report's last word on an image is its present state (AB-8). What the channel's read does not close: a read that
  fails, times out or reaches the cap of events per round is a hole of
  that round (the next round reads on from the last record read, so a
  channel busier than the cap makes the rounds lag; a lag of more than a
  round is said); a kind of event 1, 3 or 22 not read after three rounds
  (Sysmon's configuration: Raqib never changes it, A4) is said once and
  the report lists the kinds read; where neither a start time nor a
  ProcessGuid tells two processes of one image under one pid apart, they
  are one tree. Linux (no audit source of process events is read) and a
  Windows host without Sysmon keep the whole hole, said once: a `hole:`
  line of the watch's first lines, which speak from the watch's own check
  at its start and say so; where the live reader's first check differs
  (either way), the printed line of the round it is made in says so once,
  with what the sources are then, and the hole is said there if it was
  not said first (AB-3, AD-4).
- **Recorded, not closed (ADR-0007 AB-11).** The tree ledger grows by one
  entry per tree listed `by the channel`: a program that runs every
  minute for a day is 1440 entries in the state and in the report's TREES
  SEEN (each marked `by the channel`); a bound is a later task (M7.12),
  because it touches the tree key. A pid reused by a process of an image
  whose event 1 the channel does not give, wholly inside the seconds
  between a sample and its round's end, joins the earlier tree. An unknown
  program that repeats as brief runs is judged only by its acts: each run
  is its own tree, so HOST-RHYTHM and HOST-UNWATCHED never see the
  repetition; the count by path is its only trace.
- **Where the channel's watch and the watch without it still differ on
  a footprint (ADR-0007 AE; each is a knock more, never one fewer).**
  The footprints are judged from the round built without the channel's
  records, and three things of the channel still reach them through the
  trees. (1) A process whose sampled start was not read in the first
  round and was read later is two trees without the channel and one
  with it (its guid): with it the tree is history from the first round,
  so no NEW-AGENT comes for it in a later round, and its link never
  makes the footprint live (N-1) - the footprint's dark rounds knock
  where the split watch would have noted them. (2) A sampled program
  whose command line, known only from the channel, carries `--type=` is
  taken for a helper in the channel's round and is no act-root there:
  the footprint it links by name is not held quiet by it, and knocks
  AGENT-DARK-LIVE after its dark rounds while the program still runs.
  (3) In a round whose connections were partly read, a tree known only
  from the channel is said "kept" where the other watch says "quiet";
  the judgement is the same. What judging footprints without the channel
  gives up is wider than a run between rounds: the live sample reads no command line, so
  a sampled agent whose command line or working directory names the
  footprint only in the channel is not linked by it. The tree key is a
  later task (M7.12).
- **What the os lines are judged by.** NET-TOOL and DESTRUCT-CMD judge an
  os process line by its image name (P-1: `input_meta.image`, discover's
  normalised form, `curl.exe` -> `curl`; R-7: and its parent's,
  `input_meta.parent_image`, so ssh started by git is git over SSH and is
  left out, as git is on every source: an agent that reaches the network
  through git is not seen; the parent is known by its name only, and git
  starts ssh with what the agent configures - core.sshCommand,
  GIT_SSH_COMMAND - so a tunnel or a remote command through real git is
  git's). Still unseen: a shell builtin (cmd's `del`,
  `rd`, `copy`), which starts no process; a PowerShell cmdlet
  (`Invoke-WebRequest`, `Remove-Item`, and Windows PowerShell 5.1's `curl`
  and `wget`, which are aliases of a cmdlet), which runs inside the shell's
  own process; a renamed copy of a listed program; a listed program run
  inside WSL or by a multicall binary (busybox), which is the unlisted
  image; and everything that is an argument (the destination, the target,
  `vssadmin list` versus `vssadmin delete`), since the command line is
  only hashed. An os line written before P-1 has no image: the rules say
  they could not judge it, and the host watch says it once per source; no
  rule guesses the name.
- **One act, one finding, in every order; the past is history.** Nested
  trees each have a source, and each os follow reads all of its root's
  descendants: the same event (its time, tool, input hash, image and
  parent image; one key whether the pre alone or the pre and the post were
  read) read by several feeds is one act (V-1). The act stands on the
  nearest tree that read it and is not benign; only when every tree that
  read it is benign does it stand on the nearest of those, as a note
  (V-2): an agent that starts a benign program and acts through it has the
  act on the agent's tree, and an act under a benign program alone is a
  note, never an alarm, never a knock. While no knock has been sent for an
  act, each new copy asks I-6 again, first on the standing tree, then on
  each other non-benign tree that read it (the act is in each of their
  trees); a sent knock closes the act, never a second; "not notified" does
  not close it. So the knock, the exit code and the counts do not depend
  on which feed read the act first, in one poll or across polls; but which
  tree's FIRST-FINDING the knock spent does (an outer tree whose copy came
  first may spend its own). Everything said about an act - its status, its
  KNOCKS row, a fold's outcome, "judged on tree pid N" on the other trees,
  the tree that knocked - is read from the act when it is shown. A poll a
  judge cut short is settled in its own `finally`, again by the next poll
  and by the end; what the end cannot settle is listed as NOT SETTLED, an
  alarm of its tree. Two different acts of trees that are not nested, the
  same command line in the same millisecond with the same image and
  parent, would be taken for one. A catalog finding of an os
  event whose time is before the watch's start is history - listed on its
  tree with its count, never knocked, never an alarm - whenever the tree
  was first seen (R-2): a shell that becomes a tree in round 5 does not
  knock for what it ran before the watch. The silence rules keep I-3's
  rule: their findings are about Raqib's own record during the watch
  (T-5). The start is the earlier of the wall clock at the start and the
  wall clock now minus the monotonic time elapsed, so a clock that steps
  back does not turn acts into history; a step of more than a round is a
  hole, with its size, and said again when a later step is larger by more
  than a round (T-3, V-6). What remains: after such a step an act from the
  seconds before the start reads as live (the alarm side); a forward step
  makes nothing history.
- **Benign programs: sourced, and their acts are notes.** A tree whose root
  is a listed benign image under a listed directory of the system drive is
  listed `benign (its acts are noted, not knocked; its rhythm is judged)`
  (T-2, amending R-1). It is sourced like any other tree, so an agent
  inside an editor or a browser, whose root is the benign program, is
  still seen; but a catalog finding on it is a note: listed on the tree
  and in the report under "on benign trees (noted, not knocked)", counted
  apart, never an alarm, never knocked, the tree's FIRST-FINDING not
  spent. The person's own programs under explorer are such notes. One act
  under a benign tree and any non-benign tree is the non-benign tree's
  finding, nested either way (V-2). HOST-RHYTHM judges a benign tree as
  K-10 ruled, and knocks; HOST-UNWATCHED judges it as any tree; the tree's
  word then says what knocked on it (V-3). A rule turned off counts what it
  would have fired as acts, not copies, and names its would-be notes apart. Windows Defender's engine
  (`MsMpEng.exe`) is benign only under the system drive's
  ProgramData\Microsoft\Windows Defender or Program Files\Windows
  Defender (P-3). An agent with administrator rights can put a program of
  a benign name there and is then listed as benign, its acts noted, not
  knocked; a copy anywhere else knocks.
- **The person's hands (ADR-0007 P-5).** Text an agent hands to a person
  (the clipboard, a chat, a file) which the person then runs is the
  person's act: it runs under the person's own shell, outside every agent
  tree, and no rule of the agent's tree sees it. There is no timing rule
  for it, because none is sound: a pasted burst of lines and a batch file
  run from the same prompt write the same process record. The clipboard's
  text is never read by Raqib and will not be (section 1: Raqib must not
  become a second place where secrets leak). Which process wrote the
  clipboard (Sysmon event 24) is a candidate rule (ADR-0007 P-5), not
  built.
- **A channel that is there and not read (ADR-0007 AF and AG; the third
  field run).** On Windows the Sysmon channel is read with wevtutil, and
  who may read the channel is Windows' and Sysmon's configuration
  (administrators on a default install): a terminal that is not elevated
  may be denied it (wevtutil exit 5, as in the third field run). The
  watch never checks elevation: it reports the denial. Each failed read
  has a cause the watch names from the reader's own words (denied, not
  back in time, could not be run, other failure), and only a denial
  names the elevated terminal (Run as administrator). While no round of
  the watch has read the channel, every tree's source is the host's own
  record, as on a machine without Sysmon, except a Claude Code tree with
  hooks attached and a tree with no source; its source text names the
  cause. In the first round a tree is in after a read is kept, it is
  attached again as the os source: what its host record wrote stays
  judged, and an act of the tree's rhythm both sources saw is one act.
  While no read is kept, the first failed read knocks once (HOST-HOLE,
  its own rate-limit id, the cause first) and says one line in the
  terminal: the reason, that what lives between two rounds is not seen
  until a round reads, and that the trees are judged by the host's own
  record until then. The report's SYSMON line says how many of the reads
  the rounds asked were kept, with the first reason, and the holes of
  one run of failed reads whose words differ only by the round and its
  time are one line of the text report (each is still a hole of its
  round, in the record and the state). Said, not fixed: a read that
  fails after rounds that read leaves the os sources in place; what they
  cannot read while the reads fail is not seen, and each such run of
  failed reads knocks once, naming its cause and no terminal. What an
  agent without hooks reads with its own code (a file it opens, a
  directory it lists) is in no source of the host watch; the proxy
  source records the tool call where the agent is pointed at it; the
  host watch does not read the proxy's trace; the read starts no child
  and opens no connection, and Sysmon has no event for a read. A file's
  deletion is in no source at all (Sysmon's events 23 and 26 are never
  asked for); a creation only where event 11 is read. In the third field
  run the watched read the watcher's record: the agent read the watch's
  own files under the home to write its account of the test, as section
  6 says it can. Said, not fixed, of a tree attached again as os (more
  said, never less): a child its host record wrote and the channel then
  gives again can be two source findings of the one act; the follow's
  first pass reads the channel from the watch's start, and the silence
  and cross-source rules judge what it gives as live; a Claude Code tree
  tries its hooks again, and a second failure is a second hole; a tree
  that is quiet or gone when the first read is kept and never in a round
  again is never read by os; a child new in that round's sample is
  judged by the host's record too. Under the host watch a tree whose
  source is os also has the host's own record, from its attach, by the
  road a host source has it: a file of its own beside the os follow's,
  its own feed, the host's rules and the host source's history (the
  first round's lines of a tree there at the start are history; after a
  file restarts its lines are live); what becomes of the follow (an
  error, an end, a pass still out) never stops or delays those lines; a
  write of that file that fails loses those lines, is a hole, and does
  not end the follow; a tree no round's sample holds (known only from
  the channel) has no host line. So whatever its follow missed (a follow
  that never read, one that read once and then fails, one that ends in
  the round of its attach, one attached again, a channel cleared under
  it), a sampled tree is judged from its host record by the rules, the
  history and the words of the watch without Sysmon, and knocks no less.
  Not equal in three things, each more said or other words, none a
  silence: the tree's one first-finding knock may go to an act the os
  source saw before the round's sample, so the host line's own finding
  then says not notified; a tree that began on the host's record alone,
  while no round had read the channel, continues that record in a new
  file, where its lines are numbered from one again, so a knock's line
  number can differ; and an os tree attached again after its host file
  restarted judges that file's lines a second time, as history. Said,
  not fixed: a child or a talk of a sampled tree that only the round's
  channel gave can still be in its host line (the act's record does not
  say which source gave it). Each pass of a tree's os follow asks the
  channel a bounded question, as a round's read does: events 1, 3 and 11
  (the round's read asks 22 too), the first pass those since the watch's
  start (the rounds' read starts at the live reader's own start, which
  can differ by the reader's start delay), then the records after the
  highest it has read in the whole channel, at most the round's cap, a
  cut being a hole. A follow attached again is given the tree the
  earlier follow published at the end of its last finished pass, never
  the live tree of a follow still in a pass; the tree a follow keeps is
  never pruned for its life (memory, not judgment); when the round's
  read restarts (record numbers that restarted, a cleared or stopped
  channel, a clock that stepped back), every follow's bound restarts at
  the restart's time, whether or not the record numbers restarted, and
  the restart's hole says so of the follows then running; a follow
  attached after a restart says in its source text that it reads from
  the restart's time. Said, not fixed: a child between a follow's old
  bound and the restart's time is not read by the follow (the host's
  record has what the sample shows of it). A follow's pass that cannot
  read is a hole: a pass not back in time writes its own line (the
  helper's pid), a denial or a wevtutil that could not be run one line
  for the follow. Said, not fixed: the follow no longer reads the tree's
  past before the watch's start (it was history, listed and never
  knocked), and a child that started before the watch is not known to
  the follow, so its acts after the start are in the tree's sources only
  as the host's record shows them. The price is one act told twice: a
  child in the sample is a HostChild line and its event 1 an os line,
  and a rule can fire on both; the report's listing shows such a pair
  (the same tree, rule and standing, the os line's child of the
  HostChild line's image and started within a second of it, as the
  rhythm's twin rule) as one entry naming both lines, taken for the same
  act (one image, starts within 1 s), counted once; the join is the
  listing's only: the record, the state and the window keep and count
  both findings; two children of one image started within a second can
  be folded so (the words say taken for, not the same); a HostChild line
  that names several children joins at most one os line, the others stay
  apart; the rhythm counts the act once, and the catalog's rules knock
  for the pair at most once.
- **Raqib watches and stops nothing (A4; ADR-0001 section 7).** No watched
  process is signalled, suspended, attached to or killed, and nothing is
  blocked: a finding is a record and a knock after the act, never a
  prevention. The programs the watch starts are its own read-only helpers:
  the os source's `wevtutil` on Windows, `ss -tinp` on Linux every round
  (the bytes of each socket), and the notifier; Raqib ends only its own
  helpers (a `wevtutil` past its timeout and every one still out at Stop;
  an `ss` that has not returned in 30 s). The only writes are under `~/.raqib`, and the hook settings of a
  project only with `--attach-hooks`.

## 6. Attacks on the watcher itself

- **A rule a person adds (ADR-0009 Amendments E-H).** A rule made
  from the form, or added as a file, is judged by the engine as any rule,
  but it is measured on its own fixture files only, never on a corpus:
  its false-positive budget is what its two examples show. The watch's
  first lines and the report say so for every user rule.
  - A hand-written rule that reads host lines (it names HostChild) is
    polled with NET-TOOL and DESTRUCT-CMD. A regex in it that never ends
    stalls that poll, and those rules' judgement of that feed with it -
    as a hand-written rule already could on a trace feed. The form
    offers no regex.
  - Whoever can write in `~/.raqib/rules.d` or `rules.yaml` can switch a
    rule off or add one. Raqib says every rule that is off and every
    user rule at each start; it does not sign them.
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
