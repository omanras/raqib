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
- **The bytes of a connection on Windows (the host watch, ADR-0007
  Amendments BK to BO):**
  - a live watch reads them from the kernel's own tracing
    (Microsoft-Windows-Kernel-Network), listening only: nothing is switched
    on for a watched connection or process;
  - reading them needs an administrator and starts one tracing session
    named for the watch (`raqib-net-PID`, in memory only); a killed watch
    leaves it until the next start, which stops it and says so as a note;
  - where the session cannot be started (no administrator, a policy, the
    limit of sessions) the bytes are not read: the blind spot `bytes` is
    said as before, with the reason, and nothing else is tried;
  - the counts are sums since the watch began, not since the connection
    did: a connection older than the watch shows only what it carried
    since; they lag the kernel by about a second;
  - UDP carries no counts yet: QUIC is unseen here;
  - a round after which the tracing lost events, buffers or notices, went
    beyond its cap of connections, could not read a byte event, or whose
    consumer ended, is not read: the blind spot `bytes` says the first
    cause and the rounds, each further kind of cause is a note once, and
    no connection is judged unchanged on such a round; a session that
    heard no event at all while the trees' connections moved (from its
    third round on) is said the same way, not as zero bytes;
  - a connection the tracing heard nothing of shows zero since the watch
    began: true only while the session hears; a session switched off from
    outside after it heard its first event freezes the counts unseen, and
    a sender whose pid in the tracing is not the connection's owner in
    the table (an inherited socket) is not matched.
- **The kernel's process events on Linux (ADR-0007 Amendments BQ, BR,
  BS, BT, BU, BW, BY and CC to CE; docs/specs/PROC-EVENTS.md):**
  - the reader listens to the kernel's word of every fork, exec and exit,
    and reads at an exec the program, the parent and the name the kernel
    gave the process (from the same stat), and nothing more of it; a live
    watch on Linux runs it in a helper and gives what it heard to each
    round beside the sample (BY-2): a process that began between two
    samples under a tree that talks at a sample (or under an act-root the
    samples made) is that tree's child, and NET-TOOL and DESTRUCT-CMD judge
    every program it ran (the newest 8), by its file's name and, where they
    differ, by the name it was called by (CC-1, CC-2). A process is its
    maker's child where the reader heard it made and its maker is a process
    of the round or a child the watch keeps (CD-1, CE-2); else the sample's
    parent stands. An act-root is made by the samples alone (CB-1, CE-2),
    and under one the sample's parent stands for every process (CF-1): what
    an act-root's shell starts in the background and leaves is nobody's,
    as before this task.
    A child whose file the reader could not read (one run through `sudo`)
    is named by the name the kernel gave it, and its line says its file was
    not read (CE-3): that name is then all there is, and it is the
    process's to choose - a tool run so under another name is missed. Not judged: a tree that lives whole between two
    samples (a tree needs a talker at a sample; a connection between two
    samples is still unseen), a child's own connections, a program past
    the bound of 8 a process, a child whose parent the watch never wrote,
    and a process whose maker the reader did not hear that a sample holds
    under pid 1. A program not read, and no name read, is in the round and
    counted, with no line;
  - the helper's lines are its word, not a fact the watch checked (BY-4,
    BX-5): what is judged from them is said to come from the reader, and a
    program's name reaches a line's programs only through the gate a sampled
    child's name goes through. A process of the same user that writes in the
    helper's place could make the watch write HostChild lines for children
    that never ran under a tree that talks (with the names it chose, if
    plain program names), so findings of NET-TOOL or DESTRUCT-CMD on that
    tree that nothing did; it could leave out what did run, so a short child
    is not judged; and it could name the watch's own pid as a child's
    parent. It cannot make the watch run anything or write a file of its
    choosing (CA-5). The
    watch reads no /proc start of a process the reader said ended (BZ-8),
    but it reads /proc/PID/stat for the start of each other child the
    round names, so such a process could make the watch read that file of
    pids it names (read-only, a start time, nothing kept but the time). It
    holds no right the user does not hold, and such a process could as well
    stop the watch itself;
  - the watch's own short programs (the socket tool it runs each round) are
    in its record of what it started when they start (BY-6), so the reader's
    word of them is the watch's own: a process the reader gives under the
    watch's pid whose pid, program and start are the record's is not given
    to the round;
  - the helper is a second process of Raqib's, started by the watch with
    the watch's own interpreter, always `-I` (isolated: no user site folder
    and no PYTHON* variable of the environment; BY-6), its directory `/`,
    and the watch's own import path given
    entry for entry, so it loads Raqib from where the watch did and from
    nowhere else; it is in the watch's record of what it started. Where
    Raqib is packed with its own runtime (`sys.frozen`; ADR-0007 CG-1), the
    helper is the packed program itself with one fixed word as its only
    argument: no `-I` and no import path are given; it loads Raqib, and
    every module Raqib's entry imports, from the packed program's own
    folder; its directory is `/` and its environment is the watch's. That
    the packer's runtime reads nothing of that environment was measured
    once (PyInstaller 6.11.1: PYTHONPATH and a working folder's modules not
    loaded), not proven; what the packer's own start reads of it (its own
    variables, the library search path) was not measured (CH-3). Every
    `raqib` and `python -m raqib`, packed or not, on every system, given
    that word as its first and only argument serves the reader on its
    standard input and output, as `python -m raqib.procevents --serve`
    does, with the rights of whoever runs it: it adds no reach. A packed
    program given a right of its own (file capabilities, set-user-id)
    would serve the machine's process events to whoever runs it so. It reads
    its input, the kernel's socket and, at each exec, that process's
    /proc/PID/exe and /proc/PID/stat; it opens no other file, writes only
    its output and starts no program, and it ends when its input ends, so
    a watch that dies, however it dies, leaves none behind. It adds a
    process that holds a listener of the kernel's events for the watch's
    life; it adds no right and no reach outside the machine. Each line it
    writes is bounded (1 MiB) and the watch holds at most four unread and
    at most one ask unanswered, so a helper that is stopped or slow costs
    the watch a hole, never its round or its Stop (measured: a helper
    stopped under a watch of ten rounds of three seconds; the watch ended
    in 28 s, said the three late rounds and started the helper again once).
    A process of the same user that writes the helper's output in its place
    is not told apart from the helper: its numbers are counted as the
    helper's, and one that answers while the helper reads nothing could
    still hold the watch at a write; that process could as well stop the
    watch itself. The ask is written so that it cannot block: an input
    that is full is said as the helper's end. Before the helper's fixed
    program sets its import path, the interpreter's own start reads what
    the watch's start read (the system's site folders' own files): the
    places are the watch's, their contents are read again at each start.
    Packed, the helper's start reads the packed program's folder (its
    archive and libraries) again at each start: whoever can write that
    folder changes the next helper as he changes the next watch.
    A helper refused at its first start (a container, a right not given),
    or late or ended before its first answer, is a blind spot of the watch,
    said, and the rounds are the sample's alone; after its first answer, a
    late answer, a line that is not the helper's, an end, a loss of events,
    a bound passed or an answer that holds back a rest for a next one is a
    hole of the result (BY-5, BZ-6): what was being judged has a gap. One late three rounds running is ended and started again
    once, a second end is final, and the watch then hears nothing between
    two samples for the rest of its run. A process of the same user can end
    or stop the helper: that is said, never silent;
  - A program's path, text a process chose, reaches a tree's programs only
    through the gate a sampled child's name goes through (a plain program
    name, else a hole); a tree's line holds the reader's record itself, its
    path included, made printable and cut as a sampled child's record is
    (BZ-11); the PROCESS EVENTS section says only numbers;
  - when the interpreter's file, or a packed program's file, is replaced on disk while the watch runs (a
    package upgrade), /proc shows the helper's program with " (deleted)"
    after it; the watch's record takes that image as the image it was
    (BY-6), so the helper is still the watch's own;
  - an agent that starts more processes than the reader's bound (32768)
    has the rest counted `beyond`, not kept; the bound counts over the
    reader's life, and a process whose end was lost never leaves it;
  - a process that ends before its program is read, that is not readable
    by this user (a program can make itself so), or that the system hides
    from the reader is given without its program: the read is counted in
    `missed` and named in its `unread`;
  - a process that changes its program again keeps the programs it had
    before in `earlier`, its newest 7 (8 a process with the one it has
    now, CC-1); the number of older ones is said, counted and never judged:
    a process that runs more than 8 programs between two asks hides the
    oldest of them;
  - at each exec the reader reads, from the same stat, the name the kernel
    gave the process (CC-2); a child's line names it beside its file's name
    where they differ, through the name gate. A process can be called by a
    tool's name it is not (a link of its own named `curl`): its tree is then
    judged by that name, and alarms by its own doing; a name of the
    kernel's full length (15) is taken as cut and not used;
  - the watch keeps, per tree, only the children it wrote that the process
    events heard and whose end they have not told (at most 512 a tree;
    passing it is said and is a hole of the result), so a child whose
    parent has gone is still its tree's (CC-3), given to it while the tree
    is quiet too (CE-1); a child of a child written from a sample alone is
    nobody's once its parent ends, and a child whose parent the watch never
    wrote is in no tree. A tree that has gone is written nothing: how many
    processes its kept children were heard to start is said, as a hole of
    the result (CE-1);
  - a pid taken again within one second of the exec, before the read, is
    not told apart: the newcomer's program and start are then given as the
    first process's; a start later than that is told, nothing of that
    read is given, and it is counted in `reused`;
  - a burst the kernel cannot queue for the reader is counted in `lost`
    (ENOBUFS), never as nothing happened; what the queue held is given,
    what came while it was full is gone, and the kernel's own count on
    each CPU gives how many at least, a gap with no ENOBUFS included; the
    answer the kernel sends to any listener's ask takes a number of that
    count and is counted as one, so another listener is no loss; the
    time a datagram was last heard is said (`last`);
  - a process ends with its last thread: an exit of its leader thread
    while another lives on is not its end; an end of a process the reader
    did not hold from its fork, or any end given after a loss, may be its
    leader thread's alone, and says so;
  - if a thread's exec ever came before its leader's exit (not seen in
    2400 runs), the reader would give the end of a process that lives on,
    and its real end as an end of a process it did not hold;
  - a child made to be its maker's sibling is given the parent the kernel
    names, which is not its maker;
  - a kernel that refuses (an older one, or a container's) is the hole,
    said in the reader's words as `refused`, and nothing else is tried;
    no right is asked; another process cannot answer the reader's ask for
    it (its mark is random);
  - the program is raw text of the process's choosing in part (a removed
    file, a program run from memory with a name it chose): a consumer that
    shows it must escape it; no argument of any process is read, so what a
    program was asked to do is not in this source.
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
- Sysmon can stop holding a process that still runs. Seen in the field: the
  starts of a long-lived parent's later children then name the parent by an
  empty ProcessGuid (all zeros), with `-` as its image and its command line,
  the parent's pid still right; in 17 runs of ninety seconds it happened in
  two, to one child and to eleven. Raqib once took the zeros for a
  ProcessGuid of their own: the children joined no tree, their lines were
  never written, and the round took the tree for quiet while it worked. An
  empty ProcessGuid is now no ProcessGuid: the event is joined by the pid it
  names, as an event that carries none is, and the follow and the round each
  say so. What that costs: where the pid was taken again by another process
  in between, the child is given to the pid's present holder, and nothing
  tells the two apart there; the root's own pid stays the root's for the
  follow's life, so a child named by it after the root ended is the tree's
  even where the follow read the start of the pid's new holder; the parent's
  name is unread (`-` is not a program's name), so a rule that reads a
  parent's name does not have it; a connection whose own ProcessGuid is empty
  has neither its program's name nor its parent's (its start is held by its
  ProcessGuid); and a process joined by a pid is not marked as at or under
  another watched tree's root, so where it is a nested tree's, the outer tree
  takes its acts and talks as its own too. The follow's word is written once
  in each tree's source whose pass read such an event, the tree's own or not.
  Not measured: how long a process must live, or how busy the machine must
  be, before Sysmon lets go of it; whether a real desktop's Sysmon does it
  more often than a machine made for one run.

### The rules of behaviour (PERSIST-AUTOSTART, NET-ADMIN-PORT; ADR-0014)
Rulings: ADR-0014 A-3 to A-6 and A-8. Two signatures judge what a tree does to the
host, beside what its program is called, from the lines its sources write. What
was measured (a stand-in agent on a Windows machine with Sysmon logging events 1,
3, 11 and 22, each act harmless and undone) is the ground of what follows.

What they see:
- PERSIST-AUTOSTART: a file the tree created directly in a Startup folder of
  Windows (a user's or all users'), as Sysmon's file creation (event 11) names it,
  or the path of a hooks Write, Edit, MultiEdit or NotebookEdit. Measured: the
  stand-in's file in the user's Startup folder was a file line with its whole
  path. `desktop.ini`, which Windows keeps there, is left out.
- NET-ADMIN-PORT: a connection the process itself made, as event 3 says it
  (`Initiated`), to port 22, 23, 135, 445, 3389, 5900, 5985 or 5986 of a private
  address that is neither loopback nor link-local, whatever program of the tree
  opened the socket. Measured: PowerShell's own socket to port 22 and an ssh to the same
  port were each a net line with port 22 and a private address, and no rule
  judged the first. An os net line now carries `initiated`, `dest_scope`, `image`
  and `parent_image` (the names its process's own start gave); the address and
  the command line stay hashes.

What they do not see:
- Every autostart place the rule does not read yet. Measured: an autostart value
  under `CurrentVersion\Run` is Sysmon's event 13, with the program that set it;
  PERSIST-RUN-KEY judges it (below), not this rule; a scheduled task is written by the
  Schedule service (svchost, as SYSTEM, 24 ms after schtasks started), not by a
  process of the tree.
- A file moved or renamed into the folder: not measured. A move within one
  volume is believed to be no file creation for Sysmon; a move from another
  volume is a copy, and so one. A file already there changed in place, and a
  hard link made there, are believed to be none either.
- What the kernel does for a tree: Windows' own SMB client (a share, a named
  pipe, sc or schtasks against another machine) connects to port 445 as System,
  not as a process of the tree. Not measured here; the commonest way to another
  Windows machine is so outside NET-ADMIN-PORT.
- Another machine on the same link reached by its link-local address is left
  out with loopback. An address of 100.64.0.0/10 counts as private.
- A net line whose Initiated was not read has no `initiated` key (ADR-0014 AE-1):
  NET-ADMIN-PORT does not judge it, and its partial note says so, as for a line
  written before the four keys. Real Sysmon writes Initiated always, so the reach
  is small. A line written by an earlier build with a null `initiated` (its
  Initiated not read) is judged as not initiated, and nothing says so. Under `raqib watch --host` the watch says once, after three rounds
  that read the channel, that no event 11 was read (ADR-0014 AE-2, its
  words Amendment F's): a file a tree makes may then be unseen, and
  PERSIST-AUTOSTART's os lines may have nothing to read (three rounds with no
  file made are said the same way: the watch cannot tell the two apart).
  It is learned from what the rounds read, as for events 1, 3 and 22, not from
  the configuration: a channel that gave an event 11 in those rounds is not said
  at all, and a note once said is not taken back in that run.
- The budgets of the two rules were measured on no real desktop's work. A
  deploy over ssh to a machine of the same network, a remote session of an
  editor, a local virtual machine reached at its private address, a profile's
  copy that holds a Startup folder: each would fire, and how often is not
  known.
- A Sysmon that logs no file creation or no connection there: nothing is then
  there to read, and Raqib cannot tell that from nothing done.
- A port not on the list, a public address, a relay or a tunnel.
- The host's own sample of a connection (Linux, and Windows without Sysmon).
  Measured: the two short connections to port 22 were in no sample of the host.
- This machine's own private address, which a line cannot tell from another
  machine's. Measured: the stand-in reached its own machine's private address,
  and the line says a private address as it would for another machine.
- A connection accepted rather than made. Measured: the machine's own sshd had
  the same two connections as events with `Initiated: false` and port 22 as their
  destination (the listener's own port); NET-ADMIN-PORT does not judge them.
- A net line written before these keys: NET-ADMIN-PORT cannot judge it (partial,
  and said), and never guesses it.
- Linux has no os source: neither rule judges an os line there; a hooks file
  tool is judged by its path on any system.

What is not a finding (A-6): a file under TEMP, and a shell under a shell, are an
agent's ordinary work. They are recorded (the lines are in the tree's source) and
judged by no rule. Measured: a file under TEMP written by a powershell under a cmd
was a file line with its path, and nothing fired on it, by design.

### The registry's autostart values (PERSIST-RUN-KEY; ADR-0014 Amendment B)
Rulings: ADR-0014 AB-1 to AB-5, and Amendment C (AC-1 to AC-8). One signature
judges a value set under the registry's Run or RunOnce key by a process of a
watched tree. What was measured (a stand-in agent on a Windows machine, under
the rig's own Sysmon configuration and under a public configuration that many
use; harmless values, each undone) is the ground of what follows.

What it sees:
- Anything set below `\Microsoft\Windows\CurrentVersion\Run` or `\RunOnce` of a
  user's hive (`HKU\<SID>\SOFTWARE`) or the machine's (`HKLM\SOFTWARE`), with or
  without `\Wow6432Node` after `SOFTWARE`, in any case of letters, as Sysmon's
  event 13 names it, whatever program of the tree set it. Measured: the values
  were in four shapes of `TargetObject` - the user's Run and RunOnce, the
  machine's Run and the machine's 32-bit Run - and each event named the program
  that set it (reg.exe, powershell.exe) and its process. The machine's RunOnce,
  plain and 32-bit, are the two shapes the four imply; the pattern also holds
  the user's 32-bit view (eight shapes in all).
- A value whose name holds a backslash. Measured: Sysmon wrote its target as
  `...\CurrentVersion\Run\<part>\<part>`, the shape a value of a key under Run
  would have. The event cannot tell the two apart: the line says `nested`, the
  rule fires for both, and its sentence says that it cannot tell. The cost is a
  finding for a value of a real key under Run, which Windows is not believed to
  use (not measured on a desktop).
- Under the public configuration all five values of the first measure were
  logged, and they were the only events 13 of the 91 seconds measured.
- The line carries the hive, run or runonce, the 32-bit view, the value's name
  (redacted, at most 80 characters; a sentence shows it between double quotes,
  a double quote in it written as an apostrophe, so text an agent chose cannot
  pass for the sentence's own words), the name of the program the value would
  run (none where the value's text is not a command: binary data, a number, an
  id) and the program that set it with its parent. The target and the value's
  text are in the line's hash only, never in a finding.
- Under `raqib watch --host` each pass of a tree's os follow asks its question
  for event 13 first (at most 500 events a pass), and then the first question,
  which is what it was. Every event 13 the pass takes was so logged before the
  other question was asked, and, where Sysmon logs a process's start before its
  value (not measured), the start of the process that set it is in that answer
  or an earlier one; a value logged before its own process's start, the start
  falling in a later answer, would be passed over unsaid. Measured on the build that asked the two the other
  way round: in two of 21 runs, two of 40 values set by fresh reg.exe processes
  were never lines, though their process lines were there; the second read's
  bound had run ahead of the first's. Where the other answer is cut at its cap,
  no event 13 above its last record is taken and the registry's bound stops
  there, so the next pass reads it; where the other read fails, the pass takes
  none and the bound does not move; while the tree's root is not found yet, the
  bound does not move either. A read of event 13 at its cap is said, and one
  that fails is said as a silence and takes nothing from the pass's other lines.

What it does not see:
- Another autostart place of the registry: RunOnceEx, RunServices, a user's
  hive not named by a SID, a scheduled task and a service. Measured: about
  twenty seconds after the stand-in's values, Windows' own sihost.exe set
  values under `...\CurrentVersion\RunNotification\`, a key that begins with the
  same letters; the match is on the whole key, so they are not this rule's. A
  value under `...\Schedule\TaskCache\Tree\` is set by the Schedule service for
  every task, the system's own among them, and its value is a number, an id or
  binary data, never a command.
- A value or a key renamed into place (Sysmon's event 14): not read, not
  measured. A value's removal and a key made are event 12: not read. Measured:
  on a fresh machine the user's Run key was not there; the first value made the
  key (an event 12) and then set the value (an event 13), which is judged.
- A Sysmon whose configuration logs no value set under these keys: nothing is
  then there to read, and Raqib cannot tell that from nothing done. A
  configuration that logs every key was not measured: how many events 13 a pass
  then holds, and what the read of event 13 costs beside it, are not known.
- A hive written offline or loaded from a file: not measured.
- A value changed by a program of the system on the tree's behalf: the event is
  believed to name that program, not a process of the tree (not measured for
  the registry; the measured case is the Schedule service's own TaskCache key).
- An event 13 named by its pid alone (no ProcessGuid) is placed by the tree as
  the pass's walk ends, not in the order of time as the other events are: a pid
  reused within one pass could give a value to the wrong process. Sysmon
  writes the ProcessGuid, or an empty one where it no longer holds the process
  (seen for a parent, and once for a process that had ended; not seen on an
  event 13).
- A problem of the event 13 read (a line that cannot be read, an event with no
  TargetObject) is said once per its words for the life of a follow; a later
  problem at a line number said before is not said again. Not measured.
- Two follows that hold different starts of one process (nested trees) could
  give one event 13 two parents' names, and so two acts. Not shown reachable.
- Whether Windows runs a value under a user's 32-bit view
  (`HKU\<SID>\SOFTWARE\Wow6432Node\...\Run`), and whether Sysmon writes
  SYSTEM's own hive as `HKU\S-1-5-18` or as `HKU\.DEFAULT` (the second is not
  read): not measured. A service account's hive counts as a user's.
- A value whose name ends with a backslash: its target ends with one and is no
  line, and nothing says so. Whether Windows accepts or runs such a value is
  not measured.
- An export cut short holds nothing after its end.
- The budget was measured on no real desktop's work: no benign recording holds a
  registry line. A program the tree starts that sets its own Run value (an
  installer, an updater) would fire, and how often is not known.
- Not measured either: the commander's own Sysmon.
- Linux has no os source: the rule judges nothing there.
- Said (ADR-0014 AE-3): at the first round that reads the channel, the watch
  asks it once for its newest event 13, whatever its key (a bounded question of
  its own; the round's own question is what it was). Where it holds none then,
  that is a blind spot of the run, `registry`, said once and in the past tense
  (Amendment F): this Sysmon's configuration may log no registry value, or none
  was set under a key it logs in what the channel then held, and PERSIST-RUN-KEY
  may have nothing to read here. It is asked once a run, so a value logged after
  it does not take the sentence back: measured on a fresh machine whose Sysmon
  logs the Run keys, the watch said it for all its rounds though a value was
  logged seconds after the question (a tree's follow asks for its own values
  each pass, and that is not changed). Where the question cannot be asked or is
  not answered, it is said as not known, with the reason. Where it holds one,
  the inventory carries its time and nothing is said. The question is asked
  once: one that fails is not asked again, and the run says not known. It is
  asked inside the first round that reads the channel, after its read, with the
  round's own timeout: a slow answer delays that round's inventory and can make
  the round late; a question that did not return is ended and recorded, and the
  next round carries that record as a hole of the channel's read (named as that
  round's, which it was not), so the result is then incomplete; in a run with no
  next round no hole is made, and only the blind spot's reason says it. Not
  measured: how long the question takes on a full channel that holds none. The
  limit:
  a channel that holds some event 13 may still not log the Run keys (a
  configuration that logs other keys only), and that is not said. The certain
  cure is Raqib reading the autostart places itself (ADR-0014 S3).

### The autostart places read by Raqib itself (ADR-0014 Amendment G; M15.3a)
- **What this read does not see** (docs/specs/AUTOSTART.md; the read stands
  alone in M15.3a and M15.3b: no watch reads it and no rule judges it yet). The
  places AG-5 lists - Image File Execution Options, AppInit_DLLs, a WMI
  subscription, the policies' Run keys, Active Setup, a service's ServiceDll, a
  COM object, a hive that is not loaded (a driver is read: it is a key of the
  services) - and RunOnceEx, RunServices, a user's own Winlogon values, another
  user's Startup folder, a Startup folder on a share or on a drive whose kind is
  not known, what a link in a Startup folder leads to (not followed: it may
  lead to a share), a content beyond its first 64 KiB, and a key's values or a
  folder's files beyond 1000. What was there before the first read, and what a
  part held when it was first read: it is the base, and is never said (a part
  read late is said once as a base taken late, with its count, never its
  entries). A change made and undone between two reads, and one made and
  undone while its place or its key is not read. Who made a change: the read
  names the entry, never a process. A place the reading user's rights refuse
  (measured: the scheduler's tree under a deny-only Administrators group) is
  said as refused, never as empty; a place the read's deadline (5 s) did not
  reach is said as not read. A task's program is not read (its Actions are
  hashed, not parsed), so a task's change names no program; a program named
  from an unquoted text whose first word holds a separator, is followed by a
  blank and ends in no program's extension is said as one that `may run` - as
  is one whose unquoted first word holds a `%` (but a machine's own text that
  begins with `%SystemRoot%` or `%windir%`, AL-4: the system's root is taken as
  a path with no blank where the reader's own value of it holds none - a text
  of a user's own hive is never taken so), one that holds a blank other than a
  space or a tab, and one where more than one run of the text ends in a
  program's extension (AK-3) - and a Winlogon list of more than one program
  names none.
- **The lever that is left** (ADR-0014 AJ-2), as AK-2 and AK-6 leave it. Any process of the
  user can make its own Startup folder or Run key slow or large (many files,
  many or large values, a file slow to open). The deadline is looked at between
  keys and files, never inside one call: one listing, one key's enumeration or
  one open runs to its end, a key's enumeration reads each value whole and a
  folder's listing every name (the bound of 1000 is of the entries compared and
  64 KiB of what is hashed, not of what is read). In a read that reaches the
  slow key, the keys after it in its step and the steps after its step are not
  reached, and that is said; in a later read they are reached before it (the
  steps turn at each read, the users' hives turn once a whole turn of the
  steps, the machine's key or folder comes first), so a change in them is said
  late - where the slow keys are one user's own, within six reads for each
  user's hive loaded - by the first read that reads them whole, unless it was
  made and undone in that time, which is not said. Nothing turns inside the
  services' or the tasks' step: a slow key there delays the keys after it in
  every read, said `in part` each time (those keys are the machine's; whether a
  plain user can make one slow is not measured). A key or folder held over 1000
  entries is never compared while it is over: a plain user can do that to its
  own Run key and Startup folder, and every change in it is then unsaid but for
  the words `in part` at each read. A plain user can also deny its own Run key
  or Startup folder to a reader of another identity while Windows still runs
  them (AJ-8; not measured): the place is then read in part for good, and said.
  An agent that runs as an administrator can change what the read reads (a
  key's rights, the folder's listing) as it can any watcher of its own user;
  that is not measured.
- **Closed** (ADR-0014 Amendments I and J). An entry that first appears while
  a place or a key that was read before is unread - a Startup file its maker
  holds open without sharing across one read - is said as added by the first
  read that reads it (a held file: listed, said as added with its content not
  read); a hive loaded between two reads is one change, `hive loaded`, not its
  entries added; a part read for the first time late is its base, not its
  entries planted. The read opens a Startup file by its listed name in the long
  form, asks Windows not to follow a link, and opens with every sharing, so it
  does not hold a file against its maker's rename or delete: measured before the
  change, a rename failed 5406 times of 5406 while a 24 MB file was hashed;
  measured since, on Windows, by a test in which another call renames and then
  deletes a file while the module's own opener holds it, and by the rig's held
  file and the stand-in's delete (X37), not on a 24 MB file again. An open by
  another process that asks for no sharing still fails while the read holds the
  file, for the instant of the read (Windows' rule; not measured). A file
  swapped for a link under the same name, or a link for a file, is said as
  changed whether or not the content of either was read (AK-4, AL-3). Every hash
  is salted, so a key cannot be matched by trying a SID, and a read of another
  salt is not taken.

### The host watch (`raqib watch --host`; ADR-0007, Amendments P and R)
Rulings: ADR-0007 Amendments C, H, I, M, N, P, R, T, V, X. True of the
tree as P-1..P-4, R-2..R-9, T-2..T-8, V-1..V-6 and X-1..X-9 leave it (R-1
is amended by T-2, T-1 restated by V-1).
- **What a round sees.** One sample, and on Windows with Sysmon the
  channel's events since the previous round (ADR-0007 P-4, below): on
  Windows one read of the OS API
  (processes and their parents, TCP connections with their owner) and,
  where an administrator runs a live watch, the kernel's tracing of each
  connection's bytes, on
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
  the ancestor and writes every event of its tree, the agent's too; it
  marks (`input_meta.under_root`, the root's pid) each event at or under
  the root of another tree the watch holds with an os follow of its own,
  the root told and matched by its ProcessGuid, while that follow lives
  (read when the ancestor's follow asks); which events are under that
  root is the ancestor's follow's own reading of the channel, each
  member's parent by ProcessGuid (the round's process sample names no
  parent). The root's own creation is not
  marked and stays the ancestor's act; a marked line gives the ancestor
  no act, no talk and no destination, and is judged by the other rules
  as before (one act, judged once). What the mark costs: a marked line
  whose twin the other tree's file does not hold - the other follow's
  last interval before it stopped, a follow that died, a member the other
  follow never knew - gives no beat to either tree, so the rhythm of an
  agent's last seconds can be missed (its commands are still judged where
  they are written); a process born under the root before the root was
  told is marked from then on (the follow's own parents tell); a root with
  no ProcessGuid is not told, and the ancestor then counts its child's
  commands as before (on Windows with Sysmon, the same false cycles
  there), as it does those of a process whose creation its follow did
  not read or whose parent the event names by pid alone (the chain of
  parents breaks there, and nothing under it is marked); every os follow
  under the host watch keeps one more map, each member's parent by
  ProcessGuid, for the life of the follow. The mark is the os follow's
  own: the key on a line of any other source silences nothing (a hooks
  trace is the watched side's to write). The
  agent's acts with no talk seen make no cycle, so
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
  round is said); a kind of event 1, 3, 11 or 22 not read after three rounds
  (Sysmon's configuration: Raqib never changes it, A4) is said once and
  the report lists the kinds read; where neither a start time nor a
  ProcessGuid tells two processes of one image under one pid apart, they
  are one tree. Linux (its process events give the round the children of
  a tree that talks at a sample; a tree that lives whole between two
  samples is not seen) and a Windows host without Sysmon keep the whole
  hole, said once: a `hole:`
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
- **A reused pid is not a parent (ADR-0007 Amendments BE and BF).** What a
  reused pid could do: Windows keeps a dead parent's pid in its children
  for as long as they live, and gives that pid to a later process. The
  watch leaves out its own tree (its pid, its launchers and every process
  under them), so a watch given the pid that the dead parent of the
  system's first processes had became, by pid alone, the parent of the
  whole machine: it saw no tree, said nothing, and ended NONE-SEEN, exit 0
  (two field runs). The same pid, taken by any process, made it the
  parent of an older orphan, so that orphan's acts went to it. What is now
  proven by dates: a process is the child of the holder of its parent pid
  only where that holder did not start after it (both starts read from one
  source: any later start breaks the link; from the sample and the
  channel's event 1: only a difference above 2 s does); a broken link
  leaves the child with no parent in the round, for every walk of parents
  (the watch's own tree and line, a child's nearest talking ancestor, an
  act's path, the act roots). The watch's own tree is made only of links
  whose two starts were read, and the Windows reader names as its
  launcher only a process whose start and whose child's start were read
  and in order: a process under the watch's pid whose start, or whose
  parent's start, was not read is judged as any other. The links broken
  are said in the inventory's holes, each as the child's pid under the
  parent pid ("the reader's own pid" where the younger holder is the
  watch or its launcher). What is left: a link whose two starts are not
  both read is kept as before, so a reused pid there still takes an
  orphan's acts. It is counted in the holes on a round whose reader dated
  at least one link (a live round), and a process that hangs under the
  watch's own pid by such a link is named there; an export whose
  CreationDate is a local text dates no link, and says nothing of them
  unless a process hangs under the pid its snapshot line names as the
  reader's; a Sysmon export read by `raqib discover` (the channel not
  read) dates no link by its event 1 times. On Linux the kernel gives
  every orphan a living parent, and the start ticks date the links where
  the snapshot carries them. Also left, and not yet answered: a start is
  the system's wall time on Windows, so a clock set back between a
  parent's creation and its child's breaks a true link (said in the same
  hole, in words that say what was read: the holder of the parent pid
  started after the child, a pid taken again or a clock set back between
  the two; the watch is marked there as the child of such a link as well
  as its parent); some of the system's first processes carry a start
  earlier than their parent's and are broken from it on every round (they
  neither talk nor act).
- **The watch's own tree is what the watch started (ADR-0007 Amendment
  BH).** What it took for its own before: its pid, its launchers, and
  whatever stood under them by dated links - so the other children of a
  launcher (a Python harness that starts the watch and an agent beside
  it), a process whose creator named the watch as its parent (the parent
  is a field the creator fills, and the same user may fill it), and, after
  a clock set back by more than the watch's age, an old orphan of a dead
  holder of the watch's pid were all left out unseen. How it is proven
  now: the watch records every program it starts (the channel's reader,
  the notifier) by its pid, the time and its image (the basename of the
  launcher's args[0]), in the statement that starts it (a test reads the
  code for a start without the record); the live readers write the
  recorded pids alive in their sample beside the reader's own pid (a pid
  the sample holds with a start outside its record's time, or under an
  image that is not the one recorded, is another process and is not
  written - the identity is pid, time and image, not pid alone; ADR-0007
  BI-2). The watch's own
  tree is then the reader's pid; each launcher the reader names, proven by
  the dated links up from it, itself only; each recorded helper whose start
  was read and is not before the reader's; and what those helpers started,
  by dated links. Anything else under the reader's pid or a launcher's,
  whatever its image and its dates, is judged as any other process and
  named in the inventory's holes, as is a recorded pid whose start does not
  prove it. No walk of parents passes through the watch's tree: a process
  that hangs under it, by any link, has no ancestor through it, and no
  member of it owns an act, a file write or a tree - so the watch's own
  model call never makes it a candidate, and an orphan chain hung under its
  pid by links not dated gives its acts to nobody above the watch. What is
  left: the record lives in the watch's memory only, so a watch started
  again does not know the helpers of the one before (one still running is
  judged as any other); a program started by a helper is taken for the
  watch's by its dates, so a process that names a helper as its parent and
  starts after it is left out with it; a pid freed by a dead helper and
  taken again within the two seconds after the record AND under the very
  image the watch started is still taken for the watch's own (identity is
  pid, time and image, not more, until a start the watch can bind to the
  child it created; ADR-0007 BI-2) - a reuse under any other image, or
  outside that window, is judged as any other and named; past the record's
  bound (256 entries) the oldest recorded pid is forgotten even if it is
  still alive, so a long-lived helper evicted by many newer starts would be
  judged as any other - the recorded helpers are short-lived, so this is a
  backstop, not a path seen in practice (ADR-0007 BI-4); the record and the
  snapshot line are forward-only, so an older build cannot read a newer
  snapshot line and loses that sample's reader and launchers (cross-build
  mixing is unsupported; BI-4); ss (the Linux connection reader of
  last resort and the byte counter) is started without the record, because
  the call that starts it gives no pid: it runs and ends inside that call,
  in the thread that takes the sample, and one seen running under the
  watch's pid is judged as any other and named; a sample with no record (an
  export, a text written before the record) keeps the tree of dated links
  described above, and the hole says the record was not there wherever that
  tree took a process beyond the reader and its launchers; the `raqib
  os-sysmon` and `raqib doctor` commands start their programs without the
  record (each is a command of its own and takes no process sample).
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
  cut being a hole; before it, the follow asks one of its own for event 13
  (at most 500 events 13 a pass, of any key; only a value set below the
  registry's Run or RunOnce key is a line), and a value logged after a cut
  of the other answer waits for the next pass. A follow attached again is given the tree the
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
  an `ss` that has not returned in 30 s). On Windows a live watch run by
  an administrator starts one tracing session of its own and stops it at
  its end, and stops the sessions killed watches of Raqib left; no other
  session is touched. `raqib watch` and the window write under ~/.raqib and nowhere else,
  and the hook settings of a project only with `--attach-hooks`. Outside ~/.raqib Raqib
  writes only by an explicit command: `raqib forward --to journal:` hands the events to the
  system's journal because a person ran it, and `raqib forward --to eventlog:` hands them to
  the Windows event log (the Application log) because a person ran it. Nothing is installed,
  registered or switched on by either, the watch never does it on its own, and the watch, the
  capture path and the events file are not touched by them (ADR-0011 W-0, Y-1).

### The forwarder (`raqib forward`; ADR-0011 Amendments J to N)
A forwarder is a process of its own that reads the watch's events file and
sends every whole line to one collector, over HTTP or over syslog, or
hands it to the system's own journal or to the Windows event log
(docs/specs/FORWARD.md). The
watch does not know it runs: nothing of the capture path imports it, and a
collector that is slow, down or refusing never delays or loses a capture
(the lines wait in the file). What it adds to this model:

- **The token.** The collector's token is a secret on the host, in a file
  the person names (`--token-file`), read at every try. It is never
  an argument (so it is not in the process list), never read from the
  environment, never in the forwarder's state, output or errors, and an
  error never quotes the collector's answer. An error of the system at the
  start (the directory or the pid file cannot be made) is a usage error
  with its reason, an error it did not foresee is said by one word, and a
  state it does not write - whatever its JSON holds: a value of a type it
  never writes, JSON nested past what the reader takes - is read by the
  status as unreadable and refused at a start: no traceback is printed by
  the forwarder or its status. Off Windows a
  token file that others can read is refused; on Windows its access is not
  checked. Anyone who can read that file as the person can send to the
  collector as Raqib: a forged event at the collector is as good as the
  file's protection. The URL is an argument, and arguments are on the
  process list: a credential must never be put in the URL's query.
- **The wire.** https is verified - the certificate and the host name -
  against the system's authorities or the `--ca` file, and no switch turns
  that off. Without `--ca`, the system's authorities are the ones the
  forwarder's own environment names: OpenSSL reads SSL_CERT_FILE and
  SSL_CERT_DIR, so whoever sets that environment chooses whom the
  forwarder trusts. The forwarder never writes TLS secrets: SSLKEYLOGFILE
  is not honoured, so no key log written beside it can decrypt the
  Authorization header from a capture. The environment's proxies are not
  used and a redirect is a failed send, never followed. Plain http is taken
  only to a loopback address unless `--plain` is given, and then the state
  and the status say plain: every event crosses that network in clear
  text. One send is bounded whole (10 s from its start to connect, name
  resolution and the handshake included; 30 s to send the request; 30 s
  for the whole answer from the request's last byte): a collector that
  trickles its answer, or reads the request slowly, cannot hold the
  forwarder, and a send that is late (its request or its answer) makes
  the next batch half as many lines, down to one, while a send taken
  doubles it again: a slow collector is not sent the same batch for ever.
  The state is written at least once a beat whatever the forwarder is
  doing - a long send, a long try, a walk through one line or tail of any
  length, looked at in pieces with Stop at each - so its status says what
  it does, not what it did before. Name resolution is the system's: a resolver that
  never returns keeps the thread of that send (its body and headers, the
  token among them) until it does; at most four such sends are out, and
  then no send starts and the forwarder is failing `stuck` - an alarm, not
  a growth without end. An abandoned send's sockets are shut down and left
  to its own thread, never closed under it.
- **The journal.** `--to journal:` (Linux) hands each line, as an entry
  of the journal's own protocol, to the system's journal socket, from the
  user's own process with no rights (ADR-0011 W). What goes there is read
  by whoever reads the journal: root, the journal's and adm's groups, and
  the user's own; and the journal may pass it on (to a syslog daemon, to
  another host): the events then leave the host by the system's hand, not
  Raqib's. Any local process of any user - the watched agent is one - can
  write entries that say raqib (the journal's socket is open to all):
  SYSLOG_IDENTIFIER and the RAQIB_ fields prove nothing. The journal's own
  trusted fields say who wrote an entry, and a reader of the journal must
  ask them; but an agent that runs as the same user under the same Python
  differs from the forwarder only in `_PID`, and the forwarder's pid is
  kept in a state file that agent can rewrite. So an entry in the journal
  that says raqib is a lead, not a proof: the watch's own events file and
  its record are the proof, and a forwarder run as a unit of its own (with
  the service, later) is what will give its entries a unit nobody else
  has. The journal
  answers nothing (`sent`): it may drop entries over its own rate limit,
  unseen by the forwarder, whose status stays OK; that limit is counted
  for a unit or a session, so a watched agent in the forwarder's own
  session may use it up and have raqib's entries dropped. The forwarder paces
  itself (at most 250 lines a second); what tells of a loss is the
  journal's own line of suppressed messages and the search for a missing
  heartbeat. No journal (no socket) is a collector that is down: failing
  `connect`, tried again, nothing passes.
- **The Windows event log.** `--to eventlog:` (Windows) hands each line,
  as an event of the Application log under the source `Raqib`, by the
  system's own call (ReportEventW), with nothing registered: no key is
  written and no message file installed (ADR-0011 Y). Whoever reads the
  Application log reads the events (by default any signed-in user). Any
  process can write events under the source `Raqib`: the source's name is
  nobody's, only the record's own process id is the system's word, and
  the forwarder's events carry no user, so an event that says Raqib is a
  lead, not a proof (as an entry of
  the journal that says raqib is); the watch's own events file and its
  record are the proof. The Application log is bounded and overwrites its
  oldest: Raqib's events push other programs' out, and are pushed out -
  the watched agent can do it on purpose, any process writes to that log,
  and an administrator's process can clear it. The forwarder sees neither:
  what tells is the reader's search for a host with no heartbeat for more
  than two beats. The forwarder paces itself, at most 100 events a second
  over its batches (the parts of a long line counted); a log of Raqib's own is an install's work, later. Taken is
  `written`: the system's call said the log took every event of a batch, not
  that the event is still there. A source that cannot be opened is a
  collector that is down: failing `connect`, tried again, nothing passes; an
  event refused is failing `write`, nothing passes, and the next batch is
  halved.
- **Syslog.** Over `syslog+udp://` and `syslog+tcp://` every event is
  clear text over udp and tcp: any host on the path reads it whole, and can
  change it or drop it, and over udp can send datagrams with the host's
  address as their source; nothing in a message proves where it came from.
  The forwarder therefore takes them only to a loopback address unless
  `--plain` is given (a collector on the same host, or a relay there), and
  then the state and every status say "plain: not encrypted". Over
  `syslog+tls://` the wire is verified exactly as https is (the certificate
  and the host name, the system's authorities or `--ca`, no switch to turn
  it off, no key log). Syslog carries no token: a syslog collector cannot
  tell Raqib's messages from anyone's, so anyone who can reach its port -
  any process on its host for a loopback collector - can send forged
  messages in Raqib's shape; the collector's own access rules (who may
  reach its port) are the only answer - the forwarder presents no
  certificate of its own, so a collector that asks one refuses it, and that
  refusal is a failed send - and the forwarder sends no token there, so
  none can leak. Syslog answers nothing, and each delivery word says only
  what it can: over udp a batch counts as taken when its datagrams were
  sent (`sent`): over udp to a collector that is down every line is `sent`
  and the status is OK - only the collector's own search for silence tells.
  Over tcp and tls a batch counts as taken only when its connection ended
  in order (`written`): the forwarder ends its side and reads to the
  collector's end (over tls it sends its close and reads the collector's);
  a reset, an alert, an error or no end within the bound is a failed send,
  and the batch is sent again. `written` is an orderly end, not a stored
  event: a collector that read the batch and then lost it, or ended in
  order without keeping it, loses lines the forwarder counts as taken. An
  end is an end as the forwarder saw it: a collector that died or closed
  while a batch's last bytes were still on their way, and whose end reached
  the forwarder before its reset did, is taken with lines it never read
  (over tls an end with no close of the collector's, and a close that came
  before the forwarder's own, are failed sends); syslog has no answer to
  close that gap, HTTP has. A
  message may be cut by a collector at its own limit, and with `--framing
  newline` a line that holds a bare CR may be split by a collector that
  breaks on it. The heartbeat search on the collector's side is what tells
  it. A line longer than a datagram is refused locally, never cut. The
  forwarder cuts no message; a send that fails in the middle may leave
  part of a message at the collector, and the batch is sent again whole. No line ends the
  forwarder: a field of an event that cannot be a header field (a time in
  other digits than ASCII, a host or kind too long or with a space) is `-`,
  and the line is still the message whole.
- **What the collector learns.** Everything the events say (A-4: the whole
  judgement, not only what knocked): the host's name, each run, the trees
  with their images, pids and paths, each finding with its rule and
  evidence, the holes and blind spots, and a heartbeat a beat; nothing the
  trace does not already hold, and nothing of the token but the header it
  checks (a syslog collector: no token at all; besides the event, each
  message's header repeats its severity, time, host name and kind, and the
  facility the forwarder was given). It learns when the host watches and
  when it stops. Of the
  collector the forwarder reads only the status of its own send (and, in
  the hec shape, the answer's code; over syslog nothing: what a collector
  sends before its end is read and thrown away): no command, query or configuration
  comes back.
- **What a delivery is.** "Taken" is the collector's word: a 2xx (and in
  the hec shape the code 0) moves the cursor. A collector that answers 2xx
  and drops the lines loses them, and the forwarder cannot see it. A line
  the collector refuses alone is passed only when it is refused alone
  twice with a later line taken between: a collector that refuses
  everything (a wrong path, a missing channel) moves nothing, and the
  forwarder is failing `refusing`; a refusal that would not come twice (a
  node behind a balancer, a 400 of a moment) passes nothing; a collector
  that refuses one kind of line does not stop the lines of another kind
  after them. Delivery is at least once: after a restart, a refused batch,
  an answer that came too late or a file that changed under the cursor,
  the collector gets lines twice (`watch.host` and `id` tell them apart).
  The order at the collector is the file's except for a line in question
  taken when asked again (it arrives after the later line that proved the
  collector), a send answered too late and sent again, and a send
  abandoned that still arrives: `n` orders the lines of a run.
- **What an attacker on the host can do.** Stop or kill the forwarder: its
  state is then older than two beats (`raqib forward --status` exits 3) and
  the collector sees no heartbeat of the host for more than two beats,
  which is the one search the guide gives a SOC. Write to the events file:
  a line that is not an event is skipped and counted, but a well-formed
  forged event is sent as any other (the forwarder checks the shape, not
  the truth). Well-formed events of a kind the collector refuses each cost
  two sends a line (asked alone, then again after a later take), keep the
  forwarder `refusing` while they wait, and fill the latest 50 refused ids
  with theirs; the lines after them still go, with no wait between tries
  that move. A file whose first 4096 bytes (of them, what the cursor has
  passed), length or last line passed changed is another file: read again
  from its start and counted as a restart, the cursor at 0 included. A file
  cut to the cursor, or changed only after it, has what the forwarder held
  after the cursor given up: those lines are asked again as new ones, none
  counted refused on another file's answers. Change only lines between the
  first 4096 bytes and the last one passed: the forwarder checks the head,
  the length and the last line passed, not every byte, and does not see
  that.
- **The watched account.** Where the forwarder runs as the watched account
  (as it does until it runs as a service), that account can write its
  files in `~/.raqib/forward/`. The cursor: a forged offset with the
  sha256 of a later line (the account can read the events file) makes a
  restarted forwarder skip the lines between, with no restart counted (an
  offset above 0 with no hash is refused as a damaged state). The
  state: a fresh time keeps `--status` at 0 for a forwarder that is not
  there. The pid file: a live pid written in it keeps the name from ever
  starting, and the pid of a process that lives, written over a running
  forwarder's, ends that forwarder (exit 1) at its next state write. A pid
  file removed, or holding a pid no process has, is only written again
  (and said); one that cannot be read for a moment is read again at the
  next write. A line far longer than a request is
  never read whole, so a writer of the file cannot fill the forwarder's
  memory with one line. The answers are the search on the collector's side - which is
  judged by the collector's own clock of arrival, never by the event's
  `time`, the host's clock that the same account may set (EVENT.md says
  the same of any reader) - and a forwarder under another account (the
  service, later).
- **The window reads the states.** The window's Link screen reads the states
  in `~/.raqib/forward/` by the reader and the judgement `raqib forward
  --status` uses, at most once a second and off the window's thread; it
  starts, stops and configures no forwarder, holds and shows no token and
  opens no connection, and no result, exit code or finding of a watch
  depends on it. A state's text is a stranger's: it is shown as text, at
  most 300 characters of a line looked at and what is not printable shown
  as "?", and nothing of it is drawn as markup, opened or run. A writer of
  the state folder - the watched agent can be one, it runs as the same
  user - can therefore make the Link screen say a bounded untrue thing
  about a forwarder, and can make the reader work: at most 64 states of
  1 MiB are parsed, off the window's thread, and the next read waits four
  times what the last one took. It cannot hide a forwarder that fails:
  every word that is not OK is counted on the rail, none behind a worse
  one, and a forwarder known to fail keeps the link an alarm whatever
  stands beside it. What it can do is add false ones, or remove a state
  (ADR-0011 Amendments R, T and V).

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
- **Editing the events file (ADR-0016 H-5, Amendment A).** Every line the
  host watch writes to `~/.raqib/host/events.jsonl` names the line its run
  wrote before it by that line's sha256 (`prev`; a run's first line holds
  `first`), and `raqib events FILE` checks each run's chain (a run is its
  host and its run word).
  - What it proves: within a run, a line taken out of the middle, changed,
    added or moved is seen by anyone who holds the lines (the line after it
    no longer names the one before it), but the run's last line: no line
    names it, so changed, or followed by a line added after the run ended
    that names it, it is not seen from the file alone (HA-4). A line that
    names the same line as the one before it is said as a line beside the
    chain (a line the writer did not count as written, or one put there by
    another hand). A run whose lines hold no `prev` while their version is
    one that always writes it is said as a chain taken out (HA-2).
  - What it does not prove: the chain holds no secret. Whoever can write
    the file can cut its end, or write a tail again from any line and
    compute the hashes again; the file alone then looks whole, and a test
    of each case says so. A run of an older build has no chain at all, and
    a version is the line's own word: whoever removes every `prev` of a run
    and writes its lines' version again as an older one makes it read as an
    older build's, not as a chain taken out. A file whose line ends were
    all changed to Windows' checks as it did before.
  - What a collector that holds a later line can tell: over the file alone,
    nothing more - a tail written again is whole by itself, and so are the
    collector's own lines. Side by side it can: `raqib events FILE --against
    OTHER` looks for each line the collector holds (OTHER, its own export)
    in the file by host and id, and says which are not there and which are
    there with other bytes (exit 1). It needs the lines as they were sent,
    byte for byte; a file changed only after the last line a collector
    holds is not seen.
  - Under the service the record is root's and the watched account cannot
    write it; a chain keyed by a secret that account cannot read is a later
    stage, recorded and not built.
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
- **The service (`raqib service`; ADR-0013).** On Linux an administrator may
  run the host watch as a unit of the system's, `raqib-watch.service`
  (docs/specs/SERVICE.md). It changes three things.
  - Who can stop it: the watched agent, running as a person without rights,
    cannot stop, restart or change a unit of the system's. Root can, and root
    is also any user with sudo (a password it knows, none asked, or a ticket
    still valid) and any user a polkit rule lets manage units: an agent
    running as such a user can stop it. Such a user can also change the
    unit or Raqib's code. A change of the unit shows in `raqib service
    status` (NOT AS INSTALLED: the file's whole text, where systemd loaded
    it from, its drop-ins, a file changed and not reloaded); a change of
    Raqib's own code after the install does not.
  - Who can write its record: the service writes under /var/lib/raqib,
    root's alone (mode 0700). The agent cannot write its events or its
    record again, and turning a rule off in its user's ~/.raqib turns
    nothing off in the service, which never reads a user's ~/.raqib.
  - Who can hide: the service reads every user's processes and sockets, so
    an agent that makes itself another user stays in its sight. An agent in
    a network namespace of its own (a person can make one where the system
    lets users make namespaces) holds sockets the watch, in the host's
    namespace, may not see: not measured.
  What it costs:
  - Raqib's code runs as root where the service is installed, so a defect
    in it is the system's. The unit's hardening (no new privileges, the
    system read-only, two capabilities, no address family but unix and
    netlink) narrows such a defect; it does not remove it. As the kernel's
    rules read, not as measured, the two capabilities still open this much
    to a defect in the watch: CAP_SYS_PTRACE lets it reach other processes,
    root's own included, and read and change their memory; CAP_DAC_READ_SEARCH
    lets it read every file and list every folder, whatever their modes.
  - A watch made to exit comes back: the unit restarts it 5 s after any end
    but systemctl's own stop (Restart=always), whatever its exit. Each time
    is a gap in what the watch sees, and systemd counts them (NRestarts,
    which `raqib service status` says). A user who can make the watch exit
    can make such gaps again and again. A stop after a finding reads as
    failed to systemd, since the watch's own exit is 1 then; `raqib service
    remove` clears that state of the unit it removed.
  - The service serves no page. Its watch runs with --no-page and opens no
    listener; the unit allows no address family but unix and netlink, and
    denies every IP address. So no person and no agent reads root's view of
    the host over a port, root parses no user's request, and there is no
    port for anyone to take first. What the watch writes to its output goes
    to the system's journal, which root and the groups the system gives the
    journal to can read: whoever reads the journal reads the findings' lines
    the unit prints.
  - A unit that runs a file a user can write gives that user the system.
    So the install refuses an interpreter run without its site, one that
    reads PYTHONHOME or PYTHONPLATLIBDIR from its environment, a raqib that
    is not directly in that interpreter's own site folders, and a *.pth file
    holding a byte outside printable ASCII, tab and the two line ends; and
    it refuses unless the interpreter, its pyvenv.cfg, every file and folder under each
    entry of sys.path and under each path its *.pth files name, the raqib
    package, systemctl, ss and the unit's folder, and every folder above
    each of these, are root's and writable by nobody else; it says which
    path is not, and how many paths of which kinds it checked. A path that
    does not exist is checked as far as it exists; one under a place the
    system makes for a user (a login's run folder, a mounted medium, a new
    home) can become that user's. What a *.pth file's import line reaches
    that is not an entry of sys.path, and the environment it runs in, are
    the unit's and are not walked. The unit's drop-in folders are root's by
    default and are not walked; a drop-in that is there shows in status.
  - Not checked: the shared libraries the interpreter and its extension
    modules load (libpython and the libraries they name). They are found by
    reading those files, not by where they are.
  - The check guards the unit's starts, not the install itself: an install
    run from code a user can write has already run that code as root before
    it refuses. The check is made when it installs, not afterwards.
  - ACTIVE, as `raqib service status` says it, says the unit runs, not that
    the watch writes its record: a blind or a stuck watch is still active.
    Reading what the watch writes is a later stage's.
  - Two watches may run on one host, the service's and a person's own. They
    do not know each other, and each writes its own record.
  - A watch a person runs as themselves keeps every limit this model names.
  `raqib service install` and `raqib service remove` write and remove one
  file outside ~/.raqib, the unit in /etc/systemd/system, because an
  administrator ran them (ADR-0013 A-4). They ask for no elevation, and the
  watch never runs them on its own.

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
