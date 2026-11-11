# Raqib — رقيب

An external watcher for AI coding agents. Raqib records what an agent does,
judges it with deterministic rules first, and lets a model raise suspicion,
never acquit.

## Install and watch
```bash
git clone https://github.com/omanras/raqib ~/raqib
pipx install ~/raqib          # or, in a venv: pip install ~/raqib; puts `raqib` on PATH
raqib doctor ~/my-project     # one line per check, OK, MISSING or UNSURE; exit 1 if anything is missing
raqib watch ~/my-project      # then use Claude Code in ~/my-project as usual; Ctrl-C ends the watch
```
You need Python 3.11 or newer and Claude Code. Raqib itself is stdlib only and
is not on PyPI. On Windows: `pipx install C:\path\to\raqib` (or
`py -m pip install C:\path\to\raqib`), then `raqib watch C:\path\to\project`.
On Windows the path rules judge drive (`C:\`) and UNC paths (`\\server\share`, recognised by its two leading backslashes only) in any ASCII case, with `\` or `/`; the forward-slash form `//server/share` is read as a POSIX path (a hole), `/mnt/c/...` (WSL) and `C:\...` are different paths, and `--root /x` means `\x` on the current drive.
Install on the side that runs the agent (Windows or WSL), not both.

## Watch a project
`raqib watch /path/to/project` installs the hooks, keeps the trace outside the project (by default under `~/.raqib/traces/`), takes the rules' scope from the project's `HANDOFF.md` when there is one, serves the read-only page on 127.0.0.1 and opens it once. The page reloads itself every `--refresh` N seconds (default 5) and runs no script: a band (WATCHING, SILENT for N s, AGENT GONE or CAPTURE FAILED, with notifications on or off, the trace and the last line's time), the alarms, the findings by severity, the live silence windows in the timeline, the other watches listed in `~/.raqib/watches.json` (a GONE row is kept; any process of yours can write that file), and a discover tab when `<trace dir>/discover.json` (`raqib discover --json`) is there.
High findings knock once settled, as do silence (no trace line for `RAQIB_GAP_SECONDS`, default 60 s), capture failures and trace holes: OS notifications, one per rule per minute; lines already in the trace when watch starts are history, shown but never knocked; `--no-notify` or a set `CI` turns the knocks off.
Ctrl-C, or a crash, prints the final report; `<trace>.watch.json` keeps the findings, the silence windows, the holes and a heartbeat ([ADR-0005](docs/specs/ADR-0005-one-command-watch.md)).

## Doctor
`raqib doctor [PROJECT]` says in one screen what `raqib watch` needs and is
missing: one line per check, OK, MISSING or UNSURE, and exit 1 if any line
is MISSING. It checks Python (and on Linux and macOS `python3` on PATH, which
the hooks run), `claude` on PATH and its version, the project's hook
settings (installed; foreign: a Raqib entry of another checkout or install;
or missing), the notifier, tkinter (for `raqib app`), Sysmon on Windows, the host
(whether `raqib discover` can read this host live: on Windows the three
APIs it reads resolve, "names: no" when only the DNS cache's is missing),
and whether the trace can be
written. It is read-only; the only program it runs is `claude --version`,
by absolute path (in an empty temporary directory, the only thing it
creates).
If the installed package moves on Linux or macOS, the hook command's own
`|| echo` prints one `RAQIB-SILENCE:` line, because `capture.py` is gone.
If the venv moves on Windows, the hook names its `python.exe` by path, so
Claude Code shows a hook error and no `RAQIB-SILENCE:` line is printed.
Either way doctor shows the hooks as foreign, and `raqib watch` replaces them.
A check that cannot be made on this host is UNSURE, counted apart and never a failure: today the Windows trace line, which says "not checked" because os.access cannot tell there and doctor writes nothing to find out.

## Watch the host
`raqib watch --host [--every T] [--rounds N]` watches the machine, not a project: every T seconds (default 10) a read-only round of `raqib discover`; nothing is installed and no project is touched.
A tree that starts to talk and act knocks once as NEW-AGENT, or NEW-AGENT-UNKNOWN when the catalog does not name it ("host, <image> pid <n> (named|unknown)"), except an unknown tree that is a candidate only by what the Sysmon channel gave: it is listed `by the channel`, not knocked (M7.9, below); trees that are candidates at the first round's sample (there at the start) and listed benign programs are listed, not knocked; a footprint that is dark - no candidate or act-root links to it, an unknown tree listed by the channel and not knocked taken away - for 3 rounds is AGENT-DARK-LIVE.
Each round prints one line, "NO AGENT SEEN" included; a reader not back in 2 x T is a hole and a knock; the record is in `~/.raqib/host/` ([ADR-0007](docs/specs/ADR-0007-the-host-not-the-name.md)).
Every tree gets a source that only reads, by itself: the os source (Sysmon) where the channel exists, else the host's own record of its children and connections, judged by NET-TOOL and DESTRUCT-CMD; its findings show on the tree and knock.
`--attach-hooks` (the window: "attach hooks to Claude Code projects", off by default) also installs `raqib watch`'s hooks into the project a Claude Code tree works in: that settings file is the only thing ever written into a project, and only with that word.
A tree with no source at all for two rounds is HOST-UNWATCHED (high).
An unknown tree is also judged by its rhythm: HOST-RHYTHM (medium) when it talks to one destination and then starts a child within 30 s, 3 times in the last 10 rounds (the thresholds are in its YAML; on Linux the bytes per connection are recorded from `ss -tinp`, on Windows they are not read, a hole said once).
`--suspect BACKEND` (ollama[:MODEL], anthropic[:MODEL]; the window: "suspect unknown trees", empty by default) hands each unknown tree's host record to the suspect layer every 10 rounds: it may raise suspicion, which is a finding of the tree, and never acquit (A2): "benign" is no finding.
What is sent is hashes and program names only, and that call is the only network call of the watch, never made by the reader or any capture.
A footprint dark for 3 rounds after its own tree was live in this watch is the agent's normal end: it is listed as "dark after a live tree (note)" in the report, the page and the window, never knocked and never an alarm; only a footprint never live in the watch is AGENT-DARK-LIVE.
HOST-RHYTHM takes its beats from every source a tree has (the host's children and connections, Sysmon's process and network events with their own times, the hooks' Bash calls), and the final report lists every knock of the watch with its title, rate-limit id and status (KNOCKS).
Since M7.9 the hole of what lives between two rounds is narrowed where Sysmon is read, not closed: the live reader (the CLI's and the window's alike) reads the channel from the moment it is made, and each round reads the events 1, 3, 11 and 22 since the previous round (one bounded wevtutil of Raqib's own, at most 2000 events) into the same discover run as its sample, so a tree that starts, talks, acts and ends between two rounds is a tree of that round, listed as `brief` (seen in the channel, not at the sample) and sourced by pid and ProcessGuid. A brief tree the catalog names knocks NEW-AGENT each time; an unknown tree that is a candidate only by what the channel gave is listed `by the channel`, sourced and judged by its acts, but not knocked, and it neither makes a footprint live nor takes its link from a tree that holds it (a footprint's state is the one it has with such trees taken away; ADR-0007 AC-1): the report counts such trees by image path (one per tree, however many rounds it is listed; by name where no path was read) with the five latest cited, until a field run measures them, and a watch whose only news is such trees ends CLEAN with "N tree(s) listed, none knocked; M unknown tree(s) seen a candidate only by the channel, listed and not knocked" (exit 0); an unknown tree that is a candidate at a sample knocks NEW-AGENT-UNKNOWN as before. A ProcessGuid joins a tree seen before only when the records tell: the starts agree, or every event of the guid lies within that tree's life, from its start (or its first sight, where its start was unread) to its last sample, this round's when its root is in it; within one round's discover run a guid never joins a sampled process whose start was unread. A read that fails, times out, reaches the cap or lags by more than a round is a hole of its round; a stopped or cleared channel is said in the third of three rounds in a row that each sampled a process created a round earlier and read no event 1 at all, and then its read restarts - on a quiet desktop it is not said, a hole that remains; an image whose event 1 does not come while others do is a note (left out by its configuration, or late), withdrawn when an event 1 of that image comes and said again at its next miss; a kind not read after three rounds (no event 1, 3 or 22) is said once, and the report lists the kinds read. On Linux, and on Windows without Sysmon, a tree that lives between two rounds is not seen, and the watch says so once: in its first lines where its own check at its start finds no Sysmon, else in round 1's line when the live reader's own check finds none. Since M7.8 an os process line carries its image name in discover's form (`input_meta.image`: `curl.exe` -> `curl`), so NET-TOOL and DESTRUCT-CMD judge the programs Sysmon saw the tree start as they judge the host's children, Windows programs included (bitsadmin, plink, vssadmin, diskpart and the like); a cmdlet, a shell builtin, a renamed copy and every argument stay unseen.
A tree whose root process is still in the round's sample and is not in the round is `quiet (its root alive in round N; not seen talking with an act at the sample; source kept)` ("source kept" only when its source runs), neither gone nor back; it is gone only when its root process is not in the sample, and a round whose connections were not read says `not judged this round (connections unread)`. A benign tree (Windows Defender's engine under its own directories included; a copy elsewhere knocks) is `benign (its acts are noted, not knocked; its rhythm is judged)`: sourced, its catalog findings listed under "on benign trees (noted, not knocked)", never an alarm; an os event from before the watch's start is history, never knocked; one event read by several nested trees is one finding, on the nearest tree that is not benign (a note only when every tree that read it is benign), knocked at most once, the same in every order of arrival.
The watch only watches: it stops nothing, and what lives between two rounds is a hole, narrowed where the round reads the Sysmon channel and only while it delivers ([docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), "The host watch").

## The window
`raqib app` opens on the host ([ADR-0007](docs/specs/ADR-0007-the-host-not-the-name.md) decision 5): one look at this machine lists the agents found on it, and "Watch this host" runs the watch of `raqib watch --host`, with its knocks and, at Stop, its final report.

What you see ([ADR-0009](docs/specs/ADR-0009-the-window-a-person-likes.md)): a dark rail on the left with the name, what is being watched in words, Host, Project, Rules and Log, how many rules are off (red while an off rule would have fired), Open page, and the sentence Rules decide; a model may only raise suspicion. On the right, every screen starts with its verdict in one sentence ("2 trees on this host", "Watching this host"), a pill with the level's word (clean, alarm, incomplete; green, red, amber, as the exit codes 0, 1, 3) and the screen's one blue button; every green state of a watch says "Not a clearance.". Under the host's verdict the round strip is the watch's rounds as small squares, newest at the right - green read with nothing new, red with a finding, an amber outline not read or late - with its words ("40 rounds: 36 clean, 3 with findings, 1 not read"). Then the watch's status pills, the disclosures - "Could not see (N)" lists every hole of the screen, "Checks" holds what `raqib doctor` says as rows, "Watch options" the hook, suspect and page settings - each closed until clicked, and the cards: the trees (a table sorted by a click on its heading), the findings and notes, the selected tree.

Project watches a project folder as `raqib watch` does (Start watching installs its hooks; Stop, or closing the window, ends it like Ctrl-C and shows the final report); the host and a project can be watched at once, and `--every T` sets the host rounds (default 10 s). Rules lists every rule with a switch, its title, pills for kind, severity and origin, its thresholds as steppers within their bounds, a filter box and Add rule file...; Log shows the host watch's or the project watch's own lines. The keyboard reaches every control (Tab, then Space or Enter); the colours follow Windows' dark or light setting, and on Windows the text is sharp on a scaled display and the title bar follows dark mode.

`raqib app [PROJECT]` (or `raqib-app`, which on Windows opens with no console) preselects PROJECT on the Project screen. On Windows a tray icon offers Show / Stop / Quit, its tooltip reads "Raqib: N trees, K new, F findings" (and "+S suspicions") while the host is watched, "Raqib: project <name>, F findings" while only a project is, "Raqib: idle" otherwise, and closing the window while watching hides it there; on Linux there is no tray. The first finding of a watch knocks once, whatever its severity (in `raqib watch` too).

It needs tkinter: python.org Python ships it; on Debian or Ubuntu `sudo apt install python3-tk`; without it, or without a display, `raqib app` exits 2 and says so (`raqib-app`: in a message box on Windows, its log in `~/.raqib/app.log`), and `raqib watch` still works ([ADR-0006](docs/specs/ADR-0006-the-window.md)).

## Choose the rules
`raqib rules` lists every rule (id, kind, class, severity, budget, on / off, origin, the thresholds its YAML declares with their bounds); `--set ID on|off`, `--threshold ID FIELD VALUE` (for example `--threshold HOST-RHYTHM k 5`) and `--reset ID` change `~/.raqib/rules.yaml` only, never the package, and exit 2 with the reason when refused; the window's "Rules" button does the same.
`--add FILE` takes a rule you wrote, with its positive and negative fixtures beside it: it joins only when the loader and the fixture runner accept it (A6), copied into `~/.raqib/rules.d/<ID>/` (fixture paths relative, no `..`, no drive), and is shown as `origin: user`; a changed threshold is measured on the rule's fixtures and refused when a positive stops firing or a negative fires.
A threshold can be changed only within the bounds its rule's YAML declares (`bounds:` min, max and relations such as `k <= r`), shown with the range the measurement accepts; one without bounds or without a sensitive fixture is listed as fixed and refused.
A changed threshold is measured before it is allowed, when set and when the overlay or the catalog changed (the result is kept in `~/.raqib/rules.measured.json`; "measuring the overlay's thresholds..." is said while it runs): the host rules' fixtures are generated at the new value by the installed package itself, a threshold is editable only where a generated edge pair is sensitive to it, and the value is refused, naming the fixture and the condition, when a positive does not fire, a negative or a synthetic desktop's arrival fires, or the budget is broken.
A change applies to the next watch; every watch prints the overlay it applied at its start, keeps it in its state, and shows "N rules off: <ids>" in the band and the window's header.
**A new rule from a form.** On the Rules screen, "New rule" opens a form: give the rule an id (such as `MY-TF`), say what to watch for in words - a program is run, a file under a place is touched, a network host is reached, a tool is used - name the programs, places, hosts or tools, choose how grave it is, and give one example that must fire and one that must not (both are filled in from the first name; change them as you like). A program typed with capitals is also matched in lower case, and a place beginning with `~` also as your home on this machine; the form says so beside the field.
"Test" writes the rule's YAML and its fixtures in a staging folder under `~/.raqib` (removed afterwards), lets the loader and the fixture runner judge them exactly as they judge a rule you wrote by hand (measured on the examples you gave, not on a corpus), shows the YAML it would add, and says what it would have fired on in the traces and host source files already under `~/.raqib` that a watch would give it (the newest 20 files, at most 20,000 lines; information only, never a gate); each refusal stands beside its field and nothing is written in `rules.d`. "Add" is enabled only after a passing Test of the same answers and adds the rule through the same path as `--add`, into `~/.raqib/rules.d/<ID>/`, as a signature of class USER that lists the ways round it.
A rule you added, or one that was refused at load, has a "Remove" button that asks once ("Keep it" has the focus) and acts on that row's own folder or file in `rules.d`, and nothing else: every check comes first, with nothing changed (a link, a junction or anything that leads elsewhere inside it is refused, and nothing is deleted); then its rule file goes, so the rule can no longer load; only then is its entry dropped from `rules.yaml` (when that rule was loaded from that place); then the rest of its folder. A removal that deletes nothing says so ("nothing removed", or "nothing was removed") and changes nothing; one that stops midway says what is gone and what remains. A row that is not a folder or a rule file Raqib could have written (a folder whose name is no rule id, or a link) has no "Remove": it gives its path, which you can select and copy, to delete it by hand if you mean to. A package rule cannot be removed, switch it off instead. A running watch keeps the rules it started with. In the terminal: `raqib rules --new MY-TF --when program --values terraform,tofu --severity medium --fires terraform --quiet ls [--title T] [--dry-run]` and `raqib rules --remove MY-TF [--dry-run]` (it deletes without asking; `--dry-run` says what it would delete; `MY-TF` names a folder, `MY-TF.yaml` or `MY-TF.yml` a loose file of exactly that name, never the one for the other), with the same checks and the same words (exit 2 with the reason when refused).
A rule off is said, not silent: the final report lists it with who turned it off and since when, and "not judged by <id> (off): M lines" with what it would have fired; the exit code is not changed by it, but a clean watch where an off rule would have fired says "CLEAN (N findings suppressed by the overlay)" ([ADR-0008](docs/specs/ADR-0008-the-rules-panel.md)).

## How it works
- **Deterministic first.** Rules decide; a model can only add suspicion (A1, A2).
- **Silence is an alarm.** A gap, a call that never finished or a session
  that never closed is a finding, not "nothing happened" (A3).
- **The watcher never touches the watched.** Raqib reads and reports; it
  blocks nothing (A4). Capture and rules work offline; they store hashes,
  not content.

1. **Capture.** Six Claude Code hooks append JSON lines to
   `raqib.log.jsonl`: two per tool call (pre and post) and one per session
   event. Inputs and outputs are stored as
   sha256 only, plus a small extract: the path, the URL host, the program
   names of a Bash command, and the names of secret patterns seen in the
   output. Of a command's arguments only two things are kept: the file name
   of the script python or bash runs (`command_scripts`), and the first word
   of a `git commit` message when it is a lower-case word ending in a colon,
   such as `landed:` (`commit_prefix`). The session start, stop and end
   lines also carry the local git state, read from the files under `.git`
   (no `git` is run): the head commit, the sha256 of the index, and why
   either could not be read.
2. **Rules.** Twenty-two rules turn the trace into findings, and every finding
   cites the trace lines behind it (A5). The rules are 5 silence rules, 1
   cross-source rule (CROSS-SOURCE, `raqib/rules/cross.py`) and 16 more: 14
   YAML rules in `raqib/rules/catalog` and 2 tree anchors (HEAD-UNMOVED,
   INDEX-UNTOUCHED, `raqib/rules/tree.py`). Each YAML rule declares its
   false-positive budget and is measured against fixtures (A6); CROSS-SOURCE
   and the tree anchors declare 0.1, and the silence rules have no budget
   yet.
3. **Suspicion (optional).** A local or API model reads windows of the
   trace metadata. It can raise suspicion with citations; it cannot clear
   anything.
4. **Report.** Text, JSON, or a read-only HTML page. Every line names its
   capture source (`hook`; `proxy` for another agent; `os` for what Sysmon
   saw on Windows; both below), and the report names it on every finding.

## Manual steps
The steps before `raqib watch` existed, from a checkout, one command at a time.
Linux, macOS; Windows: capture and installer (path rules since M5.1b). You need
`python3` (Raqib itself is stdlib only) and Claude Code. On Windows run
`python -I tools\install_hooks.py C:\path\to\project` and `python -I tools\gate.py`.
Install from the side that runs the agent (Windows or WSL), not both.
On Windows a missing `python.exe` is a hook error shown by Claude Code: no `RAQIB-SILENCE:` line, and not a block.
The gate runs the tests with pytest; if pytest is
missing, `gate.sh` installs it with pip, which needs the network.
```bash
git clone https://github.com/omanras/raqib ~/raqib
~/raqib/tools/gate.sh                             # ends with [gate] GREEN
~/raqib/tools/install-hooks.sh /path/to/project   # adds six hooks to its .claude/settings.json
cd /path/to/project
claude -p "Use the Bash tool to run: echo raqib-quickstart" --model haiku --max-turns 3 --allowedTools "Bash(echo:*)"
cd ~/raqib
python3 -m raqib report /path/to/project/raqib.log.jsonl --scope .           # CLEAN, exit 0
python3 -m raqib ui /path/to/project/raqib.log.jsonl --scope . -o trace.html  # open trace.html
```
These steps were run from a fresh clone (see
`docs/review/2026-10-16-M3.2-questions.md`). The raw trace of such a run is
`tests/fixtures/quickstart-d7841d1-claude-code-2.1.301.log`. A session that
runs a long call or waits for you for over a minute raises SILENCE-GAP: by
design, a quiet minute is reported, not assumed harmless.
- **Where the trace goes.** The trace path is absolute, so a `cd` by the
  agent cannot split it. `--log PATH` puts it outside the project.
- **Capture never blocks the agent.** If it cannot write, it prints one
  `RAQIB-SILENCE:` line to the hook's stderr (`claude --debug` shows it).
- **The installer** keeps your other hooks and changes nothing on a second
  run.

## What it catches
| Rule | Fires on |
|---|---|
| SILENCE-GAP / OPEN / HALF / ORDER | no capture for 60 s; a session with no end; a call with no result (or a result with no call); seq or time going back |
| SILENCE-EMPTY | a session that started and ended with no tool call and no turn, or ended with no start and no tool call (one with tool calls and no start is not judged yet: SILENCE-NOSTART, a later task) |
| SCOPE-PATH | a file tool touching a path outside the session's directory |
| SCOPE-CWD-ROOT / -MOVED | a session running from `/` or a home directory; a working directory that changes |
| NET-TOOL | WebFetch, WebSearch, a URL, or curl, wget, ssh, nc and the like anywhere in a Bash command; under `raqib watch --host` also a tree's child of those names (the host's record, or Sysmon's process line by `input_meta.image`, Windows programs such as bitsadmin and plink included) |
| DESTRUCT-CMD | rm, dd, shred, mkfs and the like anywhere in a Bash command; under `raqib watch --host` also a tree's child of those names (the host's record, or Sysmon's process line by `input_meta.image`, Windows programs such as vssadmin, diskpart and format included) |
| SECRET-OUTPUT | a key, token or private key in a tool's output (by pattern name; the text is never stored) |
| DRIFT-FILES | edits to more than two files outside the task's declared scope |
| LANDED-NO-GATE | a `landed:` commit with no ok run of `gate.sh` or `gate.py` on the same Bash call or before it in the session (holes such as a stale, piped or backgrounded gate are listed in the rule) |
| EDIT-NO-TEST | an edit under `raqib/` or `tests/` with no ok run of pytest, python, python3, `gate.sh` or `gate.py` after it, before the next stop or session end |
| HEAD-UNMOVED | ok edits under the session's directory and the same git head at the session's last stop or end as at its start: never committed (a session without git state, or with no repository at either end, is not judged) |
| INDEX-UNTOUCHED | ok edits under the session's directory and the same git index bytes at its last stop or end as at its start: never staged (a `git status` that rewrites the index counts as touched) |
| NEW-AGENT / -UNKNOWN | only under `raqib watch --host`: a tree that talks and acts and was not there in an earlier round, and is no listed benign program under a system directory (NEW-AGENT high when the catalog names it; NEW-AGENT-UNKNOWN medium when not) |
| AGENT-DARK-LIVE | only under `raqib watch --host`: an agent's footprint with no live tree for 3 rounds in a row |
| HOST-UNWATCHED | only under `raqib watch --host`: a tree that talks and acts with no source attached in two rounds in a row (not even the host's own record of it) |
| HOST-RHYTHM | only under `raqib watch --host`: a tree that talks to one destination and then starts a child within 30 s, 3 times in the last 10 rounds (the think-act cycle; medium; once per streak) |
| CROSS-SOURCE | only in a trace with `os` lines: a shell call with no os process of its programs (or a shell) in the 10 s after it; an os process below the agent's own children that no shell call asked for in the 10 s before it, itself or through a parent below the shell (below) |

## What it cannot see
Content, by design. So the rules miss these:
- a program hidden behind `sudo`, `eval`, `python -c` or a second `bash -c`
  (pipes, `&&`, `;`, `$(...)` and one `bash -c` are read);
- code given to a shell on stdin, by a here-document or a here-string, or in
  a script file: only the shell or the script is recorded;
- file access made through Bash;
- a symlink out of the project;
- a secret the agent writes rather than reads;
- an agent that rewrites the trace or switches the hooks off and then
  stays quiet;
- with the os source, acts the agent runs as its own direct children
  rather than through a shell: CROSS-SOURCE does not judge them;
- a gate or test run that failed behind a pipe (`| tail`), an `||` or the
  background: LANDED-NO-GATE and EDIT-NO-TEST read only the Bash call's own
  ok and the names it ran;
- for the tree anchors, what moved the head or the index (any commit,
  checkout or `git status` counts), edits outside the session's directory
  or in a second repository, a worktree, `GIT_DIR` set by the agent, and an
  index the agent rewrites: the rules in `raqib/rules/tree.py` list every
  hole.
On 50 labelled events the rules miss 9 bad events and flag 9 of 25 benign
ones (`docs/review/2026-10-16-M2.2-baseline.md`; 8 until M4.2b, whose
EDIT-NO-TEST flags b11-refactor: dated note 2026-11-03 there). On the rule fixtures
`raqib check-rules` finds SCOPE-PATH firing on 0 of 10 benign files and
NET-TOOL on 1 of 12; a trace that expects findings is never benign
(`tests/fixtures/field/`). No model has been
evaluated yet. See
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** for every known gap and its
source.

## Commands
Once installed, `raqib COMMAND`; from a checkout without installing,
`python3 -m raqib COMMAND`. TRACE is a `raqib.log.jsonl`.
| Command | Does |
|---|---|
| `raqib watch [PROJECT]` | install the hooks, tail the trace, knock, serve the page (above) |
| `raqib watch --host [--every T] [--window S] [--rounds N] [--attach-hooks]` | watch this host in rounds of discover: NEW-AGENT, NEW-AGENT-UNKNOWN, AGENT-DARK-LIVE, HOST-UNWATCHED and each tree's own source (above); exit 0 no knock and no hole (trees listed; unknown trees seen a candidate only by the channel are listed and counted, not knocked), 1 a finding, 3 a round not read |
| `raqib doctor [PROJECT]` | what `watch` needs and is missing, one line each (above) |
| `raqib report TRACE [--scope P \| --handoff HANDOFF.md] [--json]` | findings with their cited lines, rules that did not run, every rule's budget; exit 0 clean, 1 alarm, 3 incomplete, 2 usage |
| `raqib rules TRACE -o findings.jsonl` | findings only, one JSON line each |
| `raqib ui TRACE -o trace.html` (or `--serve`) | the report as one static page: timeline, findings, silence bands; no script; `--serve` binds 127.0.0.1 |
| `raqib check-rules [--fixtures-root CHECKOUT]` | each rule's measured false-positive rate against its budget, on the fixtures of a checkout (an installed raqib has none: pass `--fixtures-root`) |
| `raqib suspect TRACE --backend ollama -o suspicion.jsonl` | model suspicion (`--backend anthropic` needs `pip install anthropic` and ANTHROPIC_API_KEY, and sends trace metadata off the machine); then `report TRACE --suspicion suspicion.jsonl` |
| `raqib suspect TRACE --backend anthropic --allow-fallback` | lets another model answer a window the requested model refuses; off by default, and such answers are labelled (`answered_by`) and counted |
| `raqib eval [--candidate ollama:MODEL]` | false negatives and false positives of the rules and of each model on 50 labelled events: a checkout's tests/fixtures/eval/events.json or --events FILE (an installed raqib has none and exits 2) |
| `raqib proxy --listen 127.0.0.1:PORT --upstream URL --log TRACE [--cwd DIR]` | relay another agent's model API calls and record its tool calls (below) |
| `raqib os-sysmon --root PID[:GUID] --log TRACE [--from FILE.xml] [--cwd DIR]` | record what Sysmon saw the agent's process tree do (below); exit 1 when it wrote a `RAQIB-SILENCE:` line, 2 off Windows without `--from` |

## Watch another agent
An agent without Claude Code hooks can be watched through the proxy source
([ADR-0003](docs/specs/ADR-0003-capture-sources.md) and its Amendment A):
any CLI that talks to an OpenAI-compatible chat/completions API or to the
Anthropic messages API. Start the proxy, point the agent's base-URL setting
at it, and watch the trace as it grows:
```bash
raqib proxy --listen 127.0.0.1:8787 --upstream https://api.moonshot.ai --log ~/.raqib/traces/kimi.jsonl --cwd ~/my-project
raqib ui ~/.raqib/traces/kimi.jsonl --serve       # the live page (raqib watch installs Claude Code hooks)
raqib report ~/.raqib/traces/kimi.jsonl           # when the run is over
```
- **Kimi Code CLI:** in `~/.kimi-code/config.toml`, set the provider's
  `base_url` (`[providers.kimi]`, type `kimi`, by default
  `https://api.moonshot.ai/v1`) to `http://127.0.0.1:8787/v1`. This is read
  from the Kimi Code CLI documentation and was not run here; the first real
  run is a field test. For any other agent, see the agent's docs for its
  base-URL setting (for example `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`).
  The base URL must name `127.0.0.1`: the proxy answers only `127.0.0.1:PORT`
  as Host (not `localhost`) and refuses any request with an Origin header
  (a browser page), 403 each.
- **Your key goes through it.** The agent sends its API key to whatever
  listens on the port: set the base URL back when the proxy stops, and
  prefer a fresh port for each run, so another program cannot take the
  port and the key with it.
- **It relays and never steers.** It listens on 127.0.0.1 only and speaks
  HTTPS to the upstream, with certificates verified (a plain `http://`
  upstream needs `--allow-plain-upstream` and must be a loopback address,
  127.0.0.0/8 or ::1: tests only). Bodies pass byte for byte, streamed
  answers piece by piece as they arrive; headers pass except Host and the
  hop-by-hop ones, and an answer that ends with the connection gets
  `Connection: close`. No other header is added, no request is retried and
  none is made that the agent did not make. Upgrade requests and methods
  other than GET, POST, PUT, PATCH, DELETE, HEAD and OPTIONS are refused.
- **What it records.** It keeps one session per conversation: the session id is a
  hash of the model and the conversation's first message. A session starts
  at its first request, a tool call in an answer is a `pre`, its result in
  a later request the `post` with the same seq, an answer that ends the
  turn a `stop`, and Ctrl-C ends every open session. Results already in a
  conversation's first request predate the proxy: they go into one
  `history` line, not into halves. Hashes and the same small extract as the
  hook (`raqib/hooks/common.py`), and `source: "proxy"`; `cwd` is `--cwd DIR`,
  else the proxy's own working directory. A tool name or id that is not
  short printable ASCII is hashed (`tool_hashed: true`). A result whose
  call the proxy never saw is a post with a new seq, so SILENCE-HALF
  reports it.
- **Silence.** An upstream that cannot be reached (the agent gets 502, or
  504 on a timeout), a TLS failure, an answer cut short, a 5xx answer
  (relayed unchanged), a refused request (folded to one line a minute), a
  recording step that failed (the bytes pass all the same), or a request or
  answer it cannot read appends one `RAQIB-SILENCE:` line to the trace and
  to stderr; `raqib watch` reads it as a capture failure, `raqib report` as
  an alarm. It logs no request line; of the header values only the
  Content-Type and Content-Encoding of an answer it cannot read appear, in
  such a line.
- **What it cannot see.** An agent that does not use the proxy leaves no
  line at all. Other API shapes (the OpenAI Responses API, Gemini) are
  relayed but not read: one `RAQIB-SILENCE:` line per path. Tool names are
  written as sent, so the Bash rules read a shell command only from a tool
  named `Bash`, and SCOPE-PATH knows Claude Code's file tool names only. A
  conversation whose first message changes (a compacted history) is a new
  session, and two with the same model and first message are one. A `post` is what the agent sent; a `pre` is what the model's
  answer asked for. Any local process that is not a browser can send
  requests to the port.
`raqib watch` installs Claude Code hooks, so a proxy trace is watched with
`raqib ui TRACE --serve` (the page reloads itself) and judged with
`raqib report TRACE`. `raqib report` and the page name the source of every finding; lines
written before M5.2 carry no `source` and read as `hook`, and one trace
may hold both. The synthetic recorded sessions, an OpenAI-style and an
Anthropic-style one, are in `tests/fixtures/proxy/`.

## Watch what the system saw (os-sysmon)
The hook and the proxy record what the agent asked for. On Windows, Sysmon
records what its process tree did, and the agent does not write that record
([ADR-0003](docs/specs/ADR-0003-capture-sources.md), Amendments C and D).
Give the root of the tree and the trace. For Claude Code on Windows the root
is `claude.exe`'s pid, from `raqib discover` or Task Manager (`Get-Process
claude`); for another agent, its own process:
```powershell
raqib os-sysmon --root 4100 --log $HOME\.raqib\traces\proj.jsonl --cwd C:\work\proj
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml > sysmon.xml   # or export the log, and on any system:
raqib os-sysmon --root 4100 --log trace.jsonl --from sysmon.xml --cwd C:\work\proj
raqib report $HOME\.raqib\traces\proj.jsonl
```
- **What it reads.** Sysmon events 1 (process create), 11 (file create) and
  3 (network connect) of the tree under the root: the root, and every
  process whose parent is in the tree (the ProcessGuid keeps a reused pid
  out). The root is the LATEST process that held the pid in the export;
  when earlier processes held it too, one `RAQIB-SILENCE:` line says how
  many, and `--root PID:GUID` (its Sysmon ProcessGuid) picks another. Live,
  it runs `C:\Windows\System32\wevtutil.exe` by that path, read-only,
  once, and exits; it does not follow the log. On Linux and macOS it reads
  only `--from` (else exit 2).
- **What it records.** One session, `os-PID`, with a `pre` and a `post` per
  event at the time of the act, `source: "os"`, tool `process`, `file` or
  `net`. Hashes of the command line, the path or the destination, never the
  text; the program name (`bash.exe`), its image name in discover's form
  (`input_meta.image`, `bash`; since M7.8), its depth below the root and its
  parent's line; the path, redacted as the hook redacts it; the destination
  port and whether it is private. `cwd` is `--cwd DIR` (an absolute
  directory), else the root's own directory in its event 1, else no `cwd`
  at all: then the SCOPE-CWD rules say they could not judge (partial), and
  os-sysmon's own directory is never written. A second run appends the
  events again: reruns are not deduplicated, and the duplicates are
  visible.
- **Silence.** The log cannot be read (no Sysmon, no channel, no rights), an
  event cannot be read, the export holds no event 1 or no event 11, the
  pid is in no event, or it had earlier holders: one `RAQIB-SILENCE:` line
  each, on stderr and in the trace, and exit 1. Raqib names the event ids
  your configuration does not log. Sysmon logs network connections only
  when installed with `-n` (for example `sysmon64 -accepteula -i -n`): an
  export with no event 3 makes the report INCOMPLETE (exit 3), not an
  alarm.
- **CROSS-SOURCE.** When one trace holds os lines and hook or proxy lines,
  a shell call with no os process of one of its programs or of a shell
  (bash, sh, zsh, dash, ksh, fish, cmd, powershell, pwsh) in the 10 s after
  it is "asked, not done"; an os process below the agent's own children
  that no shell call asked for is "done, not asked". A process is asked
  when a shell call named its program in the 10 s before it, when it is a
  shell started in those 10 s (a subshell, a forked bash), or when its
  parent below the shell was asked: what `npm` starts (`node`) or `git`
  starts (`sh`) is asked with it. A shell call is a `pre` of `Bash` or of
  any tool whose name, in lower case, holds `bash`, `shell`,
  `execute_command`, `run_command`, `cmd` or `command`; program names are
  compared in lower case without `.exe`, `.cmd` or `.bat`. Only the time
  both sources cover is judged: a shell call outside every os session is
  history and gets no note, so one os-sysmon run does not make a long
  project trace INCOMPLETE; an os process outside every hook or proxy
  session is a partial note. A trace with no os line is not judged and
  gets no note; a trace with os lines and no hook or proxy line is
  INCOMPLETE, by a partial note or, when every os process is the agent's
  own, "nothing to judge". The agent's own direct children (its helpers:
  a search tool's `rg`, `git`, MCP servers, and the shell it starts) are
  not judged: an agent that runs its acts that way is a known hole.
  Matching is by name only, so a renamed program passes as the name it
  carries; a shell call with unknown programs in the window makes the
  process partial, and the note names that call; a tool that only has a
  shell word in its name and starts no process is a false-positive source.
  SILENCE-GAP and SILENCE-ORDER do not judge a session of os lines only,
  SECRET-OUTPUT does not judge os lines, and NET-TOOL and DESTRUCT-CMD
  judge an os process line by its image only (M7.8; not its net or file
  lines; a line written before M7.8 has no image: "could not judge").
- **What it cannot see.** What a process does inside itself, tools that
  never start a process or touch a file (memory only), and whatever the
  Sysmon configuration leaves out; see
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
The synthetic export (host `host`, user `user`, documentation addresses) is
`tests/fixtures/os/sysmon-synthetic.xml`, and the four CROSS-SOURCE fixtures
are in `tests/fixtures/cross/`; a real export under your configuration is a
field test.

## Find the agents on a host (discover)
`raqib discover` looks for AI agents it has never heard of
([ADR-0004](docs/specs/ADR-0004-agent-discovery.md), Amendments B and
D). It goes by what an agent does, not by its name: a process that talks
(an outbound TCP connection) and has a child, or writes a file outside
config space. No name list decides that. `raqib/discover/endpoints.yaml`
adds supporting evidence only, and lists its own evasions: model hosts,
networks and local ports, config-dir footprints, the act names that label
a child (bash, python, git, ...), and the hand-off criteria. Each
candidate comes with its cited lines and a suggested capture source
(ADR-0003):
- **hook:** a root image named claude, but not Claude Desktop;
- **proxy:** a CLI the catalog marks `proxy_capable`;
- **os:** everything else.

**AGENT-DARK** is an agent's config directory on disk with no active tree
in the window. Discover is offline and read-only, and it never signals or
attaches to a process.

**Act-roots and recent talk (M5.0b, ADR-0004 Amendments F, G).** An agent
between two requests owns no connection, so its acts go to whatever
ancestor talks (the Kimi field test: the desktop shell). Two more lines
name it:
- **act-root, talk not seen:** a program whose image is under a user
  directory (`Users\<name>`, AppData, `/home`, `/root`), that is not a
  listed shell or system image, started from a shell or a terminal host
  (not from explorer, a desktop session or an IDE), that is no
  Electron/Chromium helper (`--type=`), with a shell as a child that runs a
  command from outside the program's own directory, and no connection of
  its own in any sample. On Linux the image path is the `/proc/PID/exe`
  link, else argv[0]. It is weaker than a candidate, and a signature (the
  catalog's `act_root` block, with its `status` and evasions: an install
  under Program Files, a shell-looking name, a GUI launcher, a `--type=`
  argument, talking through a child, ...). Exit 1 all the same. A later
  sample in which it talks makes it a candidate (the samples are merged).
- **recent talk, owner unknown:** a TIME-WAIT row with no owner (Windows
  OwningProcess 0, Linux inode 0) or a DNS cache row (a name, no pid) for
  a catalog endpoint. Shown with its cited lines; never a candidate or an
  act-root by itself. With no candidate and no act-root the talker is not
  seen, so the run is incomplete (exit 3).
```bash
raqib discover                      # this host, live: Linux /proc (one snapshot); Windows the OS API (6 samples, 10 s apart)
raqib discover --window 30 --save run1   # Linux: sample 30 s; keep the texts read and a run.json with the sample count
raqib discover --samples 3 --every 5 --save run1   # Windows: 3 samples 5 s apart, kept as win-*-<k>.csv
raqib discover --from run1 --json   # the same inventory again, from the saved texts and run.json
raqib discover --check              # candidates and act-roots on the fixtures, against act-root's fp_budget
```
On Linux, connections come from `/proc/net/tcp` and `/proc/net/tcp6`,
with owners from `/proc/PID/fd`. These are kernel files that no PATH can
replace. Only when `/proc/net/tcp` cannot be read does discover run `ss`,
by absolute path (`/usr/sbin/ss`, `/usr/bin/ss`, `/sbin/ss`, `/bin/ss`)
with a minimal environment. The output names the path it read.

On Windows, `raqib discover` reads the live host in-process (M7.1,
[ADR-0007](docs/specs/ADR-0007-the-host-not-the-name.md)), with no
PowerShell: `--samples N` samples (default 6) `--every T` seconds apart
(default 10), start to start, merged as below. Each sample reads the processes and their
parents (Toolhelp32), each image path (QueryFullProcessImageNameW, under
the least process right there is, PROCESS_QUERY_LIMITED_INFORMATION), the
TCP connections with their owning process (GetExtendedTcpTable, IPv4 and
IPv6) and the names in the DNS resolver cache (DnsGetCacheDataTable, and
the cached addresses only: nothing is asked on the network). It reads no
command line, working directory or environment (that would read another
process's memory), and says so in a hole: without argv, Claude Code run as
`node` is named "node" live. An image path it may not read is
`?` and counted in a hole; a cache it cannot read is the hole "no names";
every cap, skipped entry and truncated name is a hole with its count. The
reader and its launchers (`raqib.exe`, a venv's `python.exe`) are never
evidence. A
failed process snapshot refuses the run in one line (exit 2); any other
failure inside the reader says where it failed (exit 2). `--save DIR`
keeps each sample as `win-process-<k>.csv`, `win-tcp-<k>.csv` and
`win-dns-<k>.csv`, the shapes of the loop below, with a `run.json` naming the
APIs read and the sample times, so `--from DIR` repeats the run. Run it
elevated when you can: an elevated run reads more image paths.

**Repeat from an export.** The PowerShell loop is kept as the fallback that
an export can be repeated from. In PowerShell, in an empty folder, a loop of
`$N` samples `$T` seconds apart
(default 6 and 10; `$N = 1` is one sample). Run it from an elevated
PowerShell when you can: without it, other users' and system processes
have no image path, and each is counted in a hole.
```powershell
$N = 6; $T = 10
[ordered]@{raqib = 'discover-run'; version = 1; export = 'windows'; samples = $N; seconds_apart = $T} | ConvertTo-Json | Out-File -Encoding ascii run.json
foreach ($k in 1..$N) {
    Get-CimInstance Win32_Process | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding utf8 "win-process-$k.csv"
    Get-NetTCPConnection | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding utf8 "win-tcp-$k.csv"
    Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation | Out-File -Encoding utf8 "win-dns-$k.csv"
    if ($k -lt $N) { Start-Sleep -Seconds $T }
}
Get-ChildItem -Force C:\Users\*\, C:\Users\*\AppData\Roaming\Claude\ | ForEach-Object FullName | Out-File -Encoding utf8 footprints.txt
```
If Sysmon is installed, export its newest 5000 events into the same folder:
```powershell
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /rd:true /c:5000 > sysmon.xml
```
Then `raqib discover --from C:\path\to\that\folder`. Every sample is read
and merged, as the Linux window merges its snapshots: a process is its pid
and its CreationDate, so a pid reused between samples is two processes.
`run.json` says how many samples there should be: a sample without its
`win-process-<k>.csv` or `win-tcp-<k>.csv` is a hole, and the run is
incomplete (exit 3 unless an alarm). The single files of M5.0
(`win-process.csv`, `win-tcp.csv`, `win-dns.csv`) are still read.

**What a candidate is not.** It is a tree that talks and has a child, not
proof of an agent. IDE terminals, package managers running install
scripts, CI runners, browsers with helper processes and updaters can all
be candidates. Talk over loopback counts too: an agent's local model is
on loopback. First fp numbers (M5.0b), measured by `raqib discover
--check` on two synthetic benign exports. The Linux desktop: a GNOME
terminal running vim; VS Code from its package and a JetBrains IDE under
`~/.local`, each with a terminal running make -> cc; JetBrains Toolbox;
Firefox. The Windows desktop: explorer, OneDrive, VS Code under
`AppData\Local\Programs` with its extension host running git and its
terminal running a command (powershell -> node), and Edge. On these,
candidates fire on 2 of 2, and the anchor still declares no budget;
act-root declares fp_budget 0.25 and fires on 0 of 2. `--check` fails
when act-root is over its budget or misses a positive (the synthetic Kimi
exports and a Linux agent under `~/.local/bin`), and reports its status.
The candidate budget is set from field runs, not guessed.

**What it cannot see.** Every run prints the first five as holes; the
others are printed when they apply to the sources read:
- **liveness:** a child is seen only while it is alive at a snapshot,
  and a connection only while it is open: an agent between requests
  shows only as recent talk or as an act-root;
- **sibling talkers:** an Electron network process or a local relay sits
  beside the child, not above it;
- **reparented children:** setsid, nohup, double fork, or an exited
  parent;
- **TCP only:** no UDP or QUIC, and no unix-socket relays;
- **one view:** one network namespace, and no processes hidden by
  hidepid.
- **config space:** writes into dot-directories (also `.ssh`,
  `.git/hooks`, `.github/workflows`), AppData (also the Startup folder),
  ProgramData, temp, or the program's own directory are not counted as
  acts.
- **no names on Linux:** Linux keeps no DNS name record offline.
- **no environment on Windows:** Windows exports carry no process
  environment, and the live reader reads no command line either.
- **window merge:** samples are merged by pid, and on Windows by pid and
  CreationDate; a Linux pid reused between snapshots, or a Windows process
  without CreationDate, joins two processes.

**Exit codes.** An empty result still prints the window, the records read
per source, and every hole.
- **1:** a candidate, an act-root, an AGENT-DARK footprint, an unread
  line, or nothing read.
- **3 (incomplete):** a process or connection source failed (even in one
  sample, and also when ss stood in for /proc/net/tcp), held no record
  (Sysmon: no event 1, or no event 3), or left a talking line without an
  owner, or a Windows sample is missing, or there is recent talk with no
  candidate and no act-root: incomplete (exit 3 unless an alarm). A
  missing footprint listing is only a hole. `--save` writes a `run.json` beside the texts, so `--from`
  replays an incomplete run as incomplete.
- **0:** every process and connection source was read and complete, and
  nothing was seen. That is not a clearance.

Fixtures are in `tests/fixtures/discover/`. The Linux ones are real and
redacted, made by `capture.py` there; the Windows ones are synthetic; the
M5.0b ones (`kimi/`, `benign/`, `linux-agent/`) are synthetic, made by
`synthetic.py` there.

## More
- **[docs/CONSTITUTION.md](docs/CONSTITUTION.md)**: the nine articles
  (A1-A9) every change is held to.
- **[docs/specs/ADR-0001-architecture.md](docs/specs/ADR-0001-architecture.md)**:
  the pipeline, the trace schema and its amendments.
- **[docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md)** and `docs/review/`
  hold the plan, every review packet, and the open questions.
- **How this repo is built.** One micro-task per session (`HANDOFF.md`), a
  read-only reviewer, and a gate (`tools/gate.sh`) that every commit must
  pass.

Status: v0.1 candidate: capture, rules, report, suspicion
layer, evaluation, web view and docs. The last exit criterion of the plan
(M3.3) is still open: one person outside the project runs this quickstart
and files one issue.
