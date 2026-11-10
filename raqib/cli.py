"""Command line (M1.3): raqib <command>, or python -m raqib <command>.

`raqib` is the console script of an installed raqib (pyproject.toml, M6.3:
raqib = raqib.cli:main); from a checkout, python -m raqib runs the same main.

  rules TRACE [-o FILE] [--scope P]... [--handoff FILE] [--gap-seconds N]
      Run the silence rules and the rule catalog on a trace. Findings go to
      FILE (one JSON finding per line; ADR-0001 section 6) or stdout. With -o,
      FILE.notes.json records which rules did not run and why. The catalog
      is judged as its YAMLs declare it: the overlay below is the watches'.
  rules [--set ID on|off | --threshold ID FIELD VALUE | --add FILE | --reset ID] [--json]
      M7.6 (ADR-0008): with no TRACE, list every rule as the next watch will
      load it (id, kind, class, severity, budget, status, origin, declared
      thresholds with their bounds) from the package's catalog, the
      person's rules in ~/.raqib/rules.d and the overlay ~/.raqib/rules.yaml,
      with what the overlay applied or refused. --set, --threshold and
      --reset change the overlay only (written atomically); --add validates a
      rule file with the loader and the fixture runner and copies it, with
      its fixtures, into ~/.raqib/rules.d. A change applies to the next
      watch. Exit 2 when a change is refused (the reason on stderr), 0
      otherwise.
  report TRACE [--findings FILE] [--scope P]... [--handoff FILE] [--json]
      Show the findings with the trace lines they cite (A5), the alarms, the
      rules that did not run (A3) and every rule's fp_budget (A6). Without
      --findings the rules are run on TRACE first.
  check-rules [--json] [--fixtures-root DIR]
      Run every catalog rule, CROSS-SOURCE (raqib/rules/cross.py) and the two
      tree anchors (raqib/rules/tree.py) on its fixtures and the benign
      corpus; print the measured fp_rate against the declared fp_budget
      (A6). The fixtures are those of a checkout (DIR/tests/fixtures; default: the checkout this
      raqib runs from). An installed raqib carries the catalog but no
      fixtures: without --fixtures-root it says so and exits 2.
  suspect TRACE [--findings FILE] [--backend ollama|anthropic|fake] [--allow-fallback] [-o FILE]
      Ask a model to raise suspicion over windows of the trace (ADR-0001
      section 5). It can only raise (A2): answers below --threshold are
      dropped, never recorded as clean; failures become error lines (A3).
      With -o, FILE.run.json records how many windows were judged.
      report TRACE --suspicion FILE shows the result with cited lines.
      --allow-fallback lets another model answer a window the anthropic
      model refuses (off by default; ADR-0001 B-5).
      Exit 1 if anything was raised (or the trace is empty or corrupt), 3 if
      no suspicion was raised but some window could not be judged, 0 if
      nothing was raised (not a clearance, A2).
  ui TRACE [--findings FILE] [--suspicion FILE] [-o FILE | --serve [--port N] [--refresh N]]
      Write the report as one static, read-only HTML page (timeline,
      findings, silence windows), or serve it on 127.0.0.1, reloading every
      --refresh N seconds (1..3600, default 5). Exit codes as for report;
      --serve runs until interrupted.
  eval [--events FILE] [--candidate SPEC]... [--json] [-o FILE]
      Score the rules, and each candidate model, on labelled events (M2.2;
      a checkout's tests/fixtures/eval/events.json or --events FILE; an
      installed raqib carries none and exits 2 without --events):
      false negatives, false positives and errors, ranked by FN first. SPEC is
      ollama[:MODEL], anthropic[:MODEL] or fake:ANSWERS.json. Exit 0 when
      every row judged every event, 3 when some row has errors, 2 on bad
      input.
  discover [--from DIR] [--read KIND=FILE]... [--window S] [--samples N] [--every T] [--home DIR]... [--save DIR]
           [--json] [-o FILE]
      Find AI agents on a host by what they do (M5.0, ADR-0004 Amendment B):
      trees that talk (outbound TCP) and have a child, or write a file
      outside config space, each claim with its cited lines. Without
      --from/--read it reads this host (Linux: /proc and /proc/net/tcp, ss
      by absolute path only as fallback, --window S; Windows, M7.1: the OS
      API in-process - Toolhelp32, GetExtendedTcpTable, the DNS resolver
      cache - --samples N (default 6) samples --every T seconds apart
      (default 10), and a failed process snapshot exits 2; elsewhere the
      homes only), offline and read-only. Exit 1 when a candidate, an act-root, an AGENT-DARK
      footprint or an unread line is found, or nothing was read; 3 when a
      process or connection source failed (even in one sample), held no
      record, or left a talking line without an owner; 0 only when those
      sources were complete and nothing was seen (not a clearance); 2 on bad
      input. An act-root (M5.0b) is a program in a user directory running a
      shell that runs a command, with no talk of its own seen; recent talk
      (a TIME-WAIT or DNS cache row, owner unknown) is shown; with no
      candidate and no act-root it makes the run incomplete (3).
      --save DIR writes the texts and a run.json (each source's error, the
      live holes, the sample count); --from DIR replays them, incomplete if
      the run was, or reads the README's Windows loop (win-*-<k>.csv for
      each sample k, and its run.json) and merges the samples.
  discover --check [--fixtures-root DIR] [--json] [-o FILE]
      Measure candidates and act-roots on the fixtures the catalog's act_root
      block names, against act-root's fp_budget (A6; candidates declare
      none). Exit 0 when act-root is within it and every positive is found,
      1 otherwise, 2 when DIR (default: this checkout) holds no fixtures.
  watch [PROJECT] [--log PATH] [--no-open] [--no-notify] [--port N] [--refresh N]
      Watch a project (M6.1, ADR-0005; default: the current directory):
      install the hooks (idempotent; the installer's lines are printed),
      tail the trace (by default outside the project, under ~/.raqib/traces),
      judge each new line with the Scope of PROJECT/HANDOFF.md if there is
      one, notify the OS of settled high findings, live silence
      (RAQIB_GAP_SECONDS), capture failures and trace holes, keep it all in
      TRACE.watch.json with a heartbeat, serve the page on 127.0.0.1 (--port
      N, default 8765; a busy port gives another one and a WARNING; it reloads
      every --refresh N seconds, 1..3600, default 5) and open it once. Lines
      already in the trace at the start are history: shown, never notified.
      Notifications are off under CI or with --no-notify.
      Ctrl-C, or a crash, prints the final report; exit as for report.
  watch --host [--every T] [--window S] [--rounds N] [--attach-hooks] [--suspect BACKEND [--suspect-every N]] [--no-open] [--no-notify] [--port N]
      Watch this host, not a project (M7.2, ADR-0007): a round of live
      discover every T seconds (default 10; Linux /proc, --window S seconds
      of it; Windows one sample of the OS API), read-only; nothing installed,
      no project touched. NEW-AGENT (high; NEW-AGENT-UNKNOWN, medium, when
      the catalog does not name it) knocks once per new tree that talks and
      acts ("host, <image> pid <n> (named|unknown)"); trees of the first
      round are history, a listed benign program under a system directory
      is benign: listed, not knocked. AGENT-DARK-LIVE (medium) after 3 rounds
      of a footprint with no tree. Every round prints one line, "NO AGENT
      SEEN" included; a reader not back in 2 x T is a hole and a knock.
      Record and latest inventory under ~/.raqib/host/, every line with the
      run's id; one host watch per home. --rounds N (or Stop) ends after N
      rounds, at the reader's deadline at the latest. Exit 0 trees listed
      and nothing new (or none seen: not a clearance), 1 a finding, 3 a
      round not read or another hole, 2 usage (also --host with a PROJECT,
      or another host watch on this home). Every tree gets a source that
      only reads (M7.2b, ADR-0007 decision 3 and Amendment H): the os source
      where the Sysmon channel exists, else the host's own record of its
      children and connections (lines of source "host" under
      ~/.raqib/host/sources/, judged by NET-TOOL and DESTRUCT-CMD, as the
      os source's process lines are by their image name, M7.8); its
      findings show on the tree and knock. A tree whose root process is in
      the round's sample and does not talk is quiet (listed, its source
      kept), gone only when its root is not. A candidate with no source for
      two rounds is HOST-UNWATCHED (high). --attach-hooks: a Claude Code
      tree whose working directory was read also gets `raqib watch`'s hooks
      in that project (the trace outside it); the hook settings are the
      only file ever written into a project, and only with this flag.
      RHYTHM (M7.4, anchor, medium): K talk-then-act cycles to one
      destination in R rounds (K=3, W=30 s, R=10 in HOST-RHYTHM.yaml). --suspect
      BACKEND (ollama[:MODEL], anthropic[:MODEL], fake:FILE; off by default):
      every N rounds (--suspect-every N, default 10) each unknown tree's host record (hashes and names) goes
      to the suspect layer, the only network call; it may raise suspicion,
      never acquit (A2); a raised suspicion is a finding of the tree (exit 1).
  proxy --listen 127.0.0.1:PORT --upstream URL --log PATH [--cwd DIR] [--allow-plain-upstream]
      Watch an agent that speaks HTTP to its model API (M5.2, ADR-0003 and
      Amendment A, raqib/hooks/proxy.py): point its base URL at
      http://127.0.0.1:PORT (that host exactly); every request is relayed to
      URL (https, certificates verified) with its bytes unchanged, no retry
      and no request of its own, and streamed answers pass as they arrive.
      Tool calls of OpenAI chat/completions and Anthropic messages answers
      become `pre` lines of the trace PATH, their results in a later request
      `post` lines (source "proxy"; hashes and the input_meta extract only),
      one session per conversation; cwd on the lines is DIR (default: the
      proxy's own). An upstream failure, a refused request or anything it
      cannot record writes one RAQIB-SILENCE line. --allow-plain-upstream
      lets URL be http:// to a loopback address (127.0.0.0/8, ::1; tests).
      Runs until interrupted, then ends the open sessions; exit 2 on a bad
      option or a trace it cannot write.
  os-sysmon --root PID[:GUID] --log PATH [--from FILE.xml] [--cwd DIR]
      Record what the operating system saw the process tree under PID do
      (M5.3, ADR-0003 Amendment C, raqib/hooks/os_sysmon.py): Sysmon events
      1 (process create), 11 (file create) and 3 (network connect) become
      `pre`+`post` lines of the trace PATH with source "os", session
      os-PID; hashes and program names only, never an argument. Live on
      Windows it runs C:\\Windows\\System32\\wevtutil.exe (read-only); with
      --from it reads an export (wevtutil qe Microsoft-Windows-Sysmon/
      Operational /f:xml), on any system. Exit 1 when it wrote a
      RAQIB-SILENCE line (channel unreadable, root not found, earlier
      holders of its pid, no event 1 or 11, an unreadable event), 2 on a bad
      option, without --from off Windows, or a trace it cannot write; else 0.
  app [PROJECT] [--every T] [--log PATH] [--no-notify] [--port N] [--refresh N]
      Open Raqib as a desktop window (M6.4, ADR-0006; tkinter, standard
      library; also the `raqib-app` gui-script, with no console on
      Windows). It opens on the host (M7.3, ADR-0007 decision 5): one
      discover round at open, the trees found (image, pid, named/unknown/
      benign, first seen, acts, endpoints), doctor's lines under "Checks",
      and "Watch this host", which runs the watch of `watch --host` (a
      round every T seconds, default 10) with its knocks and its final
      report. "Watch a project" opens the project screen: what `doctor`
      says for PROJECT (default: the current
      directory), a project field with Browse, and Start; Start runs the
      same watch as `watch` in a worker thread (the page on 127.0.0.1 is
      served, not opened; its URL is shown), Stop or closing the window ends
      it like Ctrl-C and shows the final report. The first finding of a
      watch knocks once, whatever its severity. On Windows a tray icon has
      Show / Stop / Quit and closing the window while watching hides it
      there. --log is the trace of PROJECT only; a project chosen with
      Browse gets its default trace. Exit 2 when no window can open (no
      tkinter: python3-tk; no DISPLAY); else the exit of the last watch's
      report, 0 if none ran. Under `raqib-app` the output goes to
      ~/.raqib/app.log and a window that cannot open is said in a message
      box (Windows) or on stderr.
  doctor [PROJECT]
      Say in one screen what `watch` needs and is missing (M6.3,
      raqib/doctor.py): Python, `claude` on PATH and its version, the hook
      settings of PROJECT (installed / foreign / missing), the notifier, the
      window's tkinter (`app`), Sysmon (Windows) and whether the trace can
      be written. One line per check, OK,
      MISSING or UNSURE (cannot be checked here); exit 1 if any is MISSING,
      else 0. Read-only; the only
      program it runs is `claude --version`, by absolute path.

Exit codes (rules, report, ui): 0 clean, 1 alarm (any finding, empty or
corrupt trace, findings made for another trace), 3 incomplete (a rule did
not run), 2 usage or unreadable input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

from raqib import app as window_app
from raqib import discover
from raqib import doctor
from raqib import host
from raqib import overlay
from raqib import eval as evaluation
from raqib import report
from raqib import ui
from raqib import watch
from raqib.hooks import os_sysmon, proxy
from raqib.rules import context as rule_context
from raqib.rules import cross, engine, fixtures, silence, trace, tree
from raqib.suspect import backends as suspect_backends
from raqib.suspect import core as suspect_core

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "raqib", "rules", "catalog")
EVENTS = os.path.join(ROOT, "tests", "fixtures", "eval", "events.json")
# G-6: where eval's labelled events come from, in --help and in the exit-2 message.
EVENTS_SOURCE = "a checkout's tests/fixtures/eval/events.json or --events FILE"
# M5.1b C-3: --root is made absolute as this host does (os.path.abspath).
ROOT_HELP = ("directory the scope paths are relative to (default: each line's cwd); made absolute as this"
             " host does (os.path.abspath): on Windows /x means \\x on the current drive, e.g. C:\\x")


class UsageError(Exception):
    pass


def _parser():
    p = argparse.ArgumentParser(prog="raqib", description="Raqib: an external watcher for AI agents.")
    sub = p.add_subparsers(dest="command", required=True)

    def rule_options(sp, trace_optional=False):
        if trace_optional:   # M7.6: `raqib rules` with no TRACE lists and changes the rules (ADR-0008)
            sp.add_argument("trace", nargs="?", default=None,
                            help="trace file written by raqib/hooks/capture.py (none: list the rules)")
        else:
            sp.add_argument("trace", help="trace file written by raqib/hooks/capture.py")
        sp.add_argument("--scope", action="append", default=[], metavar="PATH",
                        help="a path of the task's declared scope (repeatable)")
        sp.add_argument("--handoff", metavar="FILE",
                        help="read the scope from a HANDOFF.md Scope: block (root: the file's directory)")
        sp.add_argument("--root", metavar="DIR", help=ROOT_HELP)
        sp.add_argument("--gap-seconds", type=float, metavar="N",
                        help="SILENCE-GAP limit (default: RAQIB_GAP_SECONDS or 60)")
        sp.add_argument("--catalog", default=CATALOG, metavar="DIR", help="rule catalog directory")

    r = sub.add_parser("rules", help="write findings for a trace; with no TRACE, list and choose the rules (ADR-0008)")
    rule_options(r, trace_optional=True)
    r.add_argument("-o", "--out", metavar="FILE", help="findings file (default: stdout)")
    change = r.add_mutually_exclusive_group()
    change.add_argument("--set", nargs=2, metavar=("ID", "on|off"), help="no TRACE: turn a rule on or off (the overlay)")
    change.add_argument("--threshold", nargs=3, metavar=("ID", "FIELD", "VALUE"),
                        help="no TRACE: set a declared threshold of a rule, within its bounds (the overlay)")
    change.add_argument("--add", metavar="FILE", help="no TRACE: validate a rule file and copy it into ~/.raqib/rules.d")
    change.add_argument("--reset", metavar="ID", help="no TRACE: remove a rule's entry from the overlay")
    r.add_argument("--json", action="store_true", help="no TRACE: print the listing as JSON")
    rep = sub.add_parser("report", help="report findings with their cited trace lines")
    rule_options(rep)
    rep.add_argument("--findings", metavar="FILE", help="use this findings file instead of running the rules")
    rep.add_argument("--suspicion", metavar="FILE", help="suspicion.jsonl written by `suspect`")
    rep.add_argument("--json", action="store_true", help="print the report as JSON")
    c = sub.add_parser("check-rules", help="measure every rule against its fixtures (A6)")
    c.add_argument("--catalog", default=CATALOG, metavar="DIR")
    c.add_argument("--json", action="store_true")
    c.add_argument("--fixtures-root", default=None, metavar="DIR",
                   help="a Raqib checkout: the catalog's fixture paths (tests/fixtures/...) are relative to it"
                        " (default: the checkout this raqib runs from; an installed raqib has no fixtures)")
    s = sub.add_parser("suspect", help="ask a model to raise suspicion (A2: never acquit)")
    rule_options(s)
    s.add_argument("--findings", metavar="FILE", help="findings file (default: run the rules)")
    s.add_argument("--backend", default="ollama", choices=("ollama", "anthropic", "fake"))
    s.add_argument("--model", help="model name (ollama default %s, anthropic default %s)"
                   % (suspect_backends.DEFAULT_OLLAMA_MODEL, suspect_backends.DEFAULT_ANTHROPIC_MODEL))
    s.add_argument("--ollama-url", metavar="URL", help="default: OLLAMA_HOST or http://localhost:11434")
    s.add_argument("--effort", default=suspect_backends.DEFAULT_EFFORT, choices=suspect_backends.EFFORTS,
                   help="anthropic effort level")
    s.add_argument("--allow-fallback", action="store_true",
                   help="anthropic only: let another model answer a refused window (default off;"
                        " such answers are labelled answered_by and counted)")
    s.add_argument("--answers", metavar="FILE", help="canned answers for the fake backend")
    s.add_argument("--threshold", type=float, default=suspect_core.DEFAULT_THRESHOLD)
    s.add_argument("--window", type=int, default=suspect_core.DEFAULT_WINDOW, help="lines per window")
    s.add_argument("-o", "--out", metavar="FILE", help="suspicion file (default: stdout)")
    u = sub.add_parser("ui", help="read-only HTML view of a trace (timeline, findings, silence)")
    rule_options(u)
    u.add_argument("--findings", metavar="FILE", help="use this findings file instead of running the rules")
    u.add_argument("--suspicion", metavar="FILE", help="suspicion.jsonl written by `suspect`")
    u.add_argument("-o", "--out", metavar="FILE", help="HTML file to write (default: stdout)")
    u.add_argument("--serve", action="store_true", help="serve the page on 127.0.0.1 instead")
    u.add_argument("--port", type=int, default=8765, help="port for --serve (default 8765; 0: any free port)")
    u.add_argument("--refresh", type=_refresh, default=None, metavar="N",
                   help="--serve: the page reloads every N seconds, 1..%d (default %d); a static file never does"
                        % (ui.REFRESH_MAX, ui.REFRESH_DEFAULT))
    e = sub.add_parser("eval", help="score rules and candidate models on labelled events (M2.2)")
    e.add_argument("--events", default=None, metavar="FILE",
                   help="labelled events (default: %s; an installed raqib has none)" % EVENTS_SOURCE)
    e.add_argument("--candidate", action="append", default=[], metavar="SPEC",
                   help="ollama[:MODEL], anthropic[:MODEL] or fake:ANSWERS.json (repeatable)")
    e.add_argument("--catalog", default=CATALOG, metavar="DIR", help="rule catalog directory")
    e.add_argument("--ollama-url", metavar="URL", help="default: OLLAMA_HOST or http://localhost:11434")
    e.add_argument("--effort", default=suspect_backends.DEFAULT_EFFORT, choices=suspect_backends.EFFORTS,
                   help="anthropic effort level")
    e.add_argument("--threshold", type=float, default=suspect_core.DEFAULT_THRESHOLD)
    e.add_argument("--window", type=int, default=suspect_core.DEFAULT_WINDOW, help="lines per window")
    e.add_argument("--json", action="store_true", help="print the result as JSON")
    e.add_argument("-o", "--out", metavar="FILE", help="write the result here (default: stdout)")
    d = sub.add_parser("discover", help="find AI agents on a host by what they do (ADR-0004)")
    d.add_argument("--from", dest="from_dir", metavar="DIR",
                   help="read the source texts in DIR: %s, and the samples of the README's Windows loop"
                        " (win-process-<k>.csv, win-tcp-<k>.csv, win-dns-<k>.csv, run.json)"
                        % ", ".join(discover.FILE_NAMES[k] for k in discover.SOURCES))
    d.add_argument("--read", action="append", default=[], metavar="KIND=FILE",
                   help="read one source text; KIND is one of %s (repeatable)" % ", ".join(discover.SOURCES))
    d.add_argument("--window", type=float, default=0.0, metavar="S",
                   help="live on Linux: sample for S seconds, 1 s apart (default 0: one snapshot);"
                        " files: keep timed records of the last S seconds")
    d.add_argument("--samples", type=int, default=None, metavar="N",
                   help="live on Windows: N samples (default %d, 1..%d)" % (discover.WIN_SAMPLES, discover.SAMPLES_MAX))
    d.add_argument("--every", type=float, default=None, metavar="T",
                   help="live on Windows: T seconds between samples (default %g)" % discover.WIN_EVERY)
    d.add_argument("--home", action="append", metavar="DIR",
                   help="live: a home to list footprints in (default: ~, /root and /home/*; Windows: C:\\Users\\*)")
    d.add_argument("--catalog", default=discover.CATALOG, metavar="FILE", help="endpoint and footprint catalog")
    d.add_argument("--save", metavar="DIR", help="live: write the texts read to DIR, to repeat the run with"
                                                 " --from DIR and check every cited line (A5)")
    d.add_argument("--json", action="store_true", help="print the inventory as JSON")
    d.add_argument("-o", "--out", metavar="FILE", help="write the inventory here (default: stdout)")
    d.add_argument("--check", action="store_true",
                   help="measure candidates and act-roots on the catalog's act_root fixtures against act-root's"
                        " fp_budget (A6); exit 1 when over it or a positive is missed")
    d.add_argument("--fixtures-root", default=None, metavar="DIR",
                   help="--check: a Raqib checkout; the fixture paths (tests/fixtures/discover/...) are relative to"
                        " it (default: the checkout this raqib runs from; an installed raqib has no fixtures)")
    w = sub.add_parser("watch", help="install the hooks, watch the trace live, notify, serve the page (M6.1)")
    w.add_argument("project", nargs="?", default=None, help="the project the agent works in (default: .)")
    w.add_argument("--log", metavar="PATH", help="the trace (default: one outside the project)")
    w.add_argument("--no-open", action="store_true", help="do not open the page in the browser")
    w.add_argument("--no-notify", action="store_true", help="no OS notifications (also off when CI is set)")
    w.add_argument("--port", type=int, default=None, metavar="N",
                   help="port of the page on 127.0.0.1 (default %d, else any free port)" % watch.DEFAULT_PORT)
    w.add_argument("--refresh", type=_refresh, default=ui.REFRESH_DEFAULT, metavar="N",
                   help="the page reloads every N seconds, 1..%d (default %d)" % (ui.REFRESH_MAX, ui.REFRESH_DEFAULT))
    # M7.2 (ADR-0007 decision 2): the host, not a name.
    w.add_argument("--host", action="store_true",
                   help="watch this host, not a project: discover in rounds; NEW-AGENT and AGENT-DARK-LIVE knock;"
                        " installs nothing, touches no project")
    w.add_argument("--every", type=float, default=None, metavar="T",
                   help="--host: a round every T seconds (default %g; a reader not back in 2 x T is a hole)"
                        % host.EVERY_DEFAULT)
    w.add_argument("--window", type=float, default=None, metavar="S",
                   help="--host on Linux: each round reads S seconds of /proc snapshots, 1 s apart (default 0: one)")
    w.add_argument("--rounds", type=int, default=None, metavar="N", help="--host: end after N rounds (tests, CI)")
    w.add_argument("--attach-hooks", action="store_true",
                   help="--host: also install raqib watch's hooks into the project a Claude Code tree works in (the"
                        " only write into a project; off by default, ADR-0007 H-1)")
    # M7.4 (ADR-0007 decision 4, E3): the suspect layer over unknown trees, off by default.
    w.add_argument("--suspect", metavar="BACKEND", default=None,
                   help="--host: every N rounds (--suspect-every N, default 10) hand each unknown tree's host record (hashes and names) to the suspect"
                        " layer: ollama[:MODEL], anthropic[:MODEL] or fake:ANSWERS.json; it may raise suspicion, never"
                        " acquit (A2); off by default")
    w.add_argument("--suspect-threshold", type=float, default=None, metavar="X",
                   help="--host --suspect: the suspicion threshold in (0, 1] (default %g)" % suspect_core.DEFAULT_THRESHOLD)
    # M7.6c REDO E-3 (ADR-0008 Amendment E): the suspect layer's period is the watch's option, not a rule's eq
    w.add_argument("--suspect-every", type=int, default=None, metavar="N",
                   help="--host --suspect: ask the suspect layer every N rounds, 1..%d (default %d)"
                        % (host.SUSPECT_EVERY_MAX, host.SUSPECT_EVERY))
    px = sub.add_parser("proxy", help="relay an agent's model API calls and record its tool calls (M5.2, ADR-0003)")
    px.add_argument("--listen", required=True, metavar="127.0.0.1:PORT",
                    help="where the agent's base URL points; 127.0.0.1 only (PORT 0: any free port)")
    px.add_argument("--upstream", required=True, metavar="URL",
                    help="the model API, https://host[:port][/path]; certificates are verified")
    px.add_argument("--log", required=True, metavar="PATH", help="the trace the proxy appends to")
    px.add_argument("--cwd", metavar="DIR", help="the cwd written on proxy lines: where the agent works"
                                                 " (default: the proxy's own working directory)")
    px.add_argument("--allow-plain-upstream", action="store_true",
                    help="let --upstream be http:// to a loopback address, 127.0.0.0/8 or ::1 (for tests;"
                         " never a remote host)")
    osx = sub.add_parser("os-sysmon", help="record the Sysmon events of an agent's process tree (M5.3, ADR-0003)")
    osx.add_argument("--root", required=True, metavar="PID[:GUID]",
                     help="the agent's process id, the root of the tree (Claude Code on Windows: claude.exe's pid);"
                          " without a Sysmon ProcessGuid the latest process that held PID in the export")
    osx.add_argument("--log", required=True, metavar="PATH", help="the trace os-sysmon appends to")
    osx.add_argument("--from", dest="from_path", metavar="FILE.xml",
                     help="read an export (wevtutil qe %s /f:xml) instead of the live channel (any system)"
                          % os_sysmon.CHANNEL)
    osx.add_argument("--cwd", metavar="DIR", help="the cwd written on the lines, an absolute directory (default: the"
                                                 " root's CurrentDirectory in its event 1, else no cwd)")
    a = sub.add_parser("app", help="open Raqib as a desktop window: the host first, Watch this host, or a project"
                                   " (M6.4, M7.3)")
    a.add_argument("project", nargs="?", default=None,
                   help="the project preselected for \"Watch a project\" (default: .); the window opens on the host")
    a.add_argument("--every", type=float, default=None, metavar="T",
                   help="the host watch: a round every T seconds (default %g; a reader not back in 2 x T is a hole)"
                        % host.EVERY_DEFAULT)
    a.add_argument("--log", metavar="PATH", help="the trace (default: one outside the project)")
    a.add_argument("--no-notify", action="store_true", help="no OS notifications (also off when CI is set)")
    a.add_argument("--port", type=int, default=None, metavar="N",
                   help="port of the page on 127.0.0.1 (default %d, else any free port)" % watch.DEFAULT_PORT)
    a.add_argument("--refresh", type=_refresh, default=ui.REFRESH_DEFAULT, metavar="N",
                   help="the page reloads every N seconds, 1..%d (default %d)" % (ui.REFRESH_MAX, ui.REFRESH_DEFAULT))
    dr = sub.add_parser("doctor", help="say in one screen what watch needs and is missing (M6.3; read-only)")
    dr.add_argument("project", nargs="?", default=None, help="the project the agent works in (default: .)")
    return p


def _refresh(text):
    """I-1: --refresh N, a whole number of seconds from 1 to ui.REFRESH_MAX (else exit 2)."""
    try:
        return ui.check_refresh(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def _context(args):
    scope = list(args.scope)
    root = os.path.abspath(args.root) if args.root else None
    if args.handoff:
        scope += rule_context.scope_from_handoff(_read_text(args.handoff, "HANDOFF"))
        root = root or os.path.dirname(os.path.abspath(args.handoff))
    ctx = {"scope": scope} if scope else {}
    if ctx and root:
        ctx["root"] = root
    return ctx


def _gap_seconds(args):
    try:
        if args.gap_seconds is not None:
            return silence.check_gap_seconds(args.gap_seconds, "--gap-seconds")
        return silence.gap_seconds_from(os.environ)
    except ValueError as exc:
        raise UsageError(str(exc))


def _read_text(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise UsageError("cannot read %s %s: %s" % (what, path, exc))


def _read_trace(path):
    try:
        return trace.read_numbered(path)
    except OSError as exc:
        raise UsageError("cannot read trace %s: %s" % (path, exc))


def _catalog(directory):
    try:
        return engine.load_catalog(directory)
    except engine.RuleError as exc:
        raise UsageError(str(exc))


def run_rules(records, rules, ctx, gap_seconds):
    """All findings (silence + catalog + cross-source + tree anchors) and the
    notes of rules that did not run or could not judge every line."""
    found = report.with_silence_class(silence.findings(records, gap_seconds))
    catalog_found, notes = engine.evaluate(rules, records, ctx)
    cross_found, cross_notes = cross.findings(records)   # M5.3: nothing, no note, without os lines (C-2)
    tree_found, tree_notes = tree.findings(records)      # M4.3: nothing, no note, without git keys (J-3)
    return found + catalog_found + cross_found + tree_found, notes + cross_notes + tree_notes


def rules_overlay_cmd(args, out):
    """M7.6 E2: raqib rules [--set | --threshold | --add | --reset] [--json]."""
    if args.out or args.scope or args.handoff or args.root or args.gap_seconds is not None or args.catalog != CATALOG:
        raise UsageError("-o, --scope, --handoff, --root, --gap-seconds and --catalog apply to `raqib rules TRACE`")
    said = None
    try:
        if args.set:
            said = overlay.set_status(args.set[0], args.set[1])
        elif args.threshold:
            said = overlay.set_threshold(*args.threshold, say=_say_measuring)
        elif args.add:
            said = overlay.add_rule(args.add)
        elif args.reset:
            said = overlay.reset(args.reset)
    except overlay.OverlayError as exc:
        raise UsageError("refused: %s" % exc)
    rules = _overlay_catalog()
    info = overlay.describe(rules)
    if args.json:
        out.write(json.dumps({"rules": overlay.listing(rules), "overlay": info, "said": said}, indent=2,
                             sort_keys=True, ensure_ascii=True) + "\n")
        return 0
    if said:
        out.write("raqib rules: %s\n" % said)
    out.write(overlay.table_text(overlay.listing(rules)))
    for line in overlay.start_lines(info):
        out.write("raqib rules: %s\n" % line)
    return 0


def _say_measuring(line):
    """M7.6c REDO E-7: said while a measurement of the overlay's thresholds runs (it may take seconds)."""
    sys.stderr.write("raqib: %s\n" % line)
    sys.stderr.flush()


def _overlay_catalog():
    """M7.6: the catalog as every watch loads it: the package's, ~/.raqib/rules.d and ~/.raqib/rules.yaml.
    M7.6c REDO E-7: measured only when the overlay or the catalog changed since the last measurement."""
    try:
        return overlay.load(say=_say_measuring)
    except engine.RuleError as exc:
        raise UsageError(str(exc))


def cmd_rules(args, out):
    if args.trace is None:
        return rules_overlay_cmd(args, out)
    if args.set or args.threshold or args.add or args.reset or args.json:
        raise UsageError("--set, --threshold, --add, --reset and --json apply to `raqib rules` with no TRACE")
    overlay_note()   # M7.6 REDO A-7
    numbered, problems = _read_trace(args.trace)
    rules = _catalog(args.catalog)
    records = [rec for _, rec in numbered]
    found, notes = run_rules(records, rules, _context(args), _gap_seconds(args))
    text = "".join(json.dumps(f, sort_keys=True, ensure_ascii=True) + "\n" for f in found)
    if args.out:
        sidecar = {"trace": args.trace, "trace_sha256": _trace_sha256(args.trace), "records": len(records),
                   "notes": notes, "rules": report.rule_table(rules), "context": _context(args),
                   "problems": problems}
        try:
            with open(args.out, "w", encoding="ascii") as f:
                f.write(text)
            with open(args.out + ".notes.json", "w", encoding="ascii") as f:
                f.write(json.dumps(sidecar, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
        out.write("raqib: %d findings -> %s (notes: %s.notes.json)\n" % (len(found), args.out, args.out))
    else:
        out.write(text)
    rep = report.build(args.trace, numbered, problems, found, notes, report.rule_table(rules), "rules")
    return rep["exit"]


def _trace_sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError as exc:
        raise UsageError("cannot read trace %s: %s" % (path, exc))


def _check_notes(notes, path):
    ok = isinstance(notes, list) and all(
        isinstance(n, dict) and all(isinstance(n.get(k), str) for k in ("rule_id", "status", "detail"))
        for n in notes)
    if not ok:
        raise UsageError("bad notes file %s: notes must be a list of {rule_id, status, detail}" % path)
    return notes


def _read_findings(path, with_sidecar=False):
    """Findings from a file; lines that are not JSON objects become rejected
    findings so the report raises them (A5). With with_sidecar, also return
    the FILE.notes.json record (or None)."""
    found = []
    for number, raw in enumerate(_read_text(path, "findings file").split("\n"), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except ValueError:
            item = None
        found.append(item if isinstance(item, dict) else {"_line": number})
    notes_path = path + ".notes.json"
    notes = sidecar = None
    if os.path.exists(notes_path):
        try:
            sidecar = json.loads(_read_text(notes_path, "notes file"))
            notes = _check_notes(sidecar["notes"], notes_path)
        except (ValueError, KeyError, TypeError) as exc:
            raise UsageError("bad notes file %s: %s" % (notes_path, exc))
    return (found, notes, sidecar) if with_sidecar else (found, notes)


def _read_jsonl(path, what):
    items = []
    for raw in _read_text(path, what).split("\n"):
        if raw.strip():
            try:
                items.append(json.loads(raw))
            except ValueError:
                items.append(None)
    return items


def _read_suspicion(path):
    lines = _read_jsonl(path, "suspicion file")
    run = None
    if os.path.exists(path + ".run.json"):
        try:
            run = json.loads(_read_text(path + ".run.json", "suspicion run record"))
        except ValueError as exc:
            raise UsageError("bad suspicion run record %s.run.json: %s" % (path, exc))
    return lines, run


def _report(args):
    """(report dict, numbered, problems) for report and ui."""
    numbered, problems = _read_trace(args.trace)
    rules = _catalog(args.catalog)
    suspicion, suspicion_run = _read_suspicion(args.suspicion) if args.suspicion else (None, None)
    extra = []
    if args.findings:
        found, notes, sidecar = _read_findings(args.findings, with_sidecar=True)
        source = "file %s" % args.findings
        # A findings file proves nothing about another trace (A3).
        if sidecar is not None and sidecar.get("trace_sha256") != _trace_sha256(args.trace):
            extra.append({"kind": "findings-for-another-trace",
                          "detail": "%s.notes.json records trace %s with sha256 %s, but this trace's"
                                    " sha256 is %s: the findings do not describe it (re-run `rules`)"
                                    % (args.findings, sidecar.get("trace"), sidecar.get("trace_sha256"),
                                       _trace_sha256(args.trace))})
    else:
        records = [rec for _, rec in numbered]
        found, notes = run_rules(records, rules, _context(args), _gap_seconds(args))
        source = "rules run on this trace (catalog %s)" % os.path.relpath(args.catalog, ROOT) \
            if os.path.abspath(args.catalog).startswith(ROOT) else "rules run on this trace"
    rep = report.build(args.trace, numbered, problems, found, notes, report.rule_table(rules), source,
                       suspicion, suspicion_run, extra_alarms=extra)
    return rep, numbered, problems


def overlay_note(err=None):
    """M7.6 REDO A-7 (ADR-0008 Amendment A, Q-2): `raqib rules TRACE`, report
    and ui judge the catalog as declared; when an overlay file exists they
    say so in one line, on stderr (stdout holds findings, JSON or HTML)."""
    path = overlay.overlay_path()
    if os.path.exists(path):
        (err or sys.stderr).write("raqib: an overlay exists at %s; this command judges the catalog as declared\n"
                                  % path)
        return True
    return False


def cmd_report(args, out):
    overlay_note()
    rep, _, _ = _report(args)
    if args.json:
        out.write(json.dumps(rep, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    else:
        out.write(report.render_text(rep))
    return rep["exit"]


def benign_default(root=ROOT):
    corpus = fixtures.benign_corpus(os.path.join(root, "tests", "fixtures", "rules", "benign"))
    real = sorted(os.path.join(root, "tests", "fixtures", n)
                  for n in os.listdir(os.path.join(root, "tests", "fixtures")) if n.endswith(".log"))
    return corpus + real


def cmd_check_rules(args, out):
    rules = _catalog(args.catalog)
    root = os.path.abspath(args.fixtures_root) if args.fixtures_root else ROOT
    if not os.path.isdir(os.path.join(root, "tests", "fixtures")):
        raise UsageError("no rule fixtures in %s: check-rules measures each rule on the fixtures of a Raqib"
                         " checkout, which an installed raqib does not carry; pass --fixtures-root CHECKOUT"
                         % os.path.join(root, "tests", "fixtures"))
    try:
        reports = fixtures.check_catalog(rules, root, benign_default(root))
        # M5.3 ruling D-11: the cross-source code rule is measured on its fixtures too.
        reports.append(cross.check(fixtures.load_fixture, root, benign_default(root)))
        # M4.3 ruling J-1: the two tree anchors too.
        reports += tree.check(fixtures.load_fixture, root, benign_default(root))
    except (fixtures.FixtureError, OSError) as exc:
        raise UsageError(str(exc))
    if args.json:
        out.write(json.dumps(reports, indent=2, sort_keys=True) + "\n")
    else:
        out.write("%-16s %-16s %-8s %-9s %s\n" % ("rule", "verdict", "fp_rate", "fp_budget", "fixtures"))
        for r in reports:
            rate = "-" if r["fp_rate"] is None else "%.3f" % r["fp_rate"]
            out.write("%-16s %-16s %-8s %-9g %d positive; negatives incl. benign: %d measured,"
                      " %d unmeasured (missing context or unjudgeable lines)\n" % (
                          r["rule_id"], r["verdict"], rate, r["fp_budget"], len(r["positives"]),
                          r["measured"], r["unmeasured"]))
    return 0 if all(r["verdict"] in ("ok", "disabled") for r in reports) else 1


def cmd_suspect(args, out):
    numbered, problems = _read_trace(args.trace)
    records = [rec for _, rec in numbered]
    if args.findings:
        found = _read_findings(args.findings)[0]
        for number, f in enumerate(found, start=1):
            try:
                engine.check_finding(f)
            except engine.FindingError as exc:
                raise UsageError("findings file %s, finding %d: %s" % (args.findings, number, exc))
    else:
        found, _ = run_rules(records, _catalog(args.catalog), _context(args), _gap_seconds(args))
    try:
        backend = suspect_backends.make_backend(args.backend, model=args.model, ollama_url=args.ollama_url,
                                                effort=args.effort, answers=args.answers,
                                                allow_fallback=args.allow_fallback)
        _remote_notice(backend)
        lines, summary = suspect_core.run(records, found, backend, args.threshold, args.window)
    except ValueError as exc:
        raise UsageError(str(exc))
    text = "".join(json.dumps(line, sort_keys=True, ensure_ascii=True) + "\n" for line in lines)
    if args.out:
        try:
            with open(args.out, "w", encoding="ascii") as f:
                f.write(text)
            with open(args.out + ".run.json", "w", encoding="ascii") as f:
                f.write(json.dumps(dict(summary, trace=args.trace), indent=2, sort_keys=True) + "\n")
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
    else:
        out.write(text)
    sys.stderr.write("raqib: %d windows judged by %s/%s: %d raised, %d errors, %d below threshold"
                     " (A2: below threshold is not a clearance)\n" % (
                         summary["windows"], summary["backend"], summary["model"], summary["raised"],
                         summary["errors"], summary["below_threshold"]))
    if summary["answered_by_other_model"]:
        sys.stderr.write("raqib: %d windows were answered by another model than %s (server-side fallback)\n"
                         % (summary["answered_by_other_model"], summary["model"]))
    if problems or not records:
        sys.stderr.write("raqib: the trace has %s; run `report` for the alarms\n"
                         % ("no records" if not records else "%d corrupt lines" % len(problems)))
        return 1
    if summary["raised"]:
        return 1
    return 3 if summary["errors"] else 0


def cmd_ui(args, out):
    overlay_note()   # M7.6 REDO A-7
    gap = _gap_seconds(args)
    if args.refresh is not None and not args.serve:
        raise UsageError("--refresh applies to --serve: a static page never reloads itself")
    if args.serve:
        if args.out:
            raise UsageError("use either -o or --serve")
        _report(args)  # fail early on unreadable input
        refresh = ui.REFRESH_DEFAULT if args.refresh is None else args.refresh

        def page():
            rep, numbered, problems = _report(args)
            return ui.render(rep, numbered, problems, gap, refresh=refresh)
        try:
            server = ui.make_server(page, args.port, refresh=refresh)
        except (OSError, OverflowError) as exc:
            raise UsageError("cannot serve on 127.0.0.1:%s: %s" % (args.port, exc))
        out.write("raqib: serving %s at http://127.0.0.1:%d/ (read-only; Ctrl-C to stop)\n"
                  % (args.trace, server.server_address[1]))
        out.flush()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    rep, numbered, problems = _report(args)
    text = ui.render(rep, numbered, problems, gap)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
        out.write("raqib: %s -> %s (%s)\n" % (args.trace, args.out, rep["result"]))
    else:
        out.write(text)
    return rep["exit"]


def _remote_notice(backend):
    if getattr(backend, "remote", False):
        sys.stderr.write("raqib: note: %s is not on this machine; trace metadata is sent to it\n"
                         % backend.url)
    elif backend.name == "anthropic":
        sys.stderr.write("raqib: note: trace metadata is sent to the Anthropic API\n")
        if getattr(backend, "allow_fallback", False):
            sys.stderr.write("raqib: note: server-side fallback is on; another model may answer\n")


def make_candidate(spec, args):
    name, _, rest = spec.partition(":")
    if name == "fake":
        if not rest:
            raise UsageError("candidate fake needs a file: fake:ANSWERS.json")
        return suspect_backends.make_backend("fake", answers=rest)
    if name not in ("ollama", "anthropic"):
        raise UsageError("unknown candidate %r (ollama[:MODEL], anthropic[:MODEL], fake:FILE)" % spec)
    return suspect_backends.make_backend(name, model=rest or None, ollama_url=args.ollama_url,
                                         effort=args.effort)


def cmd_eval(args, out):
    if args.events is None:
        if not os.path.isfile(EVENTS):
            raise UsageError("no labelled events at %s: eval reads %s; an installed raqib carries none"
                             % (EVENTS, EVENTS_SOURCE))
        args.events = EVENTS
    try:
        events = evaluation.load_events(args.events)
        backends = [make_candidate(spec, args) for spec in args.candidate]
        for backend in backends:
            _remote_notice(backend)
        suspect_core.check_threshold(args.threshold)
        result = evaluation.evaluate(events, _catalog(args.catalog), backends, args.threshold,
                                     args.window, silence.gap_seconds_from(os.environ))
    except ValueError as exc:
        raise UsageError(str(exc))
    source = os.path.relpath(args.events, ROOT) if os.path.abspath(args.events).startswith(ROOT) \
        else args.events
    text = (json.dumps(dict(result, source=source), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
            if args.json else evaluation.render_text(result, source))
    if args.out:
        try:
            with open(args.out, "w", encoding="ascii") as f:
                f.write(text)
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
        out.write("raqib: evaluation of %d events -> %s\n" % (result["events"], args.out))
    else:
        out.write(text)
    # A row with errors is an incomplete evaluation (A3).
    return 3 if any(row["errors"] for row in result["rows"]) else 0


def cmd_discover(args, out):
    try:
        catalog = discover.load_catalog(args.catalog)
    except discover.CatalogError as exc:
        raise UsageError(str(exc))
    if not (args.window >= 0 and args.window != float("inf")):
        raise UsageError("--window must be a finite number of seconds >= 0")
    if args.check:
        return _discover_check(args, catalog, out)
    if args.fixtures_root:
        raise UsageError("--fixtures-root applies to --check only")
    texts, holes = {}, []
    if args.from_dir:
        if not os.path.isdir(args.from_dir):
            raise UsageError("--from %s: not a directory" % args.from_dir)
        try:
            texts, holes = discover.read_dir(args.from_dir)
        except ValueError as exc:
            raise UsageError(str(exc))
        if not texts:
            raise UsageError("--from %s: none of %s, nor a numbered sample (win-tcp-1.csv, ...), is there" % (
                args.from_dir, ", ".join(discover.FILE_NAMES[k] for k in discover.SOURCES)))
    paths = {}
    for spec in args.read:
        kind, sep, path = spec.partition("=")
        if not sep or kind not in discover.SOURCES or not path:
            raise UsageError("--read %s: use KIND=FILE with KIND one of %s" % (spec, ", ".join(discover.SOURCES)))
        if kind in paths or kind in texts:
            raise UsageError("--read %s: source %s given twice" % (spec, kind))
        paths[kind] = path
    texts.update(discover.read_inputs(paths))
    windows = sys.platform == "win32"
    if texts:
        if args.save or args.home or args.samples is not None or args.every is not None:
            raise UsageError("--save, --home, --samples and --every apply to a live run (no --from, no --read)")
        inv = discover.run(texts, catalog, window=args.window, holes=holes,
                           run=discover.run_record(args.from_dir) if args.from_dir else None)   # D-3
    else:
        if (args.samples is not None or args.every is not None) and not windows:
            raise UsageError("--samples and --every apply to a live run on Windows; on %s use --window S"
                             % sys.platform)
        if windows and args.window:
            raise UsageError("--window S applies to files and to a live run on Linux; on Windows use --samples N"
                             " --every T")
        n = discover.WIN_SAMPLES if args.samples is None else args.samples
        every = discover.WIN_EVERY if args.every is None else args.every
        if not 1 <= n <= discover.SAMPLES_MAX:
            raise UsageError("--samples must be a whole number from 1 to %d" % discover.SAMPLES_MAX)
        if not (0 <= every <= 86400):
            raise UsageError("--every must be a number of seconds from 0 to 86400")
        info = {}
        try:
            texts, holes, samples = discover.collect_live(catalog, window=args.window, homes=args.home,
                                                          win_samples=n, win_every=every, run_info=info)
        except discover.LiveRefused as exc:
            sys.stderr.write("raqib: discover refused: %s\n" % exc)
            return 2
        if args.save:
            extra = dict(info, export="windows-live") if info else None
            try:
                written = discover.save(texts, args.save, holes, samples, extra)
            except OSError as exc:
                raise UsageError("cannot write %s: %s" % (args.save, exc))
            sys.stderr.write("raqib: texts read -> %s (repeat with --from %s)\n" % (", ".join(written), args.save))
        inv = discover.run(texts, catalog, holes=holes, live=True, run=info)
    text = (json.dumps(inv, indent=2, sort_keys=True, ensure_ascii=True) + "\n" if args.json
            else discover.render_text(inv))
    if args.out:
        try:
            with open(args.out, "w", encoding="ascii", errors="backslashreplace") as f:
                f.write(text)
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
        out.write("raqib: inventory of %d records -> %s (%s)\n" % (inv["records"], args.out, inv["result"]))
    else:
        out.write(text)
    return inv["exit"]


def _discover_check(args, catalog, out):
    """M5.0b E4: discover --check, as check-rules measures the rules (A6)."""
    if args.from_dir or args.read or args.save or args.home or args.window:
        raise UsageError("--check measures the catalog's fixtures: it takes no --from, --read, --save, --home"
                         " or --window")
    root = os.path.abspath(args.fixtures_root) if args.fixtures_root else discover.ROOT
    if not os.path.isdir(os.path.join(root, "tests", "fixtures")):
        raise UsageError("no discover fixtures in %s: --check measures on the fixtures of a Raqib checkout, which an"
                         " installed raqib does not carry; pass --fixtures-root CHECKOUT"
                         % os.path.join(root, "tests", "fixtures"))
    try:
        report = discover.check(catalog, root)
    except ValueError as exc:
        raise UsageError(str(exc))
    text = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n" if args.json
            else discover.render_check(report))
    if args.out:
        try:
            with open(args.out, "w", encoding="ascii", errors="backslashreplace") as f:
                f.write(text)
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
        out.write("raqib: discover check -> %s (exit %d)\n" % (args.out, report["exit"]))
    else:
        out.write(text)
    return report["exit"]


def _watch_setup():
    """(rules, gap, evaluator) of `watch`, and of every watch `app` starts.
    M7.6: the rules are the catalog with ~/.raqib/rules.d and the overlay."""
    rules = _overlay_catalog()
    try:
        gap = silence.gap_seconds_from(os.environ)
    except ValueError as exc:
        raise UsageError(str(exc))

    def evaluator(project):
        # ADR-0005 B-6: <project>/HANDOFF.md gives the scope, read as `report --handoff` reads it.
        handoff = os.path.join(project, "HANDOFF.md")
        if os.path.isfile(handoff):
            ctx = _context(argparse.Namespace(scope=[], root=None, handoff=handoff))
            note = ("%s Scope: %s (root %s), as report --handoff" % (handoff, ", ".join(ctx["scope"]), ctx["root"])
                    if ctx else "%s has no Scope: block: no scope; rules that need one do not run" % handoff)
        else:
            ctx, note = {}, "no HANDOFF.md in the project: no scope; rules that need one do not run"
        evaluate = (lambda records: run_rules(records, rules, ctx, gap))
        evaluate.context = ctx   # M7.6: what a rule off would have judged is counted with the same context
        return evaluate, note
    return rules, gap, evaluator


def cmd_watch(args, out):
    if args.host:
        return _watch_host(args, out)
    if (args.every is not None or args.window is not None or args.rounds is not None or args.attach_hooks
            or args.suspect is not None or args.suspect_threshold is not None or args.suspect_every is not None):
        raise UsageError("--every, --window, --rounds, --attach-hooks and --suspect apply to watch --host only")
    rules, gap, evaluator = _watch_setup()
    try:
        return watch.command(args.project, args.log, args.no_open, args.no_notify, args.port, out,
                             evaluator, rules, gap, refresh=args.refresh)
    except watch.WatchError as exc:
        raise UsageError(str(exc))


def _watch_host(args, out):
    """M7.2: raqib watch --host [--every T] [--window S] [--rounds N]."""
    if args.project is not None:
        raise UsageError("--host watches this host, not a project: give no PROJECT (watch --host, or watch PROJECT)")
    if args.log is not None:
        raise UsageError("--host keeps its record under ~/.raqib/host/: --log applies to a project watch")
    every = host.EVERY_DEFAULT if args.every is None else args.every
    if not (0.1 <= every <= 86400):
        raise UsageError("--every must be a number of seconds from 0.1 to 86400")
    window = 0.0 if args.window is None else args.window
    if not (0 <= window <= 3600):
        raise UsageError("--window must be a number of seconds from 0 to 3600")
    if window and not sys.platform.startswith("linux"):
        raise UsageError("--window S applies to Linux; on %s a round reads one sample" % sys.platform)
    if args.rounds is not None and not 1 <= args.rounds <= 1000000:
        raise UsageError("--rounds must be a whole number from 1 to 1000000")
    try:
        catalog = discover.load_catalog(discover.CATALOG)
    except discover.CatalogError as exc:
        raise UsageError(str(exc))
    rules = _overlay_catalog()   # M7.6 (ADR-0008): the overlay and rules.d, said at the start
    if args.suspect_threshold is not None and args.suspect is None:
        raise UsageError("--suspect-threshold applies with --suspect")
    if args.suspect_every is not None:   # M7.6c REDO E-3
        if args.suspect is None:
            raise UsageError("--suspect-every applies with --suspect")
        try:
            host.check_suspect_every(args.suspect_every)
        except ValueError as exc:
            raise UsageError("--suspect-every: %s" % exc)
    backend = None
    if args.suspect is not None:
        try:
            if args.suspect_threshold is not None:
                suspect_core.check_threshold(args.suspect_threshold)
            backend = host.suspect_backend(args.suspect)
        except ValueError as exc:
            raise UsageError(str(exc))
        _remote_notice(backend)
    try:
        return host.command(catalog, rules, every=every, window=window, rounds=args.rounds, no_open=args.no_open,
                            no_notify=args.no_notify, port=args.port, out=out, refresh=args.refresh,
                            attach_hooks=args.attach_hooks, suspect=backend,
                            suspect_threshold=args.suspect_threshold, suspect_every=args.suspect_every)
    except watch.WatchError as exc:
        raise UsageError(str(exc))


def cmd_app(args, out):
    rules, gap, evaluator = _watch_setup()
    if args.project is not None and not os.path.isdir(args.project):
        raise UsageError("not a directory: %s" % args.project)
    every = host.EVERY_DEFAULT if args.every is None else args.every
    if not (0.1 <= every <= 86400):   # M7.3: as watch --host
        raise UsageError("--every must be a number of seconds from 0.1 to 86400")
    # A-10: --log is the trace of the project on the command line only; Browse's projects get their default.
    options = window_app.Options(evaluator, rules, gap, log=args.log, no_notify=args.no_notify, port=args.port,
                                 refresh=args.refresh, log_project=os.path.abspath(args.project or "."),
                                 every=every, setup=_watch_setup)
    try:
        return window_app.run(args.project, options, out=out)
    except window_app.AppError as exc:
        raise UsageError(str(exc))


def cmd_doctor(args, out):
    return doctor.run(args.project, out)


def cmd_proxy(args, out):
    try:
        return proxy.run(args.listen, args.upstream, args.log, args.allow_plain_upstream, out, cwd=args.cwd)
    except proxy.UsageError as exc:
        raise UsageError(str(exc))


def cmd_os_sysmon(args, out):
    try:
        return os_sysmon.run(args.root, args.log, from_path=args.from_path, cwd=args.cwd, out=out)
    except os_sysmon.UsageError as exc:
        raise UsageError(str(exc))


def main(argv=None, out=None):
    """The `raqib` console script and python -m raqib (out None: stdout,
    where a path the console cannot encode is escaped, not a crash)."""
    if out is None:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="backslashreplace")
        out = sys.stdout
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        command = {"rules": cmd_rules, "report": cmd_report, "check-rules": cmd_check_rules,
                   "suspect": cmd_suspect, "ui": cmd_ui, "eval": cmd_eval,
                   "discover": cmd_discover, "watch": cmd_watch, "app": cmd_app, "doctor": cmd_doctor,
                   "proxy": cmd_proxy, "os-sysmon": cmd_os_sysmon}[args.command]
        return command(args, out)
    except UsageError as exc:
        sys.stderr.write("raqib: %s\n" % exc)
        return 2
