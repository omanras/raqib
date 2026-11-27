"""M9.2 (ADR-0010 decision 7): the README's top is one screen. README.md says what Raqib is, how to install
and start it, what an alarm looks like, where it runs and the commands; docs/GUIDE.md holds everything else
the README said, under the README's own headings, word for word. No sentence is lost: the README as it was
before (c13b9ad) is kept as a fixture and every sentence of it is found in one of the two files.
REDO (ADR-0010 Amendment E): "Where it runs" is written fresh, each fact pinned by the code or the guide (E-1);
one sentence names what prints the sample (E-2); the Commands table is for a person, every row checked against
the parser (E-3); raqib/ cites docs/GUIDE.md, not the README, for what moved there (E-4); the nothing-lost test
counts, reads under each heading and runs both ways (E-6); a split section of the guide links its start (E-7)."""
import argparse
import collections
import contextlib
import hashlib
import io
import itertools
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover, doctor, notify, report, watch  # noqa: E402
from readme_text import GUIDE, GUIDE_PATH, README, README_PATH, flat, headings, section, units  # noqa: E402

DOCS = ROOT / "tests" / "fixtures" / "docs"
BEFORE = DOCS / "README-before-M9.2.md"
BEFORE_SHA256 = "2df4f35816a778d5d702641f2184cd7ee6993e865df6ebec65555c66e5eeda42"   # git show c13b9ad:README.md
# The README's headings before this task, in their order (E3).
OLD_HEADINGS = ["Install and watch", "Watch a project", "Doctor", "Watch the host", "The window", "Choose the rules",
                "How it works", "Manual steps", "What it catches", "What it cannot see", "Commands",
                "Watch another agent", "Watch what the system saw (os-sysmon)", "Find the agents on a host (discover)",
                "More", "Licence"]
NEW_HEADINGS = ["Install and watch", "Watch a project", "Doctor", "What an alarm looks like", "Where it runs",
                "Commands", "More", "Licence"]
# Sentences deliberately changed on the way (old -> new). E-7: "this quickstart" names where the quickstart is
# (ADR-0010 decision 6: the README's install block). Link targets are not words: a guide link is relative to
# docs/, and the comparisons below read every link as the repository path it names.
CHANGED = {
    # M15.2b (ADR-0014 AE-2): event 11 is said under the same rule as events 1, 3 and 22
    "A read that fails, times out, reaches the cap or lags by more than a round is a hole of its round; a stopped "
    "or cleared channel is said in the third of three rounds in a row that each sampled a process created a round "
    "earlier and read no event 1 at all, and then its read restarts - on a quiet desktop it is not said, a hole "
    "that remains; an image whose event 1 does not come while others do is a note (left out by its configuration, "
    "or late), withdrawn when an event 1 of that image comes and said again at its next miss; a kind not read after "
    "three rounds (no event 1, 3 or 22) is said once, and the report lists the kinds read.":
    "A read that fails, times out, reaches the cap or lags by more than a round is a hole of its round; a stopped "
    "or cleared channel is said in the third of three rounds in a row that each sampled a process created a round "
    "earlier and read no event 1 at all, and then its read restarts - on a quiet desktop it is not said, a hole "
    "that remains; an image whose event 1 does not come while others do is a note (left out by its configuration, "
    "or late), withdrawn when an event 1 of that image comes and said again at its next miss; a kind not read after "
    "three rounds (no event 1, 3, 11 or 22) is said once, and the report lists the kinds read.",
    "The last exit criterion of the plan (M3.3) is still open: one person outside the project runs this quickstart"
    " and files one issue.":
    "The last exit criterion of the plan (M3.3) is still open: one person outside the project runs the quickstart"
    " in the README ([Install and watch](README.md#install-and-watch)) and files one issue.",
    # M7.18 (ADR-0007 AT-1): HOST-RHYTHM's level is high; the sentence and the table row say so, nothing else.
    "HOST-RHYTHM (medium) when it talks to one destination and then starts a child within 30 s, 3 times in the last"
    " 10 rounds (the thresholds are in its YAML; on Linux the bytes per connection are recorded from `ss -tinp`, on"
    " Windows they are not read, a hole said once).":
    "HOST-RHYTHM (high) when it talks to one destination and then starts a child within 30 s, 3 times in the last"
    " 10 rounds (the thresholds are in its YAML; on Linux the bytes per connection are recorded from `ss -tinp`, on"
    " Windows a live watch reads them from the kernel's tracing, and where it cannot they are not read, a hole said"
    " once with the reason).",
    "| HOST-RHYTHM | only under `raqib watch --host`: a tree that talks to one destination and then starts a child"
    " within 30 s, 3 times in the last 10 rounds (the think-act cycle; medium; once per streak) |":
    "| HOST-RHYTHM | only under `raqib watch --host`: a tree that talks to one destination and then starts a child"
    " within 30 s, 3 times in the last 10 rounds (the think-act cycle; high; once per streak) |",
    # M15.1 (ADR-0014): two YAML rules more, PERSIST-AUTOSTART and NET-ADMIN-PORT; the two counts move, nothing else
    # M15.2 (ADR-0014 Amendment B): one more, PERSIST-RUN-KEY; the two counts move again
    "**Rules.** Twenty-two rules turn the trace into findings, and every finding cites the trace lines behind it (A5).":
    "**Rules.** Twenty-five rules turn the trace into findings, and every finding cites the trace lines behind it (A5).",
    "The rules are 5 silence rules, 1 cross-source rule (CROSS-SOURCE, `raqib/rules/cross.py`) and 16 more: 14 YAML"
    " rules in `raqib/rules/catalog` and 2 tree anchors (HEAD-UNMOVED, INDEX-UNTOUCHED, `raqib/rules/tree.py`).":
    "The rules are 5 silence rules, 1 cross-source rule (CROSS-SOURCE, `raqib/rules/cross.py`) and 19 more: 17 YAML"
    " rules in `raqib/rules/catalog` and 2 tree anchors (HEAD-UNMOVED, INDEX-UNTOUCHED, `raqib/rules/tree.py`).",
    # M15.2 REDO (ADR-0014 AC-6): what os-sysmon reads and writes names event 13 and the tool registry
    '- **What it reads.** Sysmon events 1 (process create), 11 (file create) and 3 (network connect) of t'
    'he tree under the root: the root, and every process whose parent is in the tree (the ProcessGuid kee'
    'ps a reused pid out).':
    '- **What it reads.** Sysmon events 1 (process create), 11 (file create), 3 (network connect) and 13 '
    "(a value set below the registry's Run or RunOnce key, ADR-0014) of the tree under the root: the root"
    ', and every process whose parent is in the tree (the ProcessGuid keeps a reused pid out).',
    '"os"`, tool `process`, `file` or `net`.':
    '"os"`, tool `process`, `file`, `net` or `registry`.',
    'Hashes of the command line, the path or the destination, never the text; the program name (`bash.exe'
    "`), its image name in discover's form (`input_meta.image`, `bash`; since M7.8), its depth below the "
    "root and its parent's line; the path, redacted as the hook redacts it; the destination port and whet"
    'her it is private.':
    "Hashes of the command line, the path, the destination or the registry's target and value text, never"
    ' the text; for a value set, its name in the clear (redacted, at most 80 characters) and the name of '
    "the program it would run; the program name (`bash.exe`), its image name in discover's form (`input_m"
    "eta.image`, `bash`; since M7.8), its depth below the root and its parent's line; the path, redacted "
    'as the hook redacts it; the destination port and whether it is private.',
}
# The README's own two sentences that "Where it runs" keeps from the old Install and watch (ADR-0010 E-5: the
# Windows install line is in "Where it runs"); the old split rule cuts the first at its colon.
WINDOWS_INSTALL = ("On Windows: `pipx install C:\\path\\to\\raqib` (or `py -m pip install C:\\path\\to\\raqib`), then"
                   " `raqib watch C:\\path\\to\\project`.")
WSL = "Install on the side that runs the agent (Windows or WSL), not both."
MOVED = {"On Windows:": "Where it runs",
         "`pipx install C:\\path\\to\\raqib` (or `py -m pip install C:\\path\\to\\raqib`), then `raqib watch"
         " C:\\path\\to\\project`.": "Where it runs",
         WSL: "Where it runs"}
# E-7: the sections whose beginning stayed in the README; the guide's part begins with this line.
SPLIT = ["Install and watch", "Watch a project", "Doctor"]
LINK_LINE = "This section begins in the README, under [%s](%sREADME.md#%s)."
# E-3: the rows the guide's Commands table gained, as in README's table.
NEW_ROWS = ["| `raqib app [PROJECT]` | open Raqib as a desktop window: the host first, Watch this host, or a project |",
            "| `raqib rules [--set ID on\\|off]` | list every rule; turn a rule on or off; `--new ID`, `--add FILE`,"
            " `--remove NAME` |",
            "| `raqib discover` | find AI agents on a host by what they do |",
            "| `raqib --version` | print raqib <version> and exit 0 |"]
# ADR-0011 G-11 (the Table): a row of the guide's table only (the README names the command in "the rest")
GUIDE_ROWS = ["| `raqib events FILE [--against OTHER]` | check a watch's events file "
              "(`~/.raqib/host/events.jsonl`): every line a `raqib-event/1` event, then one line per run, by its "
              "host and run (ADR-0016): its chain whole (so many lines, and the lines said twice), not whole (and "
              "under it, in the file's order, to a bound of 10 a run that is said: that it begins before this file, "
              "each break - a line before it was removed, changed, added or moved - and each run of lines beside it "
              "- not counted as written by the writer, or put there by another hand - with the line they follow and "
              "the line that names it again), not chained (a run of a Raqib before this one: not a problem) or "
              "taken out (no line holds `prev`, and its version always writes it); exit 0, 1 (a line that is not an "
              "event, a chain not whole or taken out, or no event) or 2 (cannot be read). Each line names the line "
              "its run wrote before it by its sha256 (`prev`), so a line taken out of the middle, changed, added or "
              "moved is seen (but the run's last line: no line names it, so changed, or followed by a line added "
              "after the run ended that names it, it is not seen from the file alone); the chain has no secret, and "
              "an end cut off, or a tail written again with its hashes, is not seen from the file alone. `--against "
              "OTHER`: OTHER is the lines a collector holds (its own export); each is looked for in FILE by host "
              "and id, and those not in FILE and those with other bytes are said by their line numbers in both "
              "(exit 1; 2 where OTHER cannot be read): this, not the file alone, shows a line changed or an end cut "
              "after the collector took it. It needs the collector's lines byte for byte as they were sent (a line "
              "end aside) |",
              # ADR-0011 J (M10.3) and L (its REDO): the forwarder, rows of the guide only (G-11)
              "| `raqib forward [FILE] --to URL --name NAME [--shape raqib\\|hec] [--token-file FILE] [--ca "
              "FILE] [--plain] [--facility N] [--framing octet\\|newline] [--once]` | send every whole line of "
              "a watch's events file (default `~/.raqib/host/events.jsonl`, read only) to one collector, at "
              "least once and in the file's order (but for a line refused once and taken when asked again): "
              "over HTTP (`http://`, `https://`: taken is `acknowledged`, a 2xx) or over syslog "
              "(`syslog+udp://`, `syslog+tcp://`, `syslog+tls://`: one RFC 5424 message a line, the line as "
              "its message, app raqib, the message id the event's kind, the facility 13 unless `--facility N`, "
              "the severity high 2, medium 4, low 5, a hole 4, none and info 6; over tcp and tls framed by "
              "octet count, or --framing newline for a collector that wants lines, and taken is `written`, the "
              "connection ended in order after the batch - not a stored event; `syslog+tcp://` needs its port "
              "written; over udp one datagram a message, taken is `sent`, nothing is known, "
              "and a message over 65000 bytes is refused, counted and passed, never cut; no token)"
              # ADR-0011 W (M10.3c-a): the journal, in the forward row (G-11)
              " or to the system's journal (`journal:`, Linux only: one entry a line by the journal's own "
              "protocol, MESSAGE the line as written, PRIORITY the severity as syslog's, SYSLOG_IDENTIFIER "
              "raqib, SYSLOG_FACILITY 13 unless `--facility N`, and RAQIB_ID, RAQIB_KIND, RAQIB_HOST and "
              "RAQIB_TIME where the event holds them as text; an entry too long for a datagram is handed as a "
              "sealed memory file, never cut; taken is `sent`, nothing is known, at most 250 lines a second; no "
              "token, `--ca`, `--plain`, `--shape hec` or `--framing`)"
              # ADR-0011 Y (M10.3c-b): the Windows event log, in the forward row (G-11)
              " or to the Windows event log (`eventlog:`, Windows only: one event a line in the Application log"
              " under the source `Raqib`, nothing registered, its one string the line as written, its type from"
              " the severity - high Error, medium and a hole Warning, low, info and none Information - and its"
              " id from the kind, 1001 to 1008, else 1000; a line over 30000 characters goes in parts, in order,"
              " id 1009, each with a head `raqib-part I/N id=ID sha256=HEX chars=TOTAL` by which a reader puts"
              " the line back together; taken is `written`, the system's call took the event, at most 100 events"
              " a second, parts counted; no token, `--ca`, `--plain`, `--shape hec`, `--framing` or"
              " `--facility`); a line "
              "that is not an event is skipped and counted, never sent; a line the collector refuses alone is "
              "counted and passed only when it is refused alone again after a later line was taken (until then "
              "it is failing `refusing` and the cursor waits); its cursor and state are "
              "`~/.raqib/forward/NAME.json`; https and syslog+tls are verified by the system's authorities or "
              "`--ca`, and plain http, udp and tcp go only to a loopback address unless `--plain`; the token "
              "only from `--token-file` (HTTP only), never printed (off Windows a file others can read is exit "
              "2; on Windows it is not checked); `--once` exit 0 all taken, 1 not all, 2 usage |",
              "| `raqib forward --status [NAME]` | say a forwarder's state and the lines it refused (`--beat S`: "
              "it writes one at least every S seconds, default 60, at least 1): exit 0 only where nothing is "
              "failing and no whole line has waited longer than a beat; 1 where it is failing (`refusing` too) "
              "or behind; 3 where there is no state, it cannot be read, or it was written more than two beats "
              "ago or in the future (the forwarder is silent) |",
              "| `raqib forward FILE --to URL --name NAME --shape hec --token-file FILE` | one envelope per line "
              "in the shape of Splunk's HTTP event collector (`time` in seconds, `host` the event's "
              "`watch.host`, `source` raqib, `sourcetype` raqib:event, `event` the line unchanged) with "
              "`Authorization: Splunk <token>`; on the collector, the one search for silence: no heartbeat of a "
              "host for more than two beats by the collector's own time of arrival, never the event's `time` "
              "(`kind` heartbeat by `watch.host`; `watch.beat` is the beat) |"]
# The pieces of the guide that are not the old README's (E-6): its title, E-7's lines, E-3's rows (and CHANGED).
# ADR-0007 AG-7: the paragraph "Watch the host" gained after "Every tree gets a source that only reads, by
# itself" (the channel that is there and not read, AF and AG), its sentences as cut() makes them.
HOST_UNREAD = [
    "On Windows, who may read the Sysmon channel is Windows' and Sysmon's configuration (administrators "
     "on a default install); the watch never checks elevation, it reports the denial.",
    "While no round of the watch has read the channel, every tree's source is the host's own record, as "
     "on a machine without Sysmon (but a Claude Code tree with hooks attached, and a tree with no source),"
     " and its source text names the cause (denied, not back in time, could not be run, other failure); in"
     " the first round a tree is in after a read is kept, it is attached again as the os source, and what "
     "its host record wrote stays judged.",
    "While no read is kept, the first failed read knocks once (HOST-HOLE, the cause first) and says one "
     "line in the terminal: the reason, that what lives between two rounds is not seen until a round "
     "reads, and, for a denial, that an elevated terminal (Run as administrator) reads it.",
    "The report's SYSMON line says how many of the reads the rounds asked were kept, and the holes of one"
     " run of failed reads whose words differ only by the round and its time are one line of the report "
     "(ADR-0007 Amendments AF and AG).",
    "A read that fails after rounds that read leaves the os sources in place: what they cannot read is "
     "not seen, and each such run of failed reads knocks once, naming its cause and no terminal.",
    "Under the host watch a tree whose source is os also has the host's own record, from its attach, by "
     "the road a host source has it: a file of its own beside the os follow's, its own feed, the host's "
     "rules and the host source's history (a tree there at the start: its first round's lines are history;"
     " a file that restarts: what follows is live); a write of that file that fails loses those lines and "
     "is a hole, and never ends the follow, and nothing that becomes of the follow stops the file; a tree "
     "known only from the channel has no line, though a child of a sampled tree that only the channel gave"
     " can be in one; so a tree is judged from its host record by the rules, the history and the words of "
     "the watch without Sysmon, and knocks no less: its one first-finding knock may go to an act the os "
     "source saw first, and a tree that began on the host's record alone continues it in a new file whose "
     "lines are numbered from one again (ADR-0007 Amendments AJ, AK and AL).",
    "Each pass of a tree's os follow asks the channel a bounded question, as a round's read does (events "
     "1, 3 and 11: the first pass those since the watch's start, then the records after the highest it has"
     " read in the whole channel, at most the round's cap; a cut is a hole); before it, the follow asks one"
     " of its own for event 13 (a value set under the registry's Run or RunOnce key, at most 500 a pass),"
     " and a value logged after a cut of the other answer waits for the next pass; the rounds' own read "
     "starts at the live reader's start, which can differ by the reader's start delay.",
    "A follow attached again is given the tree the earlier follow published at the end of its last "
     "finished pass, and when the round's read restarts, every follow's bound restarts at the restart's "
     "time, whether or not the record numbers restarted, as the restart's hole says of the follows then "
     "running; a follow attached after a restart says in its source text that it reads from the restart's "
     "time; the follow no longer reads the tree's past before the watch's start (after a restart, nor what"
     " came between the watch's start and it), and a child that started before the watch is not known to "
     "it (the host's record has what a sample shows of it).",
    "A child in the sample is a HostChild line and its event 1 an os line: where one rule fires on both, "
     "the report's listing shows one entry naming both lines, taken for the same act (one image, starts "
     "within 1 s), and counts it once; the join is the listing's only: the window and the state count both"
     " findings, and the catalog's rules knock for the pair at most once.",
    "What an agent without hooks reads with its own code (a file it opens, a directory it lists) is in no"
     " source of the host watch; the proxy source records the tool call where the agent is pointed at it; "
     "the host watch does not read the proxy's trace; the read starts no child and opens no connection, "
     "and Sysmon has no event for a read; a file's deletion is in no source at all.",
    "In the third field run the watched read the watcher's record: the agent read the watch's own files "
     "under the home ([docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).",
]
# M7.21b (ADR-0007 BO-6): what the Windows byte counts are, said in the guide
BYTES_WIN = [
    "On Windows the counts are sums since the watch began, not since the connection did: a connection older than"
    " the watch shows only what it carried since; they lag the kernel by about a second, and UDP carries no counts"
    " yet (QUIC is unseen here).",
    "Reading them needs an administrator and starts one tracing session named for the watch (`raqib-net-PID`, in"
    " memory only); a killed watch leaves it until the next start, which stops it and says so.",
]
GUIDE_NEW = ["# The Raqib guide"] + [LINK_LINE % (t, "", t.lower().replace(" ", "-")) for t in SPLIT] + NEW_ROWS + GUIDE_ROWS + HOST_UNREAD + BYTES_WIN
# M15.1 (ADR-0014 A-3, A-4): the two rules of behaviour, rows of the guide's What it catches
BEHAVIOUR_ROWS = [
    '| PERSIST-AUTOSTART | a file written directly in a Startup folder of Windows (`...\\Microsoft\\Windows'
    "\\Start Menu\\Programs\\Startup\\`, a user's or all users', either slash, any case; `desktop.ini` and de"
    "eper folders left out), read from Sysmon's file line (event 11) of a watched tree or from a Write, E"
    'dit, MultiEdit or NotebookEdit of the hooks, by its path (high). Linux has no os source for it: ther'
    "e only a hooks file tool is judged. A value under the registry's Run or RunOnce key is PERSIST-RUN-K"
    "EY's; a scheduled task and a file moved or renamed into the folder are not read yet. Its os lines ne"
    'ed Windows with Sysmon logging file creation (event 11): under `raqib watch --host` the watch says o'
    'nce when its rounds have read no event 11 of the channel (a file a tree makes may then be unseen) |',
    "| NET-ADMIN-PORT | a connection the process itself made (Sysmon's net line, event 3: `initiated` tru"
    'e) to port 22, 23, 135, 445, 3389, 5900, 5985 or 5986 of a private address that is neither loopback '
    "nor link-local (`dest_scope` private), whatever program of the tree opened the socket (PowerShell's "
    'own included), unless it is ssh started by git (high). Linux has no os source for it: nothing there '
    "is judged by it, and the host's own sample of a connection is not judged yet. It needs Windows with "
    'Sysmon logging connections (event 3; Sysmon without -n logs none): under `raqib watch --host` the wa'
    'tch says once when its rounds have read no event 3 of the channel; a net line whose `initiated` was '
    "not read (no key) is not judged, and the rule's partial note says so |",
]
# M15.2 (ADR-0014 Amendment B, AB-1): the registry's autostart values, a row of the guide's What it catches
# M15.2b (ADR-0014 AE-1 to AE-3): each of the three rows says what it needs of Sysmon and what the watch says
BEHAVIOUR_ROWS.append(
    '| PERSIST-RUN-KEY | a value set under a Run or RunOnce key of the registry (anything below `...\\Micr'
    "osoft\\Windows\\CurrentVersion\\Run\\` or `\\RunOnce\\` of a user's hive or the machine's, the 32-bit view"
    " too, any case; `RunNotification`, `RunOnceEx` and `RunServices` left out), read from Sysmon's regis"
    'try line (event 13) of a watched tree, whatever program of the tree set it; the finding names the hi'
    "ve, run or runonce, the value's name between double quotes (at most 80 characters), the program the "
    "value would run and the program that set it, never the value's text (high). Where the name holds a b"
    'ackslash the event cannot tell it from a value of a key under Run, and the finding says so. Under `r'
    'aqib watch --host` the watch asks the channel once, at its first read, for its newest event 13; whe'
    're it holds none then, the blind spot `registry` says that PERSIST-RUN-KEY may have nothing to read '
    'here (a value logged later does not take it back), and where the question fails, that this is not kn'
    'own (one that holds some event 13 may still not log the Run keys, and nothin'
    'g is said). It needs Windows with Sysmon logging a value set under these keys: where the configurati'
    'on logs none, there is nothing to read. Linux has no os source for it: nothing there is judged by it'
    ' |')
GUIDE_NEW += BEHAVIOUR_ROWS
# M10.4b (ADR-0011 R-2, R-3, T-1, T-5, V): the window's Link screen, said where the window's screens are
LINK_SCREEN = [
    "Link, the rail's item under Log, shows the forwarders of `raqib forward` as their states in "
    "`~/.raqib/forward` say, read off the window's thread at most once a second by the reader and the "
    "judgement of `raqib forward --status`: each one's name, its word (OK, BEHIND, FAILING, SILENT, "
    "UNREADABLE) and its lines - where it sends and by which delivery word, plain or not, what was last "
    "taken and when, what waits, what was refused, why it fails; the forwarders that are not OK come "
    "first, and the screen has no button.",
    "The rail's Link line counts every word that is not OK on every screen (\"Link: 1 failing, 1 behind, 1"
    " silent\";",
    "\"Link: 2 OK\";",
    "\"Link: none\"): none is hidden behind a worse one.",
    "A link that sends is no judgement of the host: an OK forwarder is a note, never green, as green "
    "beside a watch means its rules found nothing;",
    "FAILING and BEHIND are alarm, SILENT and UNREADABLE incomplete, as their exit codes are.",
    "The whole link is an alarm where one forwarder is known to fail, whatever is not known beside it; "
    "else incomplete where something is not known - a silent or unreadable state, a folder that cannot be"
    " listed, states past the 64 read, a read not back in 10 s; else a note.",
    "With no state at all the screen says \"No forwarder: nothing leaves this host by Raqib\", a note, and "
    "the command that starts one.",
    "A state's text is shown as text, at most 300 characters a line, what is not printable as \"?\".",
    "The screen starts, stops and configures no forwarder, holds no token and opens no connection, and no"
    " result, exit code, finding or knock of a watch depends on it (ADR-0011 Amendments R, T, U and V).",
]
GUIDE_NEW += LINK_SCREEN
# ADR-0013 (M12.1): the service's commands, rows of the guide's table only (as the forwarder's, G-11)
SERVICE_ROWS = [
    "| `raqib service install [--no-start]` | Linux, as root (it asks for no elevation): write `/etc/s"
    "ystemd/system/raqib-watch.service` and enable and start it, the host watch as a unit of the syste"
    "m's that serves no page, with its record under `/var/lib/raqib` (`docs/specs/SERVICE.md`); refuse"
    "d, exit 2 and nothing written, for an interpreter run with `-S` or one reading `PYTHONHOME` or `P"
    "YTHONPLATLIBDIR` from its environment, a raqib not directly in that interpreter's own site folder"
    "s, or a `*.pth` file holding a byte outside printable ASCII, tab and the line ends, and unless th"
    "e interpreter, its `pyvenv.cfg`, every file and folder under sys.path and under the paths its `*."
    "pth` files name, the raqib package, systemctl, ss, the unit's folder and every folder above them "
    "are root's and writable by nobody else (the first that is not is said), or where a unit of the na"
    "me does not carry Raqib's mark, or, with no unit file, where systemd holds a unit of the name (lo"
    "aded from any place, or running) or gives no answer; it says how many paths of which kinds it che"
    "cked; after the reload, a unit not as installed is not started (exit 1); over Raqib's own unit it"
    " restarts it; 3 s after the start it asks systemctl, and a unit not active or not as installed th"
    "en is exit 1; `--no-start`: neither enabled nor started; exit 1 where systemctl failed |",
    "| `raqib service remove [--purge]` | Linux, as root: stop, disable and remove Raqib's unit (one w"
    "ithout Raqib's mark is not touched: exit 2), and have systemd forget a failed state of it (`syste"
    "mctl reset-failed`, said); the record under `/var/lib/raqib` stays and its path is said, unless `"
    "--purge` removes that folder too, and only it; with no unit file, exit 0 only where systemd holds"
    " no unit of the name (LoadState not-found, ActiveState inactive or failed), else exit 1, nothing "
    "touched and nothing purged |",
    "| `raqib service status` | no rights needed: installed, enabled and active by systemctl's own wor"
    "ds, whether it is as installed (the file's whole text the one Raqib writes, loaded from that file"
    ", no drop-in, not changed since it was loaded), the restarts, and the last result where not activ"
    "e; with no unit file, a unit of the name that systemd holds is said; exit 0 active as installed, "
    "1 installed and not active, or not as installed, 3 not installed or not known, 2 not Linux |",
]
GUIDE_NEW += SERVICE_ROWS
# ADR-0013 Amendment C (M12.1p, AC-1): the host watch without its page, where watch --host's options are told
NO_PAGE = ["`--no-page` serves no page: the watch opens no port and nothing listens on one, no page is opened in a"
           " browser, and its report and its events file are unchanged (ADR-0013 Amendment C, AC-1)."]
GUIDE_NEW += NO_PAGE
# ADR-0013 Amendment K (M12.4c1, K-6): `raqib service check`'s row in the guide's table, and when to run it
SERVICE_CHECK = [   # M12.4c1b (ADR-0013 Amendments M and N): the row and the paragraph say both roads, N-1, N-2
    "| `raqib service check` | Windows; no rights needed (ask it first as a plain user), the check writes"
    " nothing: whether the code a service of Windows would run is the system's alone, by the owners and l"
    "ists Windows gives (`docs/specs/SERVICE.md`) - on two roads: packed with its own runtime, the progra"
    "m's folder, whole, and each folder above it to the drive; run by a plain interpreter asked with `-I`"
    ", its folder, its base's, its prefixes, the names it looks for itself at every start (`pyvenv.cfg` i"
    "n the folder above its folder, `Modules\\Setup.local` and `Lib` two folders above), every entry of i"
    "ts path and the lines of its *.pth files (an entry not there judged by the deepest folder of it that"
    " is there), and the raqib package, each whole, and each folder above them; exit 0 the system's alone"
    ", with how many names of which kinds it checked, 1 not or not read, the first name refused said with"
    " its role and why, 2 not Windows, or a plain interpreter not started with `-I` or started with `-S` "
    "(the command to ask it by said) |",
    "Run `raqib service check` on Windows before a service of Windows is made to run Raqib as the system,"
    " from the packed copy that service would run, once it is where it will stay: on GitHub's Windows mac"
    "hines a copy an administrator put under `C:\\Program Files` was taken, asked by an administrator and"
    " by a plain user alike.",
    "A copy in a folder made at the drive's root or under `C:\\ProgramData` was refused, with the name re"
    "fused said.",
    "For a Raqib a plain interpreter runs, ask it with that interpreter as the service will run it, `\"PA"
    "TH\\python.exe\" -I -m raqib service check`: asked without `-I`, or with `-S`, it gets exit 2 and th"
    "at command.",
    "Ask it first as a plain user, who needs no rights for it: the check is run by the code it judges, wh"
    "ich has run its site and the `import` lines of its *.pth files at its start, so it is a gate against"
    " a tree put in the wrong place, not a judgement of a tree another already changed.",
    "The check writes nothing, but the interpreter that runs it may write bytecode caches beside what it "
    "imports, where the asker may write there.",
    "A plain interpreter looks at every start for `pyvenv.cfg` in the folder above its own and for `Modul"
    "es\\Setup.local` two folders above it, so python.org's default folder for all users (`C:\\Program Fi"
    "les\\Python311`) is refused on a machine whose drive's root lets signed-in users add a folder, as Gi"
    "tHub's does.",
    "Put a Python a service will run one folder deeper instead, as `C:\\Program Files\\NAME\\Python311`, "
    "where it is taken.",
    "The plain road is held by tests on the owners and lists measured of a Python under Program Files; th"
    "e names the interpreter itself looks for were read in its source, not measured.",
    "It is a reading at one moment: run it again after anything there changes.",
]
GUIDE_NEW += SERVICE_CHECK
# M17.1 (ADR-0015 V-1 to V-3, Amendment A): the number, what a move of it means, the changelog and the update
# steps, in the guide's Install and watch
VERSION_NUMBER = [
    "Which Raqib runs is said by its number, `0.MINOR.PATCH`:",
    "`raqib --version` prints `raqib` and the number, the first line a watch prints and the first line of its report"
    " end with it (`; raqib` and the number), the window's title bar says `Raqib` and the number, every event holds it"
    " as `watch.version`, and `raqib doctor` says it.",
    "MINOR moves with every merge into `main` that changes what Raqib does for a person (a rule, a source, a command,"
    " a report), PATCH with a merge that only repairs, and a merge of documents or tests alone moves nothing: two"
    " copies that do different things never say the same number.",
    "The number is not a promise of stability, and the events' schema has its own name (`raqib-event/1`).",
    "[CHANGELOG.md](CHANGELOG.md) says, the newest first, what each number brought, how to update to it and what was"
    " not measured.",
    "To update a checkout, as CHANGELOG.md gives it:",
    "- In the checkout's folder.",
    "First stop a running watch, window or service: a running one keeps the number it started with.",
    "- `git pull`",
    "- Installed with pipx, on Linux or Windows:",
    "`pipx install --force .`",
    "- Installed with pip:",
    "`pip install --upgrade .` in the same venv; with Windows' launcher, `py -m pip install --upgrade .`",
    "- The Linux service (root's copy, [SERVICE.md](docs/specs/SERVICE.md)), with DIR its folder and NUMBER the new"
    " number: a new copy of the checkout for each number, `sudo cp -r .",
    "DIR/src-NUMBER`, then `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER` and `sudo DIR/bin/raqib service"
    " install` again (it writes the unit again and restarts it).",
    "These steps were not run on a machine yet.",
    "A watch with rules of your own measures its thresholds again at its first start after an update, and says so.",
    "- Then `raqib --version` says the number at the top of CHANGELOG.md.",
]
GUIDE_NEW += VERSION_NUMBER
# M14.1b and its REDO (ADR-0007 BU-3, BW-3, BW-6): the report's PROCESS EVENTS section on Linux, said in the
# guide's Watch the host
PROCESS_EVENTS = [   # M14.1c and its REDO (ADR-0007 BY, BZ, CC, CD, CE): the guide's words on what the watch judges from the reader
    'On Linux the watch also hears what happens between two rounds (ADR-0007 Amendments BU, BW and BY): '
     'at its first round it starts a helper, a second process of its own that runs the reader of the '
     "kernel's process events ([docs/specs/PROC-EVENTS.md](docs/specs/PROC-EVENTS.md)), and after each "
     "round's sample it asks the helper once what it heard, waiting at most 2 s and at most a quarter of "
     'the interval.',
    'What the helper gave since the round before is given to the round beside its sample (M14.1c): a '
     "process that began between two samples under a tree that talks at a sample is that tree's child, "
     'with its HostChild line naming every program it ran while heard (up to 8 a process, in order), each '
     "by its file's name and, where they differ, by the name the kernel gave it (a file `nc.openbsd` "
     "called `nc`: both), each through the gate a sampled child's name goes through, so NET-TOOL and "
     'DESTRUCT-CMD judge a short curl, wget, nc or shred by either name (M14.1d); a process the sample '
     'also holds (the same pid and the same start ticks) is one process.',
    'A tree that is a candidate only by what the reader gave is listed `by the channel`, as on Windows; '
     'the root of a tree, and of an act-root, is always a process a sample held.',
    'A process the watch wrote a line for that runs a program not yet said, in a later round (the command'
     ' a shell runs in its own place), gets a line for that program, and a child whose parent has gone is '
     "still its tree's where the watch wrote that parent and the process events heard it (it keeps, per "
     'tree, only such children whose end it has not heard: at most 512), given to it while the tree is '
     "quiet too; a child of a child written from a sample alone is nobody's once its parent ends, and a "
     'tree that has gone is written nothing: how many processes its kept children were heard to start is '
     'said, as a hole of the result.',
    'A child whose file the reader could not read (one run through `sudo`) is named by the name the '
     'kernel gave it, its line saying its file was not read.',
    "A process is its maker's child where the reader heard it made and its maker is a process of the "
     'round or a child the watch keeps, though a sample holds it under pid 1 (a bash a shell started in '
     "the background and that outlived it); an act-root is made by the samples' own links alone, and under "
     "an act-root a process stays with the parent a sample holds it under (what its shell starts in the "
     "background and leaves is nobody's there, as before: the next task).",
    'Not judged: a tree that lives whole between two samples (a tree needs a talker at a sample, and a '
     "connection that opens and closes between two samples is still unseen), a child's own connections, a "
     'program past the bound of 8 a process (the oldest of those run between two asks), a child whose '
     'parent the watch never wrote, a process whose maker the reader did not hear that a sample holds '
     "under pid 1, and an act-root the reader's word alone would make; a process can be called by a tool's"
     ' name it is not (a link of its own), and its tree then alarms by its own doing.',
    'A program not read, and no name of it read either, is in the round and counted; it gets no line.',
    "What is judged from the helper is the helper's word: the watch does not check its lines.",
    "Its report has a section `PROCESS EVENTS (Linux):` after the place of Windows' CHANNEL line: what is"
     ' judged and what is not, the rounds asked and answered, the processes that began, those of them that'
     ' began and ended between two asks, the programs not read (reads at an exec that failed: a process '
     'can end before its program is read), how many processes were given to the rounds, joined to a tree '
     "as its child and, of them, had no program read, how many of the watch's own processes were left out,"
     " what was past the reader's bounds, and what the reader lost, in its own words, over every helper "
     'the watch had.',
    "No program's name or path is shown in that section: only numbers.",
    'Only where every ask was answered in its round, no helper was started again, nothing was lost, '
     "nothing was past the reader's bounds and the last answer left nothing for a next one, the note that "
     'what lives between two rounds is not seen on Linux says instead what is now seen and what is not; '
     'where the reader answered and was not whole, the note says what was heard and judged and why it was '
     'not whole; where it never answered, the old words stand with each reason beside them.',
    'A helper refused at its first start (a container, a right not given), or late or ended before its '
     'first answer, is a blind spot of its own kind: it does not change the result, and the rounds are the'
     " sample's alone.",
    "After its first answer, a late answer, a line that is not the helper's, an end (and its one "
     'restart), a loss of events, a bound passed or an answer that holds back a rest for a next one is a '
     'hole of the result of its own kind (`procevents`): what was being judged has a gap, and the result '
     'is INCOMPLETE unless a finding makes it an alarm.',
    'Each is said once while it lasts, and at most 10 such episodes are printed, then how many more.',
    'A helper that ends, or is late three rounds running, is started again once, and the section says '
     'that nothing was heard between its end and the new start; a second end is final.',
]
GUIDE_NEW += PROCESS_EVENTS
# M16.1 (ADR-0017 E7): the short section at the end of the guide's More that points to siem/README.md
SIEM_SECTION = [
    "### Into a SOC's search engine",
    "`siem/` holds what a SOC installs to read the events (`~/.raqib/host/events.jsonl`, or what `raqib forward`"
    " sends) in Elasticsearch or OpenSearch: an ingest pipeline to the ECS fields of the spec's Mapping, a"
    " template for each engine, the searches (an alarm, a rule's findings, a hole, a watch that did not end"
    " with 0, the search for silence, the runs that stopped with no end and the lines kept as error documents),"
    " Sigma rules over the events' own keys, and a table of every rule the report lists with its ATT&CK"
    " techniques.",   # M16.1 REDO: R2, R5; REDO 2: R4 (not-events.json)
    "How to install it, and what was measured and what was not:",
    "[siem/README.md](siem/README.md).",
]
GUIDE_NEW += SIEM_SECTION
# The two sentences the first build copied from the guide into "Where it runs" (Q-4); the guide's again (E-1).
TKINTER_SENTENCE = ("It needs tkinter: python.org Python ships it; on Debian or Ubuntu `sudo apt install python3-tk`;"
                    " without it, or without a display, `raqib app` exits 2 and says so")
BETWEEN_SENTENCE = ("On Linux, and on Windows without Sysmon, a tree that lives between two rounds is not seen, and"
                    " the watch says so once")


def before():
    """The old README. The fixture is ASCII (tests stay ASCII): its one non-ASCII line, the name in Arabic,
    is kept as \\uXXXX escapes, and the old README held no such escape of its own."""
    text = BEFORE.read_text(encoding="ascii")
    return re.sub(r"\\u([0-9a-f]{4})", lambda m: chr(int(m.group(1), 16)), text)


def root_links(text, base):
    """Every relative markdown link target rewritten as the repository path it names (base: the file's dir)."""
    def one(m):
        target = m.group(2)
        if re.match(r"^[a-z]+:", target) or target.startswith("#"):
            return m.group(0)
        path, _, anchor = target.partition("#")
        resolved = os.path.normpath(os.path.join(base, path)).replace(os.sep, "/") if path else ""
        return "%s%s%s)" % (m.group(1), resolved, "#" + anchor if anchor else "")
    return re.sub(r"(\]\()([^)\s]+)\)", one, text)


def links(text):
    return re.findall(r"\]\(([^)\s]+)\)", text)


def slug(title):
    return re.sub(r"[^a-z0-9 -]", "", title.lower()).replace(" ", "-")


def cut(text):
    """The text cut into what must survive, each with the heading it stands under (None: before the first
    `## `): each heading line, each line of a code block or a table, and each sentence of a paragraph or list
    item (flattened)."""
    out, para, fence, heading = [], [], False, None

    def flush():
        if para:
            for s in re.split(r"(?<=[.!?:;])\s+(?=[A-Z`\"*(\[])", flat(" ".join(para))):
                out.append(("sentence", s, heading))
            del para[:]
    for line in text.split("\n"):
        if line.startswith("```"):
            flush()
            fence = not fence
            out.append(("line", line, heading))
        elif fence or line.startswith("|") or line.startswith("#"):
            flush()
            if not fence and line.startswith("## "):
                heading = line[3:]
            if line.strip():
                out.append(("line", line, heading))
        elif not line.strip() or re.match(r"^(- |\d+\. )", line):
            flush()
            if line.strip():
                para.append(line)
        else:
            para.append(line)
    flush()
    return out


def pieces(text):
    return [(kind, piece) for kind, piece, _ in cut(text)]


def part(text, title):
    """The text under a heading (None: before the first heading); "" when the text has no such heading."""
    if title is None:
        return text.split("\n## ", 1)[0]
    return section(title, text) if title in headings(text) else ""


def parser_parts():
    """The parser, its subcommands {name: parser}, and every help text it holds (the module's docstring, the
    subcommands' and every option's), flattened."""
    p = cli._parser()
    sub = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))
    texts = [cli.__doc__] + [a.help or "" for a in p._actions] + [c.help or "" for c in sub._choices_actions]
    texts += [a.help or "" for sp in sub.choices.values() for a in sp._actions]
    return p, sub.choices, flat(" ".join(texts))


def parse(argv):
    """argv as `raqib` parses it: the namespace, or "--version"; a usage error fails with argv."""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            return cli._parser().parse_args(argv)
    except cli._VersionAsked:
        return "--version"
    except SystemExit as exc:
        raise AssertionError("raqib %s: usage error %s: %s" % (" ".join(argv), exc.code, err.getvalue()))


def cells(row):
    return [c.strip() for c in re.split(r"(?<!\\)\|", row)[1:-1]]


def table_rows(text):
    return [row for row in text.splitlines() if row.startswith("| ") and not row.startswith("| Command ")]


# A capital word of a row, typed with a real value.
VALUES = {"PROJECT": "my-project", "TRACE": "trace.jsonl", "ID": "NET-TOOL", "FILE": "rule.yaml", "NAME": "MY-TF"}


def argvs(code):
    """Every argv a row's command shows: each [optional | alternative] group absent or each alternative, each
    a|b word each way, each capital word a real value."""
    words = code.replace("\\|", "|")
    assert words.startswith("raqib "), code
    choices = []
    for chunk in re.split(r"(\[[^\]]*\])", words[len("raqib "):]):
        if chunk.startswith("["):
            choices.append([[]] + [alt.split() for alt in chunk[1:-1].split(" | ")])
        else:
            choices.append([chunk.split()])
    out = []
    for combo in itertools.product(*choices):
        shown = [w for seq in combo for w in seq]
        for filled in itertools.product(*[w.split("|") for w in shown]):
            out.append([VALUES.get(w, w) for w in filled])
    return out


def test_e1_readme_is_one_screen_then_the_alarm_where_it_runs_the_commands_more_and_the_licence():
    lines = README.split("\n")
    assert lines[-1] == "" and len(lines) - 1 <= 120, len(lines)
    # Q-10, ruled by the Table: only the sample's fence is exempt, up to the report's own cap (a cited line is
    # what the code prints and is not cut); every other line keeps 120.
    sample = sample_fence()
    assert max(len(line) for line in lines[:sample[0]] + lines[sample[1]:]) <= 120
    assert max(len(line) for line in lines[sample[0]:sample[1]]) <= report.LINE_TEXT_MAX
    assert lines[sample[0] - 1] == "```text" and lines[sample[1]] == "```" and lines.count("```text") == 1
    assert headings(README) == NEW_HEADINGS
    assert lines[0] == before().split("\n")[0] and lines[2:5] == before().split("\n")[2:5]   # the name, three lines
    assert len(README.split("\n## Doctor\n", 1)[0].splitlines()) <= 25
    assert section("Licence") == section("Licence", before())   # as it is


def test_e1_where_it_runs_is_written_fresh_and_each_fact_is_pinned_by_the_code_or_the_guide():
    """ADR-0010 E-1: at most eight lines of plain words, each fact true of the tree. This test replaces the first
    build's "built from sentences the README had": its two README sentences stay pinned here, its two copies of
    the guide's sentences are pinned in the guide again (the last block), and Python 3.11 in Install and watch."""
    where = section("Where it runs")
    said = flat(where)
    text_lines = [line for line in where.split("\n") if line.strip()]
    assert len(text_lines) <= 8 and all(len(line) <= 120 for line in text_lines), text_lines
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    gate = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    p, commands, helps = parser_parts()
    # Linux and Windows: both CI jobs run on exactly these two; no job runs on macOS.
    assert "Raqib runs on Linux and Windows" in said and "the tests run on both" in said
    assert re.findall(r"^\s+os: \[(.*)\]$", gate, re.M) == ["ubuntu-latest, windows-latest"] * 2
    assert "macos" not in gate.lower() and gate.count("runs-on: ${{ matrix.os }}") == 2
    # Python's floor (pyproject.toml, doctor's check) and the standard library only (no dependency).
    assert "on Python 3.11 or newer and its standard library only" in said
    assert re.search(r'^requires-python = ">=3\.11"$', pyproject, re.M) and doctor.MIN_PYTHON == (3, 11)
    assert re.search(r"^dependencies = \[\]$", pyproject, re.M)
    # The Windows install and WSL: the README's own sentences, word for word (ADR-0010 E-5).
    for sentence in (WINDOWS_INSTALL, WSL):
        assert sentence in said and sentence in flat(before()), sentence
    for words in ("On Windows: `pipx install", "(Windows or WSL)"):   # the first build's pins, kept
        assert words in said, words
    # Claude Code for `raqib watch PROJECT`: the hooks it installs are Claude Code's.
    assert "`raqib watch PROJECT` needs Claude Code, whose hooks it installs." in said
    assert doctor.check_claude({}, False, shutil.which, None) == (
        False, "not on PATH (install Claude Code; the hooks are Claude Code hooks)")
    assert parse(["watch", "my-project"]).project == "my-project" and "install the hooks" in helps
    # `raqib watch --host` names no agent; on Windows it reads Sysmon where it is; what it misses is the guide's.
    assert "`raqib watch --host` needs no agent named: it finds the agents by what they do" in said
    args = parse(["watch", "--host"])
    assert args.host and args.project is None
    assert "find AI agents on a host by what they do" in helps and "watch this host, not a project" in helps
    assert "where Sysmon is, each round also reads the channel since the previous round" in helps
    assert ("and on Windows it also reads Sysmon where it is installed ([what it misses without"
            " it](docs/GUIDE.md#watch-the-host)).") in said
    assert links(where) == ["docs/GUIDE.md#watch-the-host"] and "Watch the host" in headings(GUIDE)
    assert BETWEEN_SENTENCE in flat(section("Watch the host", GUIDE))
    # The window needs tkinter and `raqib watch` does not: doctor's line is UNSURE and never fails its exit.
    # ADR-0010 F-1 (J2): python3-tk is Debian's and Ubuntu's package; python.org's Python has tkinter (the guide's words)
    assert ("The window, `raqib app`, needs tkinter (python.org's Python has it; on Debian or Ubuntu install"
            " `python3-tk`); `raqib watch` does not.") in said
    assert "python.org Python ships it; on Debian or Ubuntu `sudo apt install python3-tk`" in TKINTER_SENTENCE

    def no_tkinter(name):
        raise ImportError("No module named %r" % name)
    verdict, line = doctor.check_tkinter({}, "linux", no_tkinter)
    assert verdict == doctor.UNSURE and doctor.TK_UNSURE == "the window needs it (python3-tk); watch does not"
    assert line.startswith(doctor.TK_UNSURE) and doctor.summary([("tkinter", (verdict, line))])[1] == 0
    assert "app" in commands
    # macOS, as the tree stands: osascript and the page opener are written; no live reader; no CI job (above).
    # ADR-0010 F-1 (J1): the hooks and doctor are written for it too (the guide's sentences, the old README's);
    # discover has no live reader there either (collect_live below is discover's own reader); nothing is tested
    assert ("On macOS the hooks, doctor, the notifications and the page opener are written for it, but `raqib watch"
            " --host` and `raqib discover` have no live reader there and no CI job runs on macOS: none of it is"
            " tested.") in said
    assert "on Linux and macOS `python3` on PATH, which the hooks run" in flat(section("Doctor", GUIDE))
    assert "Linux, macOS; Windows: capture and installer" in flat(GUIDE)
    knocks = notify.Notifier("p", environ={}, platform="darwin", isfile=lambda path: True)
    assert (knocks.backend, knocks.program) == ("osascript", notify.OSASCRIPT)
    opened = []
    watch.open_page("http://127.0.0.1:8765/", environ={}, platform="darwin", isfile=lambda path: True,
                    runner=lambda argv, env, cwd, wait=False: (opened.append(argv), (0, None))[1])
    assert opened == [[watch.MAC_OPENER, "http://127.0.0.1:8765/"]]
    texts, holes, _ = discover.collect_live(discover.load_catalog(), platform="darwin", homes=[])
    assert set(texts) == {"footprints"} and holes[0].startswith("no live process or connection reader on darwin")
    assert doctor.check_host("darwin") == (doctor.UNSURE, "homes only; no live reader")
    # The two sentences the first build copied from the guide left the README; the guide keeps them (Q-4).
    assert TKINTER_SENTENCE not in flat(README) and TKINTER_SENTENCE in flat(section("The window", GUIDE))
    assert BETWEEN_SENTENCE not in flat(README) and "on Windows without Sysmon" in flat(section("Watch the host", GUIDE))
    assert "It needs tkinter" in flat(section("The window", GUIDE)) and "It needs tkinter" not in said
    assert "Python 3.11 or newer and Claude Code" in flat(section("Install and watch"))


def test_e3_the_commands_table_is_cut_from_the_guides_and_in_the_ruled_order():
    """ADR-0010 E-3: `raqib app` first, then watch, watch --host, doctor, report, rules, discover, --version, and
    the rest in rows that point at the guide (ADR-0013 AB-1: more than one where one would pass 120). Each
    command row is a guide row (its command the row's or a prefix of it, its words a part of the row's): the
    guide's table gained E-3's new rows (NEW_ROWS)."""
    full = {}
    for row in table_rows(section("Commands", GUIDE)):
        command, does = cells(row)
        full[command.split("`")[1]] = does
    rows = table_rows(section("Commands"))
    assert len(rows) >= 8 and all(len(row) <= 120 for row in rows)
    short = [row for row in rows if row.startswith("| `raqib ")]
    rest = [row for row in rows if not row.startswith("| `raqib ")]
    assert rows == short + rest and rest
    for row in short:
        command, does = cells(row)
        command = command.strip("`")
        matches = [command] if command in full else [c for c in full if c.startswith(command)]
        assert matches and does in full[matches[0]], row
    keys = [cells(row)[0].strip("`").split()[1] for row in short]
    keys = [k + " --host" if k == "watch" and "--host" in row else k for k, row in zip(keys, short)]
    assert keys == ["app", "watch", "watch --host", "doctor", "report", "rules", "discover", "--version"], keys
    for row in NEW_ROWS:
        assert row in rows and row in table_rows(section("Commands", GUIDE)), row
    named = set(keys) | set(re.findall(r"`([a-z-]+)`", " ".join(cells(row)[0] for row in rest)))
    for name in ("watch", "doctor", "report", "ui", "suspect", "proxy", "os-sysmon"):   # the first build's names
        assert name in named, name
    # ADR-0013 AB-1: the rest is cut into rows, none past 120; the first says "the rest: ", a later one "and: ",
    # each points at the guide and names at least one command, none twice.
    for i, row in enumerate(rest):
        assert cells(row)[0].startswith("and: " if i else "the rest: ") and links(row) == ["docs/GUIDE.md#commands"]
        assert re.findall(r"`([a-z-]+)`", cells(row)[0]), row
    told = re.findall(r"`([a-z-]+)`", " ".join(cells(row)[0] for row in rest))
    assert len(told) == len(set(told)) and not set(told) & set(keys), told


def test_e3_every_command_in_the_table_is_the_parsers_and_parses_as_shown():
    """Every subcommand of the parser is named in the table, and nothing else is; a row's command, typed as shown
    with real values for its capital words, parses; each option it shows is that command's, with the metavar it
    shows; a new row's words are the help's own."""
    p, commands, helps = parser_parts()
    rows = table_rows(section("Commands"))
    short = [row for row in rows if row.startswith("| `raqib ")]
    rest = " ".join(cells(row)[0] for row in rows if not row.startswith("| `raqib "))
    named = [cells(row)[0].strip("`").split()[1] for row in short]
    assert set(n for n in named if not n.startswith("-")) | set(re.findall(r"`([a-z-]+)`", rest)) == set(commands)
    for row in short:
        command, does = cells(row)
        word = command.strip("`").split()[1]
        shapes = argvs(command.strip("`"))
        assert shapes, row
        for argv in shapes:
            got = parse(argv)
            assert got == "--version" if word == "--version" else got.command == word, (argv, got)
            for value, attr in (("my-project", "project"), ("trace.jsonl", "trace")):
                if value in argv:
                    assert getattr(got, attr) == value, argv
        owner = p if word.startswith("-") else commands[word]
        options = {o: a for a in owner._actions for o in a.option_strings}
        for code in re.findall(r"`([^`]+)`", row):
            for m in re.finditer(r"(--[a-z][a-z-]*)((?: (?:[A-Z][A-Z_]*|[a-z]+\\?\|[a-z]+))*)", code):
                option, shown = m.group(1), m.group(2).replace("\\|", "|").split()
                assert option in options, (row, option)
                metavar = options[option].metavar
                metavar = list(metavar) if isinstance(metavar, tuple) else ([metavar] if metavar else [])
                assert shown == metavar[:len(shown)] and (not shown or len(shown) == len(metavar)), (row, option)
                if word == "rules" and option != "--set":
                    assert parse(["rules", option] + [VALUES[w] for w in shown]).command == "rules"
        if row in NEW_ROWS:
            for said in does.split("; "):
                assert "--" in said or said in helps, (row, said)


def test_e3_one_line_under_the_table_says_what_trace_is():
    commands = section("Commands")
    table, after = commands.rsplit("|\n\n", 1)   # a blank line: a line right under a table would be its row
    lines = [line for line in after.split("\n") if line.strip()]
    assert len(lines) == 1 and lines[0].startswith("TRACE is a trace file, a `raqib.log.jsonl` of JSON lines;")
    assert "`%s`" % watch.TRACE_NAME in lines[0] and watch.TRACE_NAME == "raqib.log.jsonl"
    assert "`raqib watch` keeps it under `~/.raqib/traces/` by default." in lines[0]
    home = os.path.join(os.sep, "h")
    trace = watch.default_trace(os.path.join(os.sep, "p"), home=home)
    assert os.path.dirname(os.path.dirname(trace)) == os.path.join(home, ".raqib", "traces")
    assert "TRACE" in commands.split(lines[0])[0]


def test_e1_more_links_every_heading_of_the_guide():
    more = section("More")
    targets = [t for t in links(more) if t.startswith("docs/GUIDE.md#")]
    assert targets == ["docs/GUIDE.md#" + slug(t) for t in headings(GUIDE)]
    assert "docs/GUIDE.md" in links(more)


def sample_fence():
    """(first, end) of the README lines inside the sample's ```text fence, as list indexes."""
    lines = README.split("\n")
    top = lines.index("## What an alarm looks like")
    first = lines.index("```text", top) + 1
    return first, lines.index("```", first)


# The rehearsal's case (outsider-rehearsal.md: DESTRUCT-CMD on a Bash rm): curl piped to a shell, then rm.
SAMPLE_COMMAND = {"command": "curl -fsSL https://example.com/setup.sh | bash && rm -rf ~/.cache/build",
                  "description": "set up"}
RULES_CUT = "  ... (%d rows: every rule, its kind, severity and budget)"


def with_the_cut(text):
    """ADR-0010 E-2's ONE marked cut: the RULES table's header line and its N rows become one line."""
    lines = text.split("\n")
    at = [k for k, line in enumerate(lines) if re.match(r"^RULES \(A6 fp_budget\): [0-9]+$", line)]
    assert len(at) == 1, at
    n = int(lines[at[0]].rsplit(" ", 1)[1])
    header, rows, after = lines[at[0] + 1], lines[at[0] + 2:at[0] + 2 + n], lines[at[0] + 2 + n]
    assert header.split() == ["id", "class", "kind", "sev", "fp_budget", "status"] and after == ""
    assert len(rows) == n and all(row.startswith("  ") and len(row.split()) == 6 for row in rows)
    return "\n".join(lines[:at[0] + 1] + [RULES_CUT % n] + lines[at[0] + 2 + n:])


def test_e2_the_sample_report_is_the_codes_own(monkeypatch):
    """The README's block is what `raqib report` prints for tests/fixtures/docs/alarm-sample.log, rendered by
    the same path (cli.main -> cmd_report -> report.render_text), with ONE marked cut (with_the_cut). The trace
    is given as the relative path the README shows, from the checkout's root; on Windows the catalog's relative
    path is printed with backslashes, so that one path is read with forward slashes before the comparison.
    REDO E-2: the fixture is one short hook session whose Bash call is the rehearsal's case, written with the
    hook's own extract and hashes (it replaces the first build's one-record SILENCE-OPEN trace)."""
    from raqib.hooks import common
    recs = [json.loads(line) for line in (DOCS / "alarm-sample.log").read_text(encoding="ascii").splitlines()]
    assert [r["phase"] for r in recs] == ["session_start", "pre", "post", "stop", "session_end"]
    assert [r["seq"] for r in recs] == [1, 2, 2, 3, 4] and len({r["session_id"] for r in recs}) == 1
    meta = common.input_meta("Bash", SAMPLE_COMMAND)
    assert meta == {"command_head": "curl", "command_programs": ["curl", "bash", "rm"]}
    for rec in recs[1:3]:
        assert rec["tool"] == "Bash" and rec["input_meta"] == meta
        assert rec["input_sha256"] == common.canonical_sha256(SAMPLE_COMMAND)
    assert recs[2]["ok"] is True and recs[2]["output_meta"] == {"scan": "full", "secret_kinds": []}
    monkeypatch.chdir(ROOT)
    monkeypatch.delenv("RAQIB_GAP_SECONDS", raising=False)
    out = io.StringIO()
    with contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(["report", "tests/fixtures/docs/alarm-sample.log"], out=out)
    text = out.getvalue()
    text = text.replace("(catalog %s)" % os.path.join("raqib", "rules", "catalog"), "(catalog raqib/rules/catalog)")
    assert code == 1 and text.endswith("RESULT: ALARM (exit 1)\n")
    block = section("What an alarm looks like").split("```text\n", 1)[1].split("```", 1)[0]
    assert block == with_the_cut(text)
    assert block.count(RULES_CUT % 25) == 1 and "SILENCE-GAP     SILENCE" not in block and "  id  " not in block
    findings = re.findall(r"^  \[(\w+)\] (\S+) ", block, re.M)
    assert findings == [("medium", "DESTRUCT-CMD"), ("medium", "NET-TOOL")], findings
    assert '      Bash runs rm at seq 2 (programs ["curl", "bash", "rm"])\n' in block
    assert "ALARMS (A3, A5): 0" in block and "SILENCE" not in block.split("FINDINGS:", 1)[1].split("RULES")[0]


def test_e2_one_sentence_before_the_block_names_the_commands_that_print_it():
    """ADR-0010 E-2's sentence: `raqib report TRACE` prints the block (the test above); `raqib watch PROJECT`,
    when it ends, prints its summary and then the same render_text report of its own trace (watch.py)."""
    first, rest = section("What an alarm looks like").split("\n", 1)
    assert first == ("`raqib report TRACE` prints this; `raqib watch PROJECT` prints it for its own trace when it"
                     " ends, after its summary.") and rest.startswith("```text\n")
    assert parse(["report", "trace.jsonl"]).trace == "trace.jsonl" and parse(["watch", "my-project"]).command == "watch"
    source = (ROOT / "raqib" / "watch.py").read_text(encoding="utf-8")
    assert source.count("body = report.render_text(rep)") == 1 and source.count("self.final_text = summary + body") == 1


def test_e3_every_old_heading_is_a_heading_of_the_readme_or_the_guide():
    old = before()
    assert hashlib.sha256(old.encode("utf-8")).hexdigest() == BEFORE_SHA256
    assert headings(old) == OLD_HEADINGS
    for title in OLD_HEADINGS:
        assert title in headings(README) or title in headings(GUIDE), title
    assert [t for t in headings(GUIDE)] == [t for t in OLD_HEADINGS if t in headings(GUIDE)]   # the README's order
    assert "Licence" not in headings(GUIDE)


def test_e3_every_sentence_of_the_old_readme_is_in_the_readme_or_the_guide_word_for_word():
    """ADR-0010 E-6. Old -> new: a heading line the old README had n times is in the two files n times or more; a
    code or table line it had n times under a heading is there n times or more under the same heading (README's
    part and the guide's together); a sentence is under its own heading (MOVED: the three pieces E-5 put in
    "Where it runs"). New -> old: every piece of the guide is the old README's under the same heading, but for
    GUIDE_NEW and CHANGED's new sentences."""
    old = before()
    readme, guide = root_links(README, ""), root_links(GUIDE, "docs")
    lost, found = [], 0
    old_lines = collections.Counter((h, p) for k, p, h in cut(old) if k == "line" and not p.startswith("#"))
    old_heads = collections.Counter(p for k, p, h in cut(old) if k == "line" and p.startswith("#"))
    new_lines = (readme + "\n" + guide).split("\n")
    for kind, piece, heading in cut(old):
        piece = CHANGED.get(piece, piece)
        heading = MOVED.get(piece, heading)
        here = (part(readme, heading), part(guide, heading))
        if kind == "line" and piece.startswith("#"):
            ok = new_lines.count(piece) >= old_heads[piece]
        elif kind == "line":
            ok = sum(text.split("\n").count(piece) for text in here) >= old_lines[(heading, piece)]
        else:
            ok = any(piece in flat(text) for text in here)
        found += 1
        if not ok:
            lost.append((heading, piece))
    assert lost == [] and found == 395   # the fixture is fixed (its sha256 above), so is the count
    assert set(MOVED.values()) == {"Where it runs"} and all(p in flat(section("Where it runs")) for p in MOVED)
    added, used = [], set()
    for kind, piece, heading in cut(guide):
        if piece in GUIDE_NEW or piece in CHANGED.values():
            used.add(piece)
            continue
        if kind == "line" and piece.startswith("#"):
            ok = piece in old.split("\n")
        elif kind == "line":
            ok = piece in part(old, heading).split("\n")
        else:
            ok = piece in flat(part(old, heading))
        if not ok:
            added.append((heading, piece))
    assert added == [] and used == set(GUIDE_NEW) | set(CHANGED.values())


def test_e3_the_guide_is_wrapped_at_100_but_its_tables_and_code():
    fence = False
    for line in GUIDE.split("\n"):
        if line.startswith("```"):
            fence = not fence
        elif not fence and not line.startswith("|"):
            assert len(line) <= 100, line
    assert GUIDE.startswith("# The Raqib guide\n")


def test_e3_every_relative_link_names_a_file_that_exists_and_a_guide_heading():
    for path, text in ((README_PATH, README), (GUIDE_PATH, GUIDE)):
        for target in links(text):
            if re.match(r"^[a-z]+:", target):
                continue
            name, _, anchor = target.partition("#")
            where = (path.parent / name) if name else path
            assert where.is_file(), (path.name, target)
            if anchor and where.resolve() == GUIDE_PATH.resolve():
                assert anchor in [slug(t) for t in headings(GUIDE)], target
            if anchor and where.resolve() == README_PATH.resolve():   # REDO E-7: the guide links README's headings
                assert anchor in [slug(t) for t in headings(README)], target
    assert "](specs/ADR-0010-a-strangers-first-run.md)" in GUIDE and "](docs/" not in GUIDE
    assert "[CC0 1.0 Universal](LICENSE)" in README


def test_e7_a_split_section_of_the_guide_begins_with_one_line_to_its_start_in_the_readme():
    assert SPLIT == [t for t in headings(GUIDE) if t in headings(README) and t not in ("Commands", "More")]
    for title in SPLIT:
        body = section(title, GUIDE)
        first, rest = body.split("\n", 1)
        assert first == LINK_LINE % (title, "../", slug(title)) and rest.startswith("\n"), title
        assert units(body)[0] == first and first.count("](") == 1
    for title in headings(GUIDE):
        if title not in SPLIT:
            assert "This section begins in the README" not in section(title, GUIDE), title
    status = flat(section("More", GUIDE))
    assert "runs this quickstart" not in status
    assert "runs the quickstart in the README ([Install and watch](../README.md#install-and-watch))" in status


# E-4 (ADR-0010 Amendment E): raqib/ sends a person to docs/GUIDE.md, by its section, for what moved there. The
# README is still named, in statements, by three docstrings outside M9.2's Scope (review H13; recorded).
CITED = '"Find the agents on a host (discover)"'
STATEMENTS = {"raqib/hostwin.py": 1, "raqib/rules/cross.py": 1, "raqib/rules/tree.py": 1}


def test_e5_every_readme_citation_under_raqib_names_the_guide_and_a_section_that_holds_it(tmp_path):
    named = {}
    for path in sorted((ROOT / "raqib").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            count = path.read_bytes().count(b"README")
            if count:
                named[path.relative_to(ROOT).as_posix()] = count
    assert named == STATEMENTS, named
    sources = {name: " ".join((ROOT / "raqib" / name).read_text(encoding="ascii").split()).replace('\\"', '"')
               for name in ("cli.py", "discover.py")}
    assert sources["cli.py"].count(CITED) == 2 and sources["discover.py"].count(CITED) == 3
    assert sources["cli.py"].count("docs/GUIDE.md") == 2 and sources["discover.py"].count("docs/GUIDE.md") == 12
    title = CITED.strip('"')
    assert title in headings(GUIDE) and "```powershell\n$N = 6; $T = 10\n" in section(title, GUIDE)
    assert "docs/GUIDE.md#" + slug(title) in links(section("More"))   # and the README links to it
    # What a person sees: the help, the option's help, the hole of a host with no live reader, the hole of
    # numbered samples without run.json, and the refusal of a run.json that is not the loop's.
    p, commands, _ = parser_parts()
    from_help = next(a.help for a in commands["discover"]._actions if "--from" in a.option_strings)
    said = [flat(cli.__doc__), from_help]
    texts, holes, _ = discover.collect_live(discover.load_catalog(), platform="darwin", homes=[])
    said.append(holes[0])
    kimi = ROOT / "tests" / "fixtures" / "discover" / "kimi" / "one-sample"
    for name in ("win-process-1.csv", "win-tcp-1.csv"):
        shutil.copy(str(kimi / name), str(tmp_path / name))
    said += [h for h in discover.read_dir(str(tmp_path))[1] if h.startswith("no run.json beside")]
    (tmp_path / "run.json").write_text(json.dumps({"raqib": "other", "samples": 1}), encoding="ascii")
    try:
        discover.read_dir(str(tmp_path))
    except ValueError as exc:
        said.append(str(exc))
    assert len(said) == 5, said
    forms = ("docs/GUIDE.md, " + CITED, "docs/GUIDE.md loop, " + CITED, "docs/GUIDE.md loop's (" + CITED)
    for text in said:
        assert "README" not in text and any(form in text for form in forms), text
