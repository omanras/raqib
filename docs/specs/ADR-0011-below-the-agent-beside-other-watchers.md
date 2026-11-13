# ADR-0011 - Raqib below the agent, and beside other watchers

Status: accepted 2026-11-13 with Amendment A (the commander's words of that day: do as proposed; and amend what
limits Raqib). Proposed 2026-11-12, on the commander's words of that day after the third field run: Raqib must sit in a
deep layer of the system, so that an agent that makes another user, local or not, is still seen; and it must be
possible to connect it to other monitoring systems, such as an XDR or his Guardian - "this is very important".
Nothing here is built until he judges it. Amendments appended, never edited in place.

## Problem
The third field run (docs/review/2026-11-11-third-field-run.md) and the watches of 2026-11-12 showed five things
the host watch of ADR-0007 cannot do from where it stands:
- It runs as the watched agent's own account. The agent read the watcher's record; it could have erased it.
- A process of another account is half read: its start time and command line were not (one such tree knocked
  as new though it was four weeks old).
- A tree is a process and its descendants. A process that runs under an account the agent made, or from a task
  or service it registered, is nobody's child: it is in no tree.
- What an agent reads with its own code is in no source of the host watch. The proxy source has it, and the host
  watch does not read the proxy's trace.
- A finding lives in Raqib's own files and window. No other system can use it, and when Raqib is stopped nobody
  hears the silence.

## Decisions
Each names the case it is FOR and what it MUST NOT TOUCH (ADR-0007 Z-9). The constitution stands: A1, A2, A3;
A4 (Raqib reads and reports; it never blocks, signals or injects, and ships no driver of its own); A9.

1. Position: the watch as a service. `raqib service install` (an administrator's explicit command; `raqib
   service remove` undoes all of it) runs the host watch as a system service: LocalSystem on Windows, root under
   systemd on Linux. Its record is kept under a system directory the watched account cannot write
   (ProgramData\Raqib; /var/lib/raqib), readable by administrators. FOR: the watched reading or erasing the
   record; processes of every account and session. MUST NOT TOUCH: `raqib watch --host` from a terminal stays
   what it is and installs nothing.
2. Sight: more of the system's own records, each a source of class os (ADR-0003), each said when it is not
   there (A3: an audit policy that is off is a hole said at the start, never an empty list):
   (a) Windows Security and System logs: an account made (4720), a group changed (4732), a logon and a logon
   with other credentials (4624, 4648), a scheduled task (4698), a service installed (7045), a log cleared
   (1102); (b) file reads from the kernel's own tracing (ETW), measured for volume and false positives before
   it is promised; (c) Linux counterparts (auditd, eBPF), named here and built after Windows.
3. Reach beyond the tree. A tree's reach is its descendants and what it made: the accounts it created, the
   logon sessions it opened, the tasks and services it registered. A process in such a session, or started by
   such a task or service, is in the tree's reach, and the line that says so cites the event that links them
   (A5). Deterministic rules with fixtures and budgets (A1, A6): ACCOUNT-NEW, LOGON-AS, PERSIST-TASK,
   PERSIST-SERVICE. FOR: the agent that makes another user. MUST NOT TOUCH: the same events with no tree
   behind them (an administrator's own work) are notes until measured.
4. The other machine. From this host Raqib sees the bridge only: a tree's ssh, RDP or WinRM connection out, and
   the logon with other credentials that names its target. What happens there is seen by a Raqib there. The two
   are joined by decision 6, in the system that collects both - never by Raqib talking to Raqib.
5. Intent beside act. The host watch reads a proxy trace as one more source of the tree whose client it is, so
   one report holds what the model asked for and what the machine did. PROXY-BYPASS: where a proxy is running
   and a tree talks to a model endpoint of the catalog directly, that is a finding. The proxy stays what it is:
   one agent pointed at 127.0.0.1 by its own setting. Raqib never becomes the machine's proxy, never installs a
   root certificate, never reads another program's TLS (A4, A9).
6. Beside other watchers: Raqib writes, others carry. Every finding, hole, knock and verdict is one event:
   (a) a line of JSON in a documented, versioned shape (`raqib-event/1`), in a file under the record's directory,
   with a published mapping of its fields to OCSF (Detection Finding) and ECS names;
   (b) the same event in the Windows Event Log (source Raqib, a fixed id per kind) and, on Linux, the local
   syslog socket (RFC 5424);
   so the agent of any XDR or SIEM, which already forwards the Event Log, syslog or a tailed file, carries it.
   Raqib opens no connection for this (CLAUDE.md rule 5 holds as written). Each rule declares its MITRE ATT&CK
   technique ids in its YAML, checked by check-rules and carried in the event. A heartbeat event is written on
   a fixed beat with the watch's state and its holes, so the collecting system can alarm on Raqib's own silence
   (A3 across systems: a watcher that was stopped cannot knock). An event carries no secret and no text the
   trace does not already hold. The Guardian reads these events as any other consumer does: nothing of it is in
   this tree, and nothing here names its formats (A9).
7. Not in this ADR: sending events over the network by Raqib itself (a separate command outside the capture
   path, if he wants it later); reading another system's telemetry as a source (ADR-0003's contract, a later
   ADR); stopping an agent (never: A4).

## What stays out of reach, and is said
An agent with administrator or SYSTEM rights can stop the service and clear the logs. Raqib cannot prevent it
(A4); it can make it loud: the log-cleared and service-stopped events are findings where they are read, and the
heartbeat's absence is the collector's alarm. An agent that never touches this machine after its bridge out is
seen here only as that bridge.

## Order of building (one HANDOFF each; the first waits for nothing but his word)
- the event: decision 6(a), the technique ids, the heartbeat (small, needs no rights, useful at once);
- the sinks: decision 6(b);
- the service: decision 1;
- accounts, logons, tasks, services and reach: decisions 2(a) and 3;
- the proxy joined and PROXY-BYPASS: decision 5;
- file reads: decision 2(b), measured first.

## Questions for the commander
- Q-1 Decision 1 adds an installed service beside a watch that promised to install nothing. Accepted?
- Q-2 The order above puts the event and its sinks before the service. His order?
- Q-3 Which collector is the first to be shown end to end (the Event Log and a tailed file reach most of them)?
- Q-4 Windows first, Linux after: accepted?

## Amendment A (the Table, 2026-11-13) - the commander's ruling on the link to other systems, and on what Raqib is for
His words, in substance: this ADR limits Raqib's properties and its effect. Toward an XDR, a SIEM or any other
security control Raqib only sends them notice, by logs, passively; it takes no action; the security system decides
whether to act. That takes much of the reviewing load off the Guardian. And as the tests show, Raqib is not only
for AI agents: it can catch any other suspicious movement, by a logic tighter than the known systems'.
What that changes, and what it leaves:

- A-1 (passive, in both directions). Raqib emits; it never acts on what it sees and never takes an order from the
  system it reports to: no command, no query, no configuration comes back over the link. A4 stands and is the
  whole of Raqib's side of the bargain: the deciding and the acting are the other system's.
- A-2 (decision 6 widened: Raqib may send). Besides the local sinks (the file, the Windows Event Log, the local
  syslog socket), Raqib can forward its own events, one way, to a collector the person names: syslog over UDP,
  TCP or TLS (RFC 5424), and an HTTP(S) event collector that takes a JSON body (the shape Splunk's HEC and its
  like accept). Off until the person sets a destination; each destination and what is sent to it is said at the
  watch's start and in the window. Decision 7's "sending events over the network by Raqib itself" is withdrawn
  from what is not in this ADR.
- A-3 (CLAUDE.md rule 5 holds as written, and how). The forwarder is not the capture path: capture writes the
  event to the local file and is done; a forwarder of its own reads that file and sends. A collector that is
  slow, down or refusing never delays or loses a capture: the events wait in the file, and the link's failure is
  said (A3: a hole of the link, a heartbeat not delivered), in the report and the window. The watch's line
  "nothing leaves the machine" is true only while no destination is set, and says so.
- A-4 (what is sent: everything Raqib judged, not only what it knocks for). A person is knocked only by what the
  budgets allow (A6); a system whose work is to decide is sent the whole judgement, each event with its level,
  its rule, the rule's kind and declared false-positive budget, its evidence (A5) and whether Raqib knocked for
  it: findings and source findings; notes on benign trees; trees listed and not knocked (unknown, by the
  channel); holes and blind spots; the heartbeat. Decision 3's "notes until measured" now means: a note in
  Raqib's own window and no knock, and an event to the collector from the first day.
- A-5 (not only agents). The records Raqib reads and the rules that judge them are about what a process does,
  not about what it is called (ADR-0007). A finding of decisions 2 and 3 - an account made, a logon with other
  credentials, a task or a service registered, a log cleared - is a finding whether or not a tree stands behind
  it; a tree, where there is one, is its attribution. The same holds for what the catalog already judges. The
  project's first sentence ("a watcher for AI agents") is the commander's to reword; this ADR does not touch
  CLAUDE.md or the constitution.
- A-6 (the window). A panel for the link: each destination, what is sent to it, how many events, the last one
  delivered, the last failure, and a button that sends one marked test event.
- A-7 (secrets, A9). A collector's token is a secret: kept in the person's own configuration outside any trace,
  record or event, never printed, never in the tree; an event carries no secret and no text the trace does not
  already hold.
- A-8 (the Guardian). It reads these events as any consumer does. Nothing of it is in this tree and nothing here
  names its formats (A9).

Order of building, replacing the list above (one HANDOFF each): the event and its file, with the technique ids
and the heartbeat; the forwarders (syslog, HTTP) and the local sinks, with the window's panel; the service;
accounts, logons, tasks, services and reach, as findings with or without a tree; the proxy joined and
PROXY-BYPASS; file reads, measured first. Questions Q-1 to Q-4 are answered by his words: the service is accepted;
the link comes first; Windows first. Q-3 (which collector is shown end to end first) is still his to name.

## Amendment B (the Table, 2026-11-13) - the event, ruled before it is built
The first step of the order above, cut in two so that each can be read whole: the event as a shape and the one
module that builds it (this amendment, M10.1); the watch writing it to its file on a beat (M10.2). The commander
named no first collector; the Table takes the two shapes that reach most of them - an HTTP collector that takes a
JSON event (Splunk's HEC is one) and syslog - and proves the link first against stand-ins on the rig, then
against a real Splunk. An event is built once, in Raqib's own shape; a collector's shape is a mapping of it.
- B-1 (one module, pure). `raqib/event.py` is the only code that builds an event. Its functions take a ledger
  entry of the watch (a finding, a source finding, a hole, a note, a knock row, a tree row, the watch's state)
  and the watch's facts, and return a dict. No clock, no file, no network, no environment: the caller gives the
  time and the host's name. `event.check(obj)` returns the problems of an event; every event the module builds
  has none. FOR: one shape for every consumer. MUST NOT TOUCH: raqib/host.py, raqib/watch.py, the report.
- B-2 (the shape, `raqib-event/1`). Keys, in this order where a kind has them:
  schema ("raqib-event/1"); id ("<run>:<n>"); n (the event's number in its run, from 1); time (UTC, ISO 8601,
  milliseconds, Z: when Raqib said it); kind (finding | source-finding | note | tree | hole | knock | heartbeat |
  watch); severity (the rule's high | medium | low for a finding and a source finding; "hole" for a hole; "info"
  for the rest); summary (one sentence, the report's own); rule ({id, class, kind, fp_budget, attack}: finding
  and source-finding only); subject ({tree, pid, image, named, agent, path}: a key is absent where the entry
  does not hold it, never null-filled or guessed); evidence ({run, round, record, source, trace, seqs, lines,
  cites}: A5, where a person or a system can check it; absent keys as for subject); knocked ({status, event}:
  whether Raqib knocked a person for it and what became of the knock); state (a source finding: settled |
  history | judged on another tree | noted; a watch event: start | end); result ({word, exit}: a watch end and a
  heartbeat); counts ({rounds, findings, source_findings, holes, notes, trees}: a heartbeat and a watch end);
  watch ({run, mode, platform, version, host}: on every event).
- B-3 (the same in, the same out). An event is one line: JSON, keys sorted, compact, ASCII (non-ASCII
  escaped). The same ledger gives the same lines byte for byte. A collector that is sent an event twice drops it
  by id.
- B-4 (nothing new is said). An event holds only what its ledger entry holds and the report already prints:
  no command line, no file content, no destination the report does not print, no secret (A9). A text is the
  report's sentence, not a new one.
- B-5 (ATT&CK ids are declared, not guessed at run time). A catalog rule declares `attack:` (a list of
  technique ids, `T` and four digits, a sub-technique's three after a dot); an empty list needs `attack_note:`
  saying why. `raqib check-rules` refuses a catalog rule without it. The rules written in code declare theirs
  beside their kind (silence.py, cross.py, tree.py), and the rule table carries the column. A user's own rule
  with no `attack` loads as before (empty). The table, the Table's and the commander's to correct:
  NEW-AGENT, NEW-AGENT-UNKNOWN: T1059. HOST-RHYTHM: T1059, T1071. NET-TOOL: T1105, T1048. DESTRUCT-CMD: T1485.
  SECRET-OUTPUT: T1552. SCOPE-PATH: T1005. The five SILENCE rules and CROSS-SOURCE: T1562.
  Empty, with the note "a rule about the agent's own work or the watch's own sight, not a technique":
  AGENT-DARK-LIVE, HOST-UNWATCHED, SCOPE-CWD-ROOT, SCOPE-CWD-MOVED, DRIFT-FILES, EDIT-NO-TEST, LANDED-NO-GATE and
  the two tree anchors. A technique id says what a finding is consistent with, never that it happened.
- B-6 (the contract is a document). `docs/specs/EVENT.md` states every key, per kind which are required, one
  example line per kind (made by the module, checked by a test against it), and the mapping of each key to
  OCSF (Detection Finding) and to ECS names. A test reads the document: a key the module can emit and the
  document does not name, or the reverse, fails.
- B-7 (tested on the watch's own entries). The entries the tests feed the module are made by the watch on
  fixtures (a fixture run's findings, source findings, holes, notes, knocks, trees, state), not written by hand:
  a shape the watch does not make proves nothing.
- Not in M10.1, named: the watch writing events and the heartbeat's beat (M10.2); the forwarders, the local
  sinks and the stand-in collectors on the rig (M10.3); the window's panel (M10.4).

## Amendment C (the Table, 2026-11-13) - rulings on review 2026-11-13-M10.1.md (3ff5c99): REDO
The build did what Amendment B said; where it is wrong, B was. The Table read the examples before the packet
came and found three things: (a) a cite was passed through whole, with the raw row of the inventory - a process
row with its command line - which B-4 forbids and the report never prints; (b) a heartbeat and a watch's end
took their word from the window's band (WATCHING, FINISHED), so a watch with a finding ended "FINISHED, exit
0"; (c) the Windows gate failed on a test that compared paths of two temporary directories. The packet found
what matters more: B made an event's number its identity, and a number is a position.
- C-1 (F2, F14: what an event is). An event is a thing said once. `id` ("<run>:<n>", n rising by one for each
  event the run says) names the saying and is never used twice; a collector keys by watch.host and id. What the
  event is about is named apart: `about` ("finding:3", "source-finding:2", "hole:1", "blind:1", "note:4",
  "knock:2": the ledger and the entry's place in it, from 1; "tree:<the tree's word>"; "watch") and `rev` (1
  the first time it is said; one more each time it is said again because it changed: a finding that grew, a
  knock whose fold was decided, a tree that was knocked). Both are given by the caller. The module's function
  over a whole state is `snapshot` (it was `ledger`): the events of one finished watch in one call, n from 1,
  rev 1; its document says it is not how a running watch says events (M10.2 keeps the count and says a changed
  thing again). FOR: a collector that drops what it has seen never drops what it has not.
- C-2 (the shape, replacing B-2's list; the key order as given). schema; id; n; time; kind; about; rev;
  severity; alarm; summary; rule {id, class, kind, fp_budget, attack}; subject {tree, pid, image, started,
  named, agent, path, benign, history, by}; evidence {run, round, rounds, record, source, trace, seqs, lines,
  cites}; hole {kind, class, count, last}; knocked {status, event, title, limit_id, called}; state; result
  {word, exit}; counts {rounds, findings, source_findings, holes, blind, notes, trees, knocks}; watch {run,
  mode, platform, version, host}. The kinds are B-2's eight.
- C-3 ((a), F7, F9, F11: evidence). A cite is {src, line} and, where the entry's cite holds them, {round, seq}:
  never its text, under any key. `evidence.rounds` is a rhythm finding's cycle rounds. `evidence.record` is the
  file the seqs are in (the state's trace) for a finding, a tree and a note of the rounds; `evidence.trace` and
  `lines` stay the source finding's own. Paths are said as the report says them (they hold the account's name
  where the machine's do; EVENT.md says so). MUST NOT be in any event: a command line, a row of a sample.
- C-4 (F3, F4: a source finding's state, and whether it is an alarm). The state is the report's own word, in
  the report's own order: judged on another tree; history; noted; pending at exit; not settled; settled. B-2's
  list gains the two it lacked. `alarm` (finding and source-finding; a hole) is whether the report counts it
  under ALARMS or INCOMPLETE: true for a finding of the rounds; true for a source finding that is settled, not
  settled or pending at exit; false for one that is history, judged on another tree or noted; true for a hole,
  false for a blind spot. The severity stays the rule's: the consumer is told both.
- C-5 ((b): the watch's word). A heartbeat's `state` is the band's word (the watch is alive, silent or failed);
  its `result` is the exit the watch would end with now (the state's code so far) and that code's word. A
  watch's end has `result` from the exit the caller gives. The words are the fixed three: 0 CLEAN, 1 ALARM, 3
  INCOMPLETE; another code has no word, only the exit.
- C-6 (F1, F8: holes). A hole event has `hole` {kind: the hole's own kind; class: "hole" or "blind spot";
  count and last where the entry holds them}. A blind spot (the state's blind) is an event of kind hole, class
  "blind spot", severity "info"; a hole's severity is "hole". counts gains blind and knocks.
- C-7 (F6, Q4, Q6: trees). `subject.named` is a boolean on every kind (a finding's word becomes the boolean it
  means; a word that is neither of the report's two leaves the key out). A tree's subject gains started (the
  third part of its key), benign, history and by (how it became a candidate, where the row says). A tree
  event's time is the row's own first-seen time where it has one.
- C-8 (F5, Q3: knocks). A knock event carries title, limit_id and called beside status and event. `snapshot`
  takes the knock rows as an argument it must be given (the state keeps only the newest). Which finding a knock
  was for is M10.2's (the writer knows both).
- C-9 (F10: B-4 read rightly). B-4 is about what an event says of the watched machine. A rule's own class,
  kind, budget and technique ids are the rule's, written in its file: they are in the event and need not be in
  the printed report. An empty `attack` means the rule declares none; EVENT.md says a catalog rule's file says
  why and a person's own rule may declare none.
- C-10 (check). `check` knows each key's type and each closed list (kind, severity, a source finding's state,
  hole.class, result.word); a time must be a real instant; a finding and a source finding need rule.attack (a
  list), alarm, about and rev; a watch's end needs result.exit. What the module builds from any entry the
  watch makes passes; an entry that lacks what a kind requires is not built into a half event: the function
  raises ValueError naming the key (M10.2 turns that into a hole).
- C-11 (EVENT.md, the mapping; the Table's, checked against OCSF 1.5.0's Detection Finding and Finding
  Information). Every key has a type and, where closed, its values. A key maps to a named field or to the
  namespace: OCSF `unmapped.raqib.<key>`, ECS `raqib.<key>`. Named, and no others:
  finding, source-finding and hole are OCSF Detection Finding (class_uid 2004, category_uid 2; activity_id 1
  Create at rev 1, 2 Update after; type_uid 200400 + activity_id); every other kind is OCSF Base Event
  (class_uid 0). time -> `time` as epoch milliseconds and `time_dt` as given; ECS `@timestamp`.
  severity -> `severity_id` high 4, medium 3, low 2, info 1, hole 3; ECS `event.severity` the same number.
  alarm -> `is_alert`; ECS `event.kind` "alert" when true, else "event". id -> `finding_info.uid`; ECS
  `event.id`. about -> `metadata.correlation_uid`. summary -> `message` and `finding_info.desc`; ECS `message`.
  rule.id -> `finding_info.analytic.uid` and `finding_info.title`; ECS `rule.id`. rule.class -> ECS
  `rule.category`. rule.attack -> `finding_info.attacks[].technique.uid`; ECS `threat.technique.id`.
  subject.pid, subject.image -> `evidences[].process.pid`, `.process.name`; ECS `process.pid`, `process.name`.
  watch.host -> `device.hostname`; ECS `host.name`. watch.version -> `metadata.product.version`
  (`metadata.product.name` is "Raqib"); ECS `observer.version` (`observer.product` "Raqib"). kind -> ECS
  `event.action`. knocked.status -> `status_detail`. The whole line -> `raw_data`; ECS `event.original`.
  A test holds this table against the document.
- C-12 (the tests, section 9 and E2). No assertion compares a thing with itself. The entries reach, by fixture
  watches, each state of C-4, a HOST-RHYTHM finding, a footprint finding, a hole that knocked, a notifier's
  hole, a blind spot, a folded or rate-limited knock, a benign tree and a tree there at the start. A broken or
  non-ASCII event for `check` is a built event with one value changed, not one written by hand. The same
  entries give the same lines on every platform: the two runs share one home, or the comparison is of values
  no path enters. "Nothing new is said" is tested against what the report prints and the rule declares, not
  against the entry's own strings: no string of a cite's text, of a sample row, is in any line.
- Recorded, not built: F12 (a time that does not parse is replaced by the caller's, unsaid); a kind for the
  model layer's suspicions, and events for the watch's own errors (M10.2); F13 is said, not changed.
- The ledger. The Table wrote a shape before asking how a thing that changes is said twice; a contract's
  first question is identity, and it was the reviewer who asked it.

## Amendment D (the Table, 2026-11-13) - rulings on review 2026-11-13-M10.1-redo.md (eabca24): REDO, narrow
The packet's verdict is STOP, because the fix changes words C-1 wrote: so it is the Table's, and here it is.
C-1 gave a thing a name by "the ledger and the entry's place in it" and did not ask whether every list the
state shows is one ledger: the state shows the watch's holes followed by the notifier's, and the notes followed
by one note that is always last. A place in a joined list moves. The Table also ran the module on a real watch
of this machine (two trees, a blind spot, three notes): eight events, none refused by check, no row or command
line in any line. And the six CI jobs are green on eabca24, Windows among them.
- D-1 (C-1 completed: a name is a place in a list that only grows). A hole of the watch is "hole:i"; a hole of
  the notifier is "notifier-hole:i" (each counted in its own list; the notifier's entry is the one that holds
  a count). A note is "note:i" over the watch's own notes; the note of the words a terminal lost, which is
  always last and whose text changes, is "note:lost-words" (snapshot is told its text by an argument; without
  it the note is numbered as any other, and snapshot's document says so). FOR: a hole made after a failed
  knock never takes the failed knock's name. MUST NOT TOUCH: findings, source findings, blind spots, knocks,
  trees (their lists only grow; the packet checked each).
- D-2 (what a thing is called outside its run). `about` is a name within one run. EVENT.md says so, and its
  mapping uses the run and the name together: "<watch.run>/<about>" -> OCSF `finding_info.uid` and
  `metadata.correlation_uid`; ECS `event.id` stays the event's id. The event's own id -> OCSF `metadata.uid`
  (it was `finding_info.uid`: then every time a finding was said again it would have been a new finding).
  C-11's two pairs for id and about are replaced by these; `activity_id` and `type_uid` from rev, and
  `class_uid` and `category_uid` from kind, are C-11's own words and stay in the table. For a hole,
  hole.kind -> `finding_info.title`. For the kinds that are Base Event: id -> `metadata.uid`, summary ->
  `message`, the rest in the namespace.
- D-3 (the host is not optional). `watch.host` is required on every event: check refuses an event without it,
  and `facts` refuses to be called without it. A collector keys by it.
- D-4 (a heartbeat's state is a closed word). WATCHING, SILENT, AGENT GONE, CAPTURE FAILED, FINISHED: the
  band's word without its number ("SILENT for 12 s" is SILENT). check knows the list.
- D-5 (small, each as the packet names it). A cite that lacks its src or its line is left out whole, never
  half. A value that is an empty string is not held. check refuses a negative round, pid, seq, line or n, and a
  technique id twice. A blind spot's `hole.count` is the number of rounds it was seen in. The document says:
  that a source finding's state is C-4's word and what the report prints for each of the six; the base of
  `evidence.lines`; that `subject.by` is carried by no event yet; that the heartbeat's and the watch-end's
  examples are the last event of two snapshots of one watch (so they share a number, and are never both in
  one stream).
- D-6 (the tests the packet shows to be weak). No cite text of any ledger is in any line, with no exception
  for texts the report prints (a report prints no cite's text). A hole's alarm is compared with the watch's
  result (INCOMPLETE and the report's HOLES), not with the event's own class. A value is "in the report" when
  it is in the report's line for that entry, not anywhere in the report. Two new cases through fixture
  watches: a watch's hole made after a notifier's hole (their names do not move between two snapshots), and a
  note made after the lost-words note is given.
- Accepted as built, said: Q7 (the report's order), Q8 (C-4's words), Q10 (a cite's src and a tree's start are
  the entry's own), Q11 (a name is stable within a run; two runs of one input may number source findings
  differently), Q13 (the folded knock is made by a second call of the notifier on the watch's own finding: no
  fixture watch folds by itself).
- Recorded for M10.2, where raqib/host.py is in Scope: the tree row's `candidate_by` (so `subject.by` is
  carried); a tree's benign word and its HOST-UNWATCHED and HOST-RHYTHM knocks; a source finding's growth; a
  knock's shown-on and knocked-on; the watch's own errors (code_error, state_error) as events; an entry that
  makes a builder raise becomes a hole, one entry, never a whole pass; that a snapshot's events and a running
  watch's are never sent as one stream.

## Amendment E (the Table, 2026-11-13) - on the second REDO of M10.1 (9e8cecd) and its questions
- E-1 (Q15: D-4's list was short, and the Table completed it itself, CLAUDE.md rule 8). D-4 named five words;
  a host watch's band has two more, READER LATE and HOST READER FAILED, and the build, following D-4, refused a
  heartbeat in exactly the state a collector most needs to hear of: a watch that cannot read. The list is every
  word a band can be, and a test reads the band's own code so that a word added there and not here fails.
  FOR: a watch whose reader failed still beats. MUST NOT TOUCH: a word that is none of them is still refused.
- E-2 (Q14). D-6 said the report prints no cite's text; a footprint's cite is its path, and the report prints
  the path. The test as built is the one meant: every cite's text and every sample's row is replaced by a
  marker before the events are built, and no marker is in any line and no line changed.
- E-3 (Q16). `hole.last` and `evidence.record` are values of the entry and the state that the report's line
  for the entry does not hold; allowed by name, as built. "The rest in the namespace" means every key D-2 and
  C-11 do not name: OCSF `unmapped.raqib.<key>`, ECS `raqib.<key>`, for every kind.
- E-4 (review 2026-11-13-M10.1-redo2.md: NEXT; the gate and the six CI jobs green on 00069ed). The document
  now gives `snapshot`'s arguments in the module's order, says what `about` is in D-1's words, and holds E-3's
  sentence. Everything else the packet raises is the writer's, and is M10.2's HANDOFF, not a third REDO: how a
  running watch tells the lost-words note and a notifier's hole without `snapshot` (the watch knows which
  list an entry is in; the module's "the one that holds a count" is for a state read back from a file); which
  changes are said again (a finding that grew, a knock decided, a tree knocked, a hole's count: yes; a blind
  spot's rounds and a new lost-words text: at the heartbeat's beat, not at each); what a builder that raised
  becomes; a finding whose every cite was left out (said, with their number; never an event with an empty
  list); a snapshot of a watch whose reader failed; examples of a notifier's hole and the lost-words note; the
  counts beside the split names; the tests the packet shows to be weak (section 5).

## Amendment F (the Table, 2026-11-13) - the watch writes its events (M10.2)
The shape is in the tree (M10.1). This is the writer: the host watch says, as events in a file beside its
record, everything it judged, while it runs. Nothing is sent anywhere yet (M10.3); the file is what a
collector's own agent can already tail.
- F-1 (one writer, outside the judging). `raqib/eventlog.py`: it is given the file, the watch's facts and the
  rule table; it keeps the run's count (n) and, for each thing by its `about`, the revision last said and
  what was said. `say` builds the event with raqib/event.py, and writes one line - appended, flushed - when
  the thing is new (rev 1) or what would be said of it changed (the next rev); the same again is not written.
  FOR: C-1. MUST NOT TOUCH: how anything is judged, knocked or reported; a rule's result never waits for it.
- F-2 (when). One pass of the watch over its own ledgers at the end of every round and at the finish: the
  trees, the findings, the source findings, the watch's holes ("hole:i"), the notifier's ("notifier-hole:i"),
  the blind spots ("blind:i"), the notes ("note:i"), the knock rows ("knock:i"). The watch names each from the
  list it is in; it does not guess from what an entry holds. The first event of a watch is its start, the last
  its end, with the report's own result and exit.
- F-3 (the heartbeat). On a fixed beat (`--beat S`, 60 s by default, never shorter than a round): a heartbeat
  event with the watch's state and counts. The watch is one thing ("watch"): its start is rev 1 and each beat
  and its end the next rev. Two things change every round or every lost word and would otherwise be said each
  time: a blind spot's count and the lost-words note ("note:lost-words"); they are said again only with a
  beat. FOR: a collector alarms on Raqib's own silence. A beat is written even when nothing else changed.
- F-4 (what cannot be said is said). A builder that raises (an entry lacking what its kind requires) becomes a
  hole of the watch, one per thing, naming the thing and the key; the pass goes on to the next entry. A line
  that cannot be written (the file, the disk) is a hole said once, and the count of events not written is in
  the report and the state; the watch goes on. A cite left out because it lacked its source or its line is
  counted on the event (`evidence.cites_left_out`), and an event never holds an empty list of cites.
- F-5 (the knock and its thing; the tree's road). A knock event names the thing it knocked for
  (`knocked.for`: that thing's `about`), which the writer knows. A tree's row carries how it became a
  candidate, so `subject.by` is said. Both are additions to `raqib-event/1`, made before anything reads it;
  EVENT.md, check and the tests follow.
- F-6 (the host's name). Read once at the start from the system (no network call); `--event-host NAME`
  replaces it; a system that gives none: the watch says so at its start and uses "unnamed".
- F-7 (said to the person). The watch's first lines name the events file and the beat; the report has a line
  EVENTS (written, heartbeats, not built, not written, the file); the state carries the same numbers.
- F-8 (a tool for whoever connects a collector). `raqib events FILE`: checks every line with `event.check`,
  prints the count per kind and each problem with its line number; exit 0 when every line is an event, 1
  when not, 2 when the file cannot be read. It reads; it sends nothing.
- F-9 (the rig). The rig's check reads the events file of its watch: every line is an event; a start and an
  end; an event for each finding the report lists; heartbeats where the watch outlasted a beat.
- Not in M10.2, named: sending (M10.3); the window's panel (M10.4); a kind for the model layer's suspicions
  and events for the watch's own errors (recorded for M10.3's handoff); `raqib watch PROJ` (the session
  watch) writing events: after the host watch has proven the road.

## Amendment G (the Table, 2026-11-13) - rulings on review 2026-11-13-M10.2.md (a9667eb), the rig, and a real watch: REDO
The writer works: a real watch here, and the rig's two machines, wrote files in which every line is an event,
with a start, an end and heartbeats. Three things showed only by running. The rig's own X18 was MISSED on
Windows: four source-finding events where the report lists two - an act that the host's sample and Sysmon both
saw is one line of the report and was two alarms in the file. Every tree and every blind spot was said again
at every beat with nothing new. An event said again carried the time of the first saying.
- G-1 (one act, one alarm). A pair the report takes for one act (its listing's own join) is one alarm in the
  file: the entry the listing folds is said with `alarm` false and `evidence.same_as`, the `about` of the entry
  it is one with. The pass finds the pairs by the function the report uses, once a pass. A pair found after
  both were said makes the folded one's next rev. X18 compares things: of the report's run only, the events
  that are alarms' own things - every finding and every listed source finding has its event, and no event of
  the run is a listed thing the report does not hold.
- G-2 (what is said again). A thing is said again when what a consumer acts on changed. A tree's latest record
  line and cites, and a blind spot's count, are not that: they are not said again at a beat. The last state
  of each is said once, at the finish, so that the file read back still equals the snapshot. A tree knocked,
  made benign or history, or named: at once, as built. The lost-words note: at a beat, as built.
- G-3 (time). `time` is when the event is said: the entry's own time at rev 1, the time of the pass that
  says it at any later rev.
- G-4 (the end's word). `result.word` is the report's own word: CLEAN, ALARM, INCOMPLETE or NONE-SEEN (a
  closed list of four, in check and in EVENT.md); a clean result with findings suppressed by the person's
  overlay says CLEAN and `result.suppressed`, their number. The watch gives the word; the module does not
  derive it from the exit. A heartbeat's result keeps C-5's three words from the code so far.
- G-5 (Q4: a hole is a hole). An events file that cannot be written, and an entry that cannot be built, are
  holes of the watch, and a watch with a hole is INCOMPLETE: as built. It is not F-1's "judging": nothing
  judged waits for it.
- G-6 (the writer cannot harm the watch; section 4). (a) Nothing the pass calls can end it: each entry is
  built, lined and written inside its own guard, the watch's own naming too; a pass that failed for one
  ledger goes on to the next and still writes a due beat; a failing pass is not tried again at every tick.
  (b) A line is never glued to a torn one: before a line is appended, a file that does not end in a newline
  gets one (as the record's own writer does); a write that failed is never counted as said. (c) Its cost is
  bounded and said: between beats the pass looks at what is new in each list and at what can still change
  (the trees, the source findings not yet settled, the knocks not yet decided, the notifier's holes); at a
  beat and at the finish it looks at everything; what a knock was for is found by one table made once a pass,
  not by a search for each knock; the longest pass is in the state and on the report's EVENTS line.
- G-7 (a watch that was killed). EVENT.md and THREAT_MODEL say what a start with no end means: a run whose
  last line is older than two beats was stopped or killed, and that silence is the collector's alarm; a last
  line that is not whole JSON is a torn write.
- G-8 (ADR-0007 AD-4 stands). The state's tree does not carry `candidate_by` again. The pass takes "by" from
  where the watch holds it without putting it on the state's row; the test that claimed its absence looks
  where the trees are.
- G-9 (`knocked.for`). It names only a thing said in this file. A knock for a thing that was not built, or
  for a suspicion (no kind yet), has none.
- G-10 (the end is said once, last, and the report counts it). The result is computed, the end is written,
  then the EVENTS line is made: the report and the state say what the file holds. No second end.
- G-11 (Q11: the builder should have stopped; the Table should have put the files in Scope). README.md and
  docs/GUIDE.md name `events` in their Commands tables, by the test's own rule; the exception in
  tests/test_readme_top.py is taken out.
- G-12 (tests the packet shows to be weak). `subject.by` "channel" on a tree that became a candidate by the
  channel; the exit of a watch with no finding and an unwritable events file (3); a NONE-SEEN watch's end; a
  torn file; a pass in which one ledger raises; a told-twice pair through the watch and through X18; the
  host-name line among the first lines.
- Accepted as built: Q3 (a number is used once; "not written" counts attempts - the report says "attempts"),
  Q5, Q7, Q8 with G-9, Q9 (and X17 wants at least one heartbeat for each two whole beats the watch ran),
  Q10, Q12.
- G-13 (the REDO's STOP, c1e7919: the builder stopped rather than change a guard, and was right to; the Table
  answered, CLAUDE.md rule 8). The guide's Commands table has the row of `raqib events`; the guard's list of
  the guide's own rows names it (a row of the guide only: the README names the command among "the rest").
  QR2 recorded: `result.suppressed` is tested with the overlay's count replaced, since no rule of the host
  fires on the clean fixture watch; a watch with a real overlay that suppresses a finding is M10.3's to add.

## Amendment H (the Table, 2026-11-13) - rulings on review 2026-11-13-M10.2-redo.md (bc57cc9): REDO, narrow
The REDO did what G said, and the rig now meets X18 on Windows: one act, one alarm. The packet's main finding
is against the Table's own G-6 (c). To bound the pass, G-6 (c) had it look between beats only at "what can
still change", and the build took that to mean an entry not yet settled. A settled entry still changes: an
act's standing moves to a nearer tree, a fold is decided, a finding grows. So a change could wait a whole beat:
two alarms for one act for up to a minute, or one alarm on the wrong tree. The Table bought cost with silence,
which the ledger says never to do; a bound must be on the work for an entry that did not change, not on which
entries are looked at.
- H-1 (G-6 (c) replaced). Every pass looks at every entry of every ledger that can change: the findings, the
  source findings, the watch's holes, the notifier's holes, the knock rows, the trees; and at the notes that
  are new or that the watch replaced in place since the last pass (the watch tells the writer which: it knows
  the three places it does that). The bound is this: for each entry the writer keeps the values the event is
  built from; where they are what they were, nothing is built. A test holds, for each kind, that a change of
  any value the builder reads changes what is kept (so no change can hide), and that a pass over a watch with
  thousands of unchanged entries builds nothing. FOR: a changed thing is said in the pass that follows the
  change. The longest pass stays in the state and the report.
- H-2 (G-1, said for the collector). Where the os source tells an act before the host's sample does, the os
  entry is said as an alarm and is folded by its next rev. That is G-1 as ruled; what was missing is the
  sentence in EVENT.md: an alarm can be taken back by a later rev of the same thing (`alarm` false, with
  `evidence.same_as`), so a collector keys an alert by the run and the thing's name and takes its latest rev.
  Where the kept half was not built or not written, the folded half is not folded: an act always has an alarm.
- H-3 (G-6 (a) completed). The read of an entry is inside the entry's own guard too (a knock row that raises
  when it is read stops that row, not the rows after it); a failure of a whole list is said once, not at every
  pass.
- H-4 (G-6 (b) completed). The file's end is checked before every line, not only the first: a line is never
  appended to a fragment, whoever left it. What a failed write leaves to be said is said at the next pass,
  whatever it was: a first saying, a later rev, the start. A watch whose start could not be written writes it
  before anything else when the file can be written again. A heartbeat is a new rev each time, never a number
  used before.
- H-5 (the end's word is the report's, also when the watch's own files fail). The watch writes its state
  before it computes the result that the end says; what fails after the end (the report itself, the last
  write of the state) is in the report alone, and EVENT.md says that the end cannot hold it.
- H-6 (the beat is in the file). `watch.beat`, the heartbeat's interval in seconds, is on every event: a
  reader of the file alone can tell a run that went silent for more than two beats.
- H-7 (the snapshot knows a pair). `snapshot` is given the pairs, so the file read back equals it for a watch
  with a pair too; tested on one.
- H-8 (EVENT.md, a section for whoever reads the file). The file holds many runs; Raqib only appends to it and
  never rewrites, rotates or truncates it; a last line with no newline is still being written; a line in the
  middle that is not JSON is a torn write, to be skipped and counted; within a run n rises in the file's order,
  with gaps; one thing at one rev can be under two ids after a failed write; `time` is when the thing was said
  and does not rise from line to line (a first saying carries the entry's own time); a run with a start and no
  end has not said its trees' last evidence. The sentence that the watch does not write events yet is gone, and
  `snapshot` is given as the module has it.
- H-9 (tests). The host-name line in what the watch really prints at its start; the tests the packet's section
  10 shows to be weak, each made able to fail (a pair in every order of arrival; a per-entry failure among
  good entries; a pass with a beat due; an entry changed after it settled).
- Recorded, not built: a tree's event does not carry its HOST-RHYTHM and HOST-UNWATCHED knocks (their findings
  do); a write whose bytes landed and whose close failed is said twice (two ids, one rev).

