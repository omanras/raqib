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

