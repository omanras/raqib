# ADR-0011 - Raqib below the agent, and beside other watchers

Status: proposed 2026-11-12, on the commander's words of that day after the third field run: Raqib must sit in a
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
