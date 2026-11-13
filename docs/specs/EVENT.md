# EVENT - the event, raqib-event/1 (ADR-0011 Amendment B, M10.1)

An event is one line Raqib says about what its watch holds: a finding, a source finding, a note, a tree, a
hole, a knock, a heartbeat, or the watch's start and end. It is built once, in Raqib's own shape, by one
module (`raqib/event.py`, B-1); a collector's shape (OCSF, ECS) is a mapping of it, given below. The watch
does not write events yet (M10.2).

- One line: JSON, keys sorted, compact (no spaces), ASCII (non-ASCII escaped). The same ledger gives the same
  lines byte for byte (B-3). A collector that is sent an event twice drops it by `id`.
- Nothing new is said (B-4): an event holds only what its ledger entry holds and the report prints; a text is
  the report's sentence. No command line, no file content, no secret.
- A key the entry does not hold is absent: never null, never guessed (B-2).
- A technique id in `rule.attack` says what a finding is consistent with, never that it happened (B-5).

## Keys

In B-2's order of meaning (a line sorts them). A dotted name is a key of the object named before the dot.
OCSF: the Detection Finding class (2004); a key with no OCSF attribute goes under `unmapped`. ECS: a key with
no ECS field goes under the custom field set `raqib`.

| key | meaning | kinds | OCSF (Detection Finding) | ECS |
|---|---|---|---|---|
| `schema` | the shape's name and version: raqib-event/1 | all | metadata.version (the shape: metadata.log_name) | event.dataset |
| `id` | <run>:<n>: unique in a run; a collector sent an event twice drops it by id | all | metadata.uid | event.id |
| `n` | the event's number in its run, from 1, rising | all | metadata.sequence | event.sequence |
| `time` | when Raqib said it: UTC, ISO 8601, milliseconds, Z (an entry's own time where it holds one, else the caller's) | all | time | @timestamp |
| `kind` | finding, source-finding, note, tree, hole, knock, heartbeat or watch | all | class_uid 2004 (Detection Finding) for finding and source-finding; the rest are not findings (unmapped.kind) | event.kind (alert for finding and source-finding, event for the rest); event.action |
| `severity` | the rule's high, medium or low (finding, source-finding); hole for a hole; info for the rest | all | severity, severity_id (high 4, medium 3, low 2, info 1; hole: 99 Other) | event.severity, log.level |
| `summary` | one sentence, the report's own (a hole: its HOLES line, kind: detail; a knock: its body) | finding, source-finding, note, hole, knock | message; finding_info.desc | message |
| `rule` | the rule that fired | finding, source-finding | finding_info.analytic | rule |
| `rule.id` | the rule's id | finding, source-finding | finding_info.analytic.uid, finding_info.analytic.name | rule.id, rule.name |
| `rule.class` | the rule's class (NET, HOST, SILENCE, CROSS ...) | finding, source-finding | finding_info.analytic.category | rule.category |
| `rule.kind` | signature, demand or anchor (ADR-0002) | finding, source-finding | finding_info.analytic.type | rule.ruleset |
| `rule.fp_budget` | the rule's false-positive budget, from the rule table | finding, source-finding | unmapped.fp_budget | raqib.rule.fp_budget |
| `rule.attack` | the ATT&CK technique ids the rule declares (B-5): what a finding is consistent with, never that it happened | finding, source-finding | finding_info.attacks[].technique.uid (a dotted id: .sub_technique.uid) | threat.technique.id (a dotted id: threat.technique.subtechnique.id); threat.framework MITRE ATT&CK |
| `subject` | what the event is about; a key the entry does not hold is absent | finding, source-finding, note, tree | process / file | process / file |
| `subject.tree` | the tree's word as the report says it, pid:image:started | finding, source-finding, note, tree | process.uid | process.entity_id |
| `subject.pid` | the tree's root pid | finding, source-finding, tree | process.pid | process.pid |
| `subject.image` | the root's image name (discover's normalised form) | finding, source-finding, tree | process.name | process.name |
| `subject.named` | a finding: its named word (named, unknown ...); a tree row: whether it is named (true, false) | finding, tree | unmapped.named | raqib.subject.named |
| `subject.agent` | the agent a footprint is of | finding, note | actor.app_name | raqib.subject.agent |
| `subject.path` | the footprint's path | finding, note | file.path | file.path |
| `evidence` | where a person or a system can check it (A5); absent keys as for subject | finding, source-finding, note, tree, hole, knock | evidences[] | raqib.evidence |
| `evidence.run` | the run the cited lines are of | finding, source-finding, note | metadata.correlation_uid | raqib.evidence.run |
| `evidence.round` | the round of the watch | finding, note, hole, knock | unmapped.round | raqib.evidence.round |
| `evidence.record` | the record cited (named by B-2; no entry of M10.1 holds one, so it is never emitted yet) | none yet | unmapped.record | raqib.evidence.record |
| `evidence.source` | the source the cited lines are of (os, hooks, host) | source-finding | metadata.log_provider | event.provider |
| `evidence.trace` | the file the cited lines are in | source-finding | evidences[].file.path | log.file.path |
| `evidence.seqs` | the seqs cited (a tree: its HostTree line's) | finding, source-finding, note, tree | evidences[].data.seqs | raqib.evidence.seqs |
| `evidence.lines` | the line numbers cited in the trace | source-finding | evidences[].data.lines | raqib.evidence.lines |
| `evidence.cites` | the inventory's record lines cited (src, line, text) | finding, note, tree | evidences[].data.cites | raqib.evidence.cites |
| `knocked` | whether Raqib knocked a person for it and what became of the knock | finding, source-finding, tree, hole, knock | status, status_detail | raqib.knocked |
| `knocked.status` | the knock's status now (sent, off, not notified: ..., a fold's outcome) | finding, source-finding, tree, hole, knock | status_detail | raqib.knocked.status |
| `knocked.event` | the knock's event (the KNOCKS ledger's event column) | knock | unmapped.knock_event | raqib.knocked.event |
| `state` | a source finding: settled, history, judged on another tree, noted (or the entry's own pending at exit); a watch event: start or end | source-finding, watch | status (a watch: activity start or end) | event.type (a watch: start, end) |
| `result` | the watch's word and exit | heartbeat, watch end | status, status_code | raqib.result |
| `result.word` | the window's band word (WATCHING, FINISHED ...) | heartbeat, watch end | status | raqib.result.word |
| `result.exit` | the watch's exit code, as the caller gives it | watch end | status_code | process.exit_code |
| `counts` | what the ledger holds so far | heartbeat, watch end | unmapped.counts | raqib.counts |
| `counts.rounds` | rounds attempted | heartbeat, watch end | unmapped.counts.rounds | raqib.counts.rounds |
| `counts.findings` | findings of the rounds | heartbeat, watch end | unmapped.counts.findings | raqib.counts.findings |
| `counts.source_findings` | findings of the trees' sources | heartbeat, watch end | unmapped.counts.source_findings | raqib.counts.source_findings |
| `counts.holes` | holes (the watch's and the notifier's) | heartbeat, watch end | unmapped.counts.holes | raqib.counts.holes |
| `counts.notes` | notes | heartbeat, watch end | unmapped.counts.notes | raqib.counts.notes |
| `counts.trees` | trees seen | heartbeat, watch end | unmapped.counts.trees | raqib.counts.trees |
| `watch` | the watch's facts, on every event | all | metadata.product, device | observer, host |
| `watch.run` | the watch's run | all | metadata.correlation_uid | raqib.watch.run |
| `watch.mode` | the watch's mode (host) | all | metadata.product.feature.name | observer.type |
| `watch.platform` | the platform the watch runs on | all | device.os.name | host.os.platform |
| `watch.version` | Raqib's version | all | metadata.product.version | observer.version |
| `watch.host` | the host's name, as the caller gives it | all | device.hostname | host.name |

## Required keys

Every event holds the keys of the first seven; each kind adds its own. A watch end (`state` end) holds
`result` and `counts` too; a watch start holds neither. Any other key of the table is held only where the
entry holds it. `event.check(obj)` names every problem of an event; every event the module builds has none.

| kind | required keys |
|---|---|
| finding | `schema`, `id`, `n`, `time`, `kind`, `severity`, `watch`, `summary`, `rule`, `evidence` |
| source-finding | `schema`, `id`, `n`, `time`, `kind`, `severity`, `watch`, `summary`, `rule`, `subject`, `evidence`, `state` |
| note | `schema`, `id`, `n`, `time`, `kind`, `severity`, `watch`, `summary` |
| tree | `schema`, `id`, `n`, `time`, `kind`, `severity`, `watch`, `subject` |
| hole | `schema`, `id`, `n`, `time`, `kind`, `severity`, `watch`, `summary` |
| knock | `schema`, `id`, `n`, `time`, `kind`, `severity`, `watch`, `summary`, `knocked` |
| heartbeat | `schema`, `id`, `n`, `time`, `kind`, `severity`, `watch`, `result`, `counts` |
| watch | `schema`, `id`, `n`, `time`, `kind`, `severity`, `watch`, `state` |

## Examples

One line per kind, each the line `raqib/event.py` builds (`event.ledger`, host `host.example`) from the watch
of a named fixture run (B-7); `tests/test_event.py` builds them again and compares. The fixture's home
directory is written `~`. Run A: the field run of `tests/test_field_run.py` (run `field-run`). Run B: the os
source of `net-windows` on powershell pid 5888 of `tests/test_acts_judged.py` (run `fixture-run`). Run C: a
reader that fails in round 2, as in `tests/test_host.py` (run `hole-run`).

### example: finding

From run B.

```json
{"evidence":{"cites":[{"line":8,"src":"win-process-1","text":"\"5888\",\"5100\",\"powershell.exe\",\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\",\"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"\",\"2026-11-10T07:50:00.000Z\""},{"line":4,"src":"win-tcp-1","text":"\"192.0.2.10\",\"50100\",\"203.0.113.40\",\"443\",\"Established\",\"5888\",\"2026-11-10T07:55:00.000Z\""},{"line":9,"src":"win-process-1","text":"\"5890\",\"5888\",\"conhost.exe\",\"C:\\Windows\\System32\\conhost.exe\",\"\\??\\C:\\Windows\\system32\\conhost.exe 0x4\",\"2026-11-10T07:50:00.100Z\""}],"round":2,"run":"fixture-run","seqs":[1]},"id":"fixture-run:3","kind":"finding","knocked":{"status":"off"},"n":3,"rule":{"attack":["T1059"],"class":"HOST","fp_budget":0.4,"id":"NEW-AGENT-UNKNOWN","kind":"anchor"},"schema":"raqib-event/1","severity":"medium","subject":{"image":"powershell","named":"unknown","pid":5888,"tree":"5888:powershell:2026-11-10T07:50:00.000Z"},"summary":"unknown agent tree powershell pid 5888 (round 2, was absent)","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: source-finding

From run B.

```json
{"evidence":{"lines":[8,9],"run":"fixture-run","seqs":[5],"source":"os","trace":"~/.raqib/host/sources/fixture-run-5888-04cd10d3a5.jsonl"},"id":"fixture-run:4","kind":"source-finding","knocked":{"status":"off (knocked on tree pid 5888)"},"n":4,"rule":{"attack":["T1105","T1048"],"class":"NET","fp_budget":0.25,"id":"NET-TOOL","kind":"signature"},"schema":"raqib-event/1","severity":"medium","state":"settled","subject":{"image":"powershell","pid":5888,"tree":"5888:powershell:2026-11-10T07:50:00.000Z"},"summary":"process may reach the network at seq 5 (host -, program bitsadmin, programs [\"bitsadmin.exe\"])","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: note

From run A (the dark note).

```json
{"evidence":{"cites":[{"line":2,"src":"footprints","text":"C:\\Users\\user\\.kimi"}],"round":13,"run":"field-run","seqs":[27]},"id":"field-run:9","kind":"note","n":9,"schema":"raqib-event/1","severity":"info","subject":{"agent":"kimi","path":"C:\\Users\\user\\.kimi","tree":"10728:kimi:11/2/2026 10:21:05 AM"},"summary":"round 13: kimi footprint C:\\Users\\user\\.kimi: dark after a live tree (note): no live tree for 3 rounds since its tree 10728:kimi:11/2/2026 10:21:05 AM was live (round 10, within the live window of 9 rounds); not a knock, not an alarm (cites run field-run seq 27)","time":"2026-11-03T10:02:00.000Z","watch":{"host":"host.example","mode":"host","platform":"test","run":"field-run","version":"0.1.0"}}
```

### example: tree

From run B.

```json
{"evidence":{"cites":[{"line":8,"src":"win-process-1","text":"\"5888\",\"5100\",\"powershell.exe\",\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\",\"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"\",\"2026-11-10T07:50:00.000Z\""},{"line":4,"src":"win-tcp-1","text":"\"192.0.2.10\",\"50100\",\"203.0.113.40\",\"443\",\"Established\",\"5888\",\"2026-11-10T07:55:00.000Z\""},{"line":9,"src":"win-process-1","text":"\"5890\",\"5888\",\"conhost.exe\",\"C:\\Windows\\System32\\conhost.exe\",\"\\??\\C:\\Windows\\system32\\conhost.exe 0x4\",\"2026-11-10T07:50:00.100Z\""}],"seqs":[2]},"id":"fixture-run:2","kind":"tree","knocked":{"status":"off"},"n":2,"schema":"raqib-event/1","severity":"info","subject":{"image":"powershell","named":false,"pid":5888,"tree":"5888:powershell:2026-11-10T07:50:00.000Z"},"time":"2026-11-03T10:00:30.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: hole

From run C.

```json
{"evidence":{"round":2},"id":"hole-run:6","kind":"hole","knocked":{"status":"sent"},"n":6,"schema":"raqib-event/1","severity":"hole","summary":"reader-failed: round 2: the reader failed: OSError: snapshot failed","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"test","run":"hole-run","version":"0.1.0"}}
```

### example: knock

From run B.

```json
{"evidence":{"round":2},"id":"fixture-run:10","kind":"knock","knocked":{"event":"NEW-AGENT-UNKNOWN","status":"off"},"n":10,"schema":"raqib-event/1","severity":"info","summary":"host, powershell pid 5888 (unknown)","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: heartbeat

From run B.

```json
{"counts":{"findings":1,"holes":0,"notes":3,"rounds":3,"source_findings":3,"trees":1},"id":"fixture-run:12","kind":"heartbeat","n":12,"result":{"word":"WATCHING"},"schema":"raqib-event/1","severity":"info","time":"2026-11-03T10:00:30.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: watch start

From run B.

```json
{"id":"fixture-run:1","kind":"watch","n":1,"schema":"raqib-event/1","severity":"info","state":"start","time":"2026-11-03T10:00:00.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: watch end

From run B (after its end, exit 0).

```json
{"counts":{"findings":1,"holes":0,"notes":3,"rounds":3,"source_findings":3,"trees":1},"id":"fixture-run:12","kind":"watch","n":12,"result":{"exit":0,"word":"FINISHED"},"schema":"raqib-event/1","severity":"info","state":"end","time":"2026-11-03T10:00:30.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

## Not here

The watch writing events and the heartbeat's beat (M10.2); the forwarders, the local sinks and the stand-in
collectors (M10.3); the window's panel (M10.4).
