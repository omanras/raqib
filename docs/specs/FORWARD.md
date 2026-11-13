# FORWARD - the forwarder, raqib-forward/1 (ADR-0011 Amendment J)

`raqib forward` is a process of its own (J-1). It reads one events file - the watch's
`~/.raqib/host/events.jsonl`, as docs/specs/EVENT.md "For a reader of the file" says a reader may - and sends
every whole line to one destination: an HTTP collector (this task; syslog is the next, and until then a
`syslog+udp://`, `syslog+tcp://` or `syslog+tls://` destination is a usage error that says so). The watch does
not know it runs: raqib/host.py, raqib/eventlog.py, raqib/event.py and raqib/hooks/ import nothing of
raqib/forward.py, and no result, report or finding of a watch depends on a forwarder. The standard library only.

    raqib forward [FILE] --to URL --name NAME [--shape raqib|hec] [--token-file FILE] [--ca FILE] [--plain]
                  [--beat S] [--from start|end] [--batch N] [--once]
    raqib forward --status [NAME]

## What it sends, and what acknowledged means

- The file is the buffer (J-3). It is opened for reading only: never written, moved or locked. The forwarder
  keeps nothing of it but the batch in flight.
- The cursor is a byte offset at the end of the last whole line passed, kept with the sha256 of that line's
  bytes (its newline included). A line is passed when the collector took it, when it was skipped (not an
  event) or when it was refused alone (J-4). The cursor moves only past lines the collector took.
- `acknowledged` is HTTP's delivery word (J-3), and the state says it in `delivery`: a batch is taken when the
  answer is a 2xx and, in the hec shape, the answer's body is JSON whose `code` is 0. A 200 with another code is
  not taken. Taken is the collector's word: a collector that answers 2xx and drops the lines loses them.
- At least once, in order (J-3, J-11): one request at a time, the file's order, at most 100 lines and at most
  512 KiB to a request (`--batch N` lowers the count, 1 to 100). A batch that failed is sent again whole, and
  nothing after it is sent before it. A line whose piece of the body alone is over 512 KiB is refused locally:
  counted, its id kept, passed - never cut.
- A line that is not JSON or not an event (`event.check`) is skipped and counted (`skipped`), never sent; a last
  line with no newline is not whole and waits for its newline (J-5, EVENT.md).
- The file's identity (J-5): where the file is shorter than the cursor, or the line that ends at the cursor is
  not the line whose sha256 was kept, the file is another: it is read again from its start, counted in
  `restarts` and said. The collector then gets lines twice; `watch.host` and `id` tell them apart. The check is
  the length and the last line passed, not every byte before the cursor.
- Where a first run starts (J-12): at the file's start (Raqib sends everything it judged). `--from end` starts at
  the end of the file's last whole line, and `from` says from which offset. A later run of the same name goes on
  from its cursor; a name is one file, one destination and one shape (J-13), and another of these is a usage
  error.

## A refused line, a refused token, a failed send (J-4, J-10)

- A 4xx answer other than 401, 403, 408 and 429: the batch's lines are sent again one by one; a line refused
  alone is counted in `refused`, its `id` kept in `ids` (the latest 50) and passed. One bad line does not stop
  the lines after it.
- 401 and 403 are the token's: nothing moves, `failing` says `token`, and the token file is read again at every
  try (a file corrected between two tries is used at the next).
- Every other failure is a failed send: nothing moves, and it is tried again after 1, 2, 4, 8, 16, 32 and then
  60 s, for as long as it runs. A collector that is down never ends it. It ends at Stop (the batch in flight is
  finished or abandoned unmoved, the state written) or at a usage error. `--once` sends what the file holds
  once, with no second try, and ends: 0 every event line taken, 1 not all (a failed send or a refused line), 2
  usage.

The forwarder's own words for a failure (`failing.error`); an error is one of them and a status number, never
the collector's body:

| word | the failure |
|---|---|
| `connect` | no connection to the collector (within 10 s) |
| `tls` | the TLS handshake or the certificate failed |
| `no-answer` | the connection ended with no answer |
| `late` | no answer within 30 s |
| `redirect` | a 3xx answer (a redirect is never followed) |
| `busy` | 408 or 429 |
| `server` | a 5xx answer |
| `answer` | an answer that does not say the batch was taken (in the hec shape: a 2xx whose code is not 0) |
| `token` | 401 or 403 |
| `token-file` | the token file cannot be read at a try |
| `file` | the events file cannot be read |

## The shapes (J-6)

- `--shape raqib` (the default): the body is the lines as the file holds them, byte for byte, each with its
  newline; `Content-Type: application/x-ndjson`. With `--token-file`, `Authorization: Bearer <token>`.
- `--shape hec`: one envelope per line, in the shape Splunk's HTTP event collector takes, one after another,
  each on a line of its own: `{"time": the event's time as seconds since the epoch with its milliseconds,
  "host": the event's watch.host, "source": "raqib", "sourcetype": "raqib:event", "event": the event}`. The
  event's bytes are put in the envelope unchanged. The header is `Authorization: Splunk <token>`, and
  `--token-file` is required. A shape wraps the line; it never rewrites it.

## The secret and the wire (J-7, J-8)

- The token is read from `--token-file` at every connection: never an argument, never the environment, never
  printed, never in the state, in an error's text or in an output line. Off Windows a token file that others
  can read (mode & 0o077) is exit 2 with the reason; on Windows that is not checked.
- https is verified against the system's authorities, or against `--ca FILE` alone. No switch and no variable
  of the environment turns verification off. The environment's proxies are not used; a redirect is not
  followed. A URL with user information is a usage error.
- Plain http is taken only to a loopback address (127.0.0.0/8, ::1) unless `--plain` is given; `plain` is true
  for every http destination and the status then says "plain: not encrypted". Connect within 10 s, an answer
  within 30 s.

## The state (J-9)

After every batch, every failure and at least once a beat (`--beat S`, 60 s unless given), the forwarder writes
its state whole - written beside, then renamed over - to `~/.raqib/forward/<name>.json` (ASCII JSON, keys
sorted). A name is `[a-z0-9-]{1,32}`; a second forwarder of one name is refused while the first one's pid lives
(`~/.raqib/forward/<name>.pid` holds it while it runs). The keys:

| key | type | meaning |
|---|---|---|
| `schema` | str | `raqib-forward/1` |
| `name` | str | the forwarder's name |
| `pid` | int | the forwarder's process id |
| `written` | instant | when this state was written (UTC, milliseconds, Z) |
| `destination` | object | `scheme`, `host`, `port`, `path`: no query, no user information |
| `shape` | str | `raqib` or `hec` |
| `delivery` | str | what taken means: `acknowledged` (HTTP) |
| `plain` | bool | true where the wire is plain http |
| `file` | str | the events file, absolute |
| `cursor` | object | `offset` (bytes) and `line_sha256` (of the line that ends at the offset; null at 0) |
| `from` | object | `start` (`start` or `end`) and `offset`: where the first run of the name started (J-12) |
| `beat` | number | the forwarder's beat in seconds: the status judges its silence by it |
| `sent` | count | event lines the collector took |
| `skipped` | count | lines passed that are not JSON or not an event |
| `refused` | object | `count` and `ids`, the latest 50 ids of lines refused alone |
| `restarts` | count | how many times the file was another and was read again from its start |
| `last_id` | str or null | the id of the last line taken |
| `last_ok` | instant or null | when a send was last taken |
| `behind` | count | bytes of whole lines after the cursor, not yet taken |
| `failing` | object or null | `since` (instant), `tries` (count), `error` (a word above), `status` (the HTTP status or null) |

`from` and `beat` are not in J-9's list; they are what J-12 ("the state says from which offset") and J-9's
status ("more than two beats") need (docs/review/2026-11-13-M10.3-questions.md).

## The status (J-9)

`raqib forward --status [NAME]` reads the state (every state in `~/.raqib/forward/` without NAME) and says it in
a few lines. Exit 0 where nothing fails and nothing waits longer than a beat; 1 where it is failing, or behind
(`behind` above 0 while the last taken send is more than a beat older than the state); 3 where there is no
state, it cannot be read, or it was written more than two beats ago: the forwarder is silent (CLAUDE.md rule 4).
Of several states, the worst: 3, then 1.

## On the collector's side: the one search for silence

The heartbeats are the proof of the whole path. A SOC makes one search: no heartbeat of a host for more than two
beats - the events of `kind` heartbeat, grouped by `watch.host`, the latest `time` of each host older than two
of its `watch.beat`. A host whose watch stopped, whose forwarder stopped or whose wire is cut looks the same
there, and each is an alarm.

## Not here

Syslog over udp, tcp and tls (the next task); the forwarder as a service; the local sinks; OCSF and ECS
documents built by Raqib; more than one file.
