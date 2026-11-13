# FORWARD - the forwarder, raqib-forward/1 (ADR-0011 Amendments J, K and L)

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
  keeps nothing of it but the lines in flight.
- The cursor is a byte offset at the end of the last whole line passed, kept with the sha256 of that line's
  bytes (its newline included). A line is passed when the collector took it; when it was skipped (not an
  event); when it was refused locally (longer than one request may be); or when the collector refused it alone
  and then took a later line of the file (L-1, below). A line refused alone with no taken line after it is
  not passed: it is in question, and the cursor stays before it.
- `acknowledged` is HTTP's delivery word (J-3), and the state says it in `delivery`: a batch is taken when the
  answer is a 2xx and, in the hec shape, the answer's body is JSON whose `code` is 0. A 200 with another code is
  not taken. Taken is the collector's word: a collector that answers 2xx and drops the lines loses them.
- At least once, in order (J-3, J-11): one request at a time, the file's order, at most 100 lines and at most
  512 KiB to a request (`--batch N` lowers the count, 1 to 100). A batch that failed is sent again whole, and
  nothing after it is sent before it. A line whose piece of the body alone is over 512 KiB is refused locally:
  counted, its id kept, passed - never cut (K-2); such a line is read once, whole, to be named.
- A line that is not JSON or not an event (`event.check`) is skipped and counted (`skipped`), never sent; a last
  line with no newline is not whole and waits for its newline (J-5, EVENT.md). More than 512 KiB after the
  last newline is not read into memory: it is looked through in pieces for its newline, and until one comes
  the forwarder is failing with the word `file` (L-8).
- The file's identity (J-5): where the file is shorter than the cursor, or the line that ends at the cursor is
  not the line whose sha256 was kept, the file is another: it is read again from its start, counted in
  `restarts` and said. The collector then gets lines twice; `watch.host` and `id` tell them apart. The check is
  the length and the last line passed, not every byte before the cursor (K-2).
- Where a first run starts (J-12): at the file's start (Raqib sends everything it judged). `--from end` starts at
  the end of the file's last whole line, and `from` says from which offset. A later run of the same name goes on
  from its cursor; a name is one file, one destination and one shape (J-13), and another of these is a usage
  error.

## A refused line, a refused token, a failed send (J-4, L-1, J-10)

- A 4xx answer other than 401, 403, 408 and 429 to a batch: its lines are sent again one by one. A line refused
  alone is in question. It is counted in `refused`, its `id` kept in `ids` (the latest 50), and passed only when
  a later line of the file has been taken by the same collector - one bad line does not stop the lines after
  it, and a collector that refuses everything (a wrong path, a missing channel) does not empty the file into
  `refused`. Past the batch, the lines after those in question are sent (as a batch, then one by one where that
  batch is refused) until one is taken. While the lines in question have no taken line after them - the file
  has no more, or 100 lines are in question in one try - the cursor stays before the first of them, the
  forwarder is failing with the word `refusing` and the collector's status, and it tries again as below. A
  restarted forwarder starts at its cursor and sends the lines in question again. A taken line is never sent
  before a line that is neither taken nor in question before it.
- 401 and 403 are the token's: nothing moves, `failing` says `token`, and the token file is read again at every
  try (a file corrected between two tries is used at the next). A token file that fails its checks while the
  forwarder runs (others can read it, it is emptied, it cannot be read) is a failed try, `token-file`: nothing
  moves, the state says so, and it is read again at the next try; at the start it is a usage error (L-3).
- Every other failure is a failed send: nothing moves, and it is tried again after 1, 2, 4, 8, 16, 32 and then
  60 s, for as long as it runs. A collector that is down never ends it. It ends at Stop (the batch in flight is
  finished or abandoned unmoved, the state written) or at a usage error. `--once` sends what the file holds
  once, with no second try, and ends: 0 every event line taken, 1 not all (a failed send, lines in question or
  a refused line), 2 usage.
- Whatever ends the run after its start - Stop, a usage error, an error the forwarder did not foresee - the
  state is written first (L-3). An unforeseen error ends the run with `failing` saying `unforeseen` and the
  output naming only the error's class: never a traceback's text. The start is the pid file taken, the state
  read and the first state written: a usage error before that (a second forwarder of the name, a damaged
  state) writes no state, so that the state that is there stays as it was.

The forwarder's own words for a failure (`failing.error`); an error is one of them and a status number, never
the collector's body:

| word | the failure |
|---|---|
| `connect` | no connection to the collector (within 10 s) |
| `tls` | the TLS handshake or the certificate failed |
| `no-answer` | the connection ended with no answer |
| `late` | no handshake within 10 s of connecting, or no whole answer within 30 s of the request's last byte |
| `redirect` | a 3xx answer (a redirect is never followed) |
| `busy` | 408 or 429 |
| `server` | a 5xx answer |
| `answer` | an answer that does not say the batch was taken (in the hec shape: a 2xx whose code is not 0) |
| `refusing` | the lines sent alone were refused (a 4xx) and no later line was taken: they are in question |
| `token` | 401 or 403 |
| `token-file` | the token file cannot be read, or fails its checks, at a try |
| `file` | the events file cannot be read, or more than 512 KiB follow its last newline |
| `unforeseen` | an error the forwarder did not foresee ended the run (the state written first) |

## One send, bounded (L-4)

A send runs on a thread of its own, and the forwarder waits for it on a clock that does not step:

- connecting, the TLS handshake included, within 10 s (`connect` where no connection came, `late` where the
  handshake did not end);
- the whole answer within 30 s from the request's last byte - not each read: a collector that answers one byte
  at a time is `late` at 30 s;
- Stop is honoured within 2 s during a send (it is abandoned unmoved: its sockets are shut down and closed),
  between the lines of a refused batch and in a wait.

Name resolution is the system's (getaddrinfo) and cannot be bounded from Python: it runs within the 10 s of
connecting, and where the system's resolver does not return, the try is abandoned at 10 s while the
resolver's own thread waits for it. A forwarder held in any way for more than two beats writes no state, and
`--status` then says SILENT (exit 3).

The waits (1, 2, 4 ... 60 s, the poll for new lines) and "at least once a beat" run on the monotonic clock: a
wall clock set back or ahead delays nothing and hurries nothing. Only the state's times (`written`, `last_ok`,
`failing.since`) are the wall's.

## The shapes (J-6)

- `--shape raqib` (the default): the body is the lines as the file holds them, byte for byte, each with its
  newline; `Content-Type: application/x-ndjson`. With `--token-file`, `Authorization: Bearer <token>`.
- `--shape hec`: one envelope per line, in the shape Splunk's HTTP event collector takes, one after another,
  each on a line of its own: `{"time": the event's time as seconds since the epoch with its milliseconds,
  "host": the event's watch.host, "source": "raqib", "sourcetype": "raqib:event", "event": the event}`. The
  event's bytes are put in the envelope unchanged. The header is `Authorization: Splunk <token>`, and
  `--token-file` is required. A shape wraps the line; it never rewrites it.

## The secret and the wire (J-7, J-8, L-5)

- The token is read from `--token-file` at every try: never an argument, never the environment, never
  printed, never in the state, in an error's text or in an output line. Off Windows a token file that others
  can read (mode & 0o077) is exit 2 with the reason at the start, and a failed try while it runs; on Windows
  that is not checked.
- https is verified - the certificate and the host name - against the system's authorities, or against
  `--ca FILE` alone. No switch turns verification off. Without `--ca`, "the system's authorities" are the ones
  the forwarder's own environment names: OpenSSL reads SSL_CERT_FILE and SSL_CERT_DIR, and where they are set
  they replace the system's default set (whoever sets the forwarder's environment chooses whom it trusts).
- The forwarder never writes TLS secrets: SSLKEYLOGFILE is not honoured (the TLS context is built without
  it), so no key log can decrypt the Authorization header from a capture of the wire.
- The environment's proxies are not used; a redirect is not followed. A URL with user information is a usage
  error. A query is sent and never stored or printed by the forwarder (K-2), but the URL is an argument, and
  arguments are on the process list: a credential must never be put in the URL's query.
- Plain http is taken only to a loopback address (127.0.0.0/8, ::1) unless `--plain` is given; `plain` is true
  for every http destination and the status then says "plain: not encrypted".

## What is refused at the start (L-6, L-7)

Each of these is exit 2 with its reason, before anything is sent - never a failed send that is tried again:

- a URL whose path or query is not printable ASCII or holds a space (write a space as `%20`);
- a host that is no valid name or address (a name of ASCII letters, digits and inner hyphens; a name in another
  script is written in its `xn--` form);
- a `--beat` that is not a finite number of at least 1 (s);
- a state that is not one of this schema - not JSON, empty, another schema, or a key of the wrong type. It is
  never taken for a first run: `--from end` must not skip a file because its state was damaged. Move it away
  to start the name again;
- a second forwarder of one name while the first one's pid lives, and a pid file that is empty or cannot be
  read (whether a forwarder runs cannot be told, so the name is refused, never taken).

## The state (J-9)

After every batch, every failure, at least once a beat (`--beat S`, 60 s unless given) and before whatever ends
the run, the forwarder writes its state whole - written beside, flushed to the disk, then renamed over - to
`~/.raqib/forward/<name>.json` (ASCII JSON, keys sorted). A name is `[a-z0-9-]{1,32}`; a second forwarder of
one name is refused while the first one's pid lives: `~/.raqib/forward/<name>.pid` holds the pid while it
runs, and it appears with its pid already in it (written beside, then linked into place, or renamed on
Windows, where a rename never replaces a file that is there). The keys:

| key | type | meaning |
|---|---|---|
| `schema` | str | `raqib-forward/1` |
| `name` | str | the forwarder's name |
| `pid` | int | the forwarder's process id |
| `written` | instant | when this state was written (UTC, milliseconds, Z; the wall's clock) |
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
| `refused` | object | `count` and `ids`, the latest 50 ids of lines refused and passed (alone, with a later line taken; or locally); a line in question is not counted |
| `restarts` | count | how many times the file was another and was read again from its start |
| `last_id` | str or null | the id of the last line taken |
| `last_ok` | instant or null | when a send was last taken |
| `behind` | count | bytes of whole lines after the cursor, not yet passed (lines in question among them) |
| `failing` | object or null | `since` (instant), `tries` (count), `error` (a word above), `status` (the HTTP status or null) |

`from` and `beat` are not in J-9's list; they are what J-12 ("the state says from which offset") and J-9's
status ("more than two beats") need (K-2).

## The status (J-9, L-2)

`raqib forward --status [NAME]` reads the state (every state in `~/.raqib/forward/` without NAME) and says it in
a few lines; the first line of each says the count of lines refused. Its rule: exit 0 only where nothing is
failing and no whole line has waited longer than a beat; 1 where it is failing (`refusing` too) or behind; 3
where there is no state, it cannot be read, or it was written more than two beats ago or in the future (the
forwarder is silent). Behind is `behind` above 0 while the last taken send is more than a beat older than the
state; a forwarder whose sends are taken while the file grows faster than a beat's worth is 0 (K-2). A state
written in the future of the reader's clock has an age that cannot be told: it is not fresh. Of several
states, the worst: 3, then 1.

## On the collector's side: the one search for silence

The heartbeats are the proof of the whole path. A SOC makes one search: no heartbeat of a host for more than two
beats - the events of `kind` heartbeat, grouped by `watch.host`, judged by the collector's own clock of arrival
(its index time), never by the event's `time`: the event's time is the host's clock, and a host clock set ahead
would hide silence for the length of its skew (EVENT.md says the same of any reader). A host whose latest
heartbeat arrived more than two of its `watch.beat` ago is silent. A host whose watch stopped, whose forwarder
stopped or whose wire is cut looks the same there, and each is an alarm. Where the forwarder runs as the
watched account, that account can write the forwarder's cursor, state and pid file (docs/THREAT_MODEL.md); this
search is the answer the collector holds.

## Not here

Syslog over udp, tcp and tls (the next task); the forwarder as a service, under an account of its own; the
local sinks; OCSF and ECS documents built by Raqib; more than one file.
