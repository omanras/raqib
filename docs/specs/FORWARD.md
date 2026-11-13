# FORWARD - the forwarder, raqib-forward/1 (ADR-0011 Amendments J to N)

`raqib forward` is a process of its own (J-1). It reads one events file - the watch's
`~/.raqib/host/events.jsonl`, as docs/specs/EVENT.md "For a reader of the file" says a reader may - and sends
every whole line to one destination: an HTTP collector, or a syslog collector over `syslog+udp://`,
`syslog+tcp://` or `syslog+tls://` (J-6; "Syslog" below). Syslog is another way to send, not another machine:
the cursor, the lines in question, the state and the status are one for both. The watch does
not know it runs: raqib/host.py, raqib/eventlog.py, raqib/event.py and raqib/hooks/ import nothing of
raqib/forward.py, and no result, report or finding of a watch depends on a forwarder. The standard library only.

    raqib forward [FILE] --to URL --name NAME [--shape raqib|hec] [--token-file FILE] [--ca FILE] [--plain]
                  [--beat S] [--from start|end] [--batch N] [--once]
    raqib forward [FILE] --to syslog+udp|syslog+tcp|syslog+tls://HOST[:PORT] --name NAME [--facility N]
                  [--framing octet|newline] [--ca FILE] [--plain] [--beat S] [--from start|end] [--batch N]
                  [--once]
    raqib forward --status [NAME]

## What it sends, and what acknowledged means

- The file is the buffer (J-3). It is opened for reading only: never written, moved or locked. The forwarder
  keeps nothing of it but the lines in flight.
- The cursor is a byte offset at the end of the last whole line passed, kept with the sha256 of that line's
  bytes (its newline included). A line is passed when the collector took it; when it was skipped (not an
  event); when it was refused locally (longer than one request may be); or when the collector refused it alone
  twice with a take of a later line between the two refusals (L-1, M-2, below). A line refused alone and not
  yet asked again after a later take is not passed: it is in question, and the cursor stays before it. The
  cursor never passes any other line, and a kill at any point leaves only a state written whole: a restart
  sends again from the cursor, it never skips. `sent` counts a line when the cursor passes it (N-5): a line
  taken after lines in question is counted when they are settled and the cursor passes it, so a restart that
  sends it again does not count it twice.
- `acknowledged` is HTTP's delivery word (J-3), and the state says it in `delivery`: a batch is taken when the
  answer is a 2xx and, in the hec shape, the answer's body is JSON whose `code` is 0. A 200 with another code is
  not taken. Taken is the collector's word: a collector that answers 2xx and drops the lines loses them.
- Over syslog there is no answer (J-3, J-6), and the delivery word says what took means there: `written` over
  tcp and tls - a batch is taken when its bytes were handed to the system with no error (sendall returned):
  not that the collector received them, read them or kept them; a collector that closes its end while the
  bytes are on their way loses them unseen - and `sent` over udp - a batch is taken when each of its
  datagrams was sent with no error: nothing is known of their arrival. The cursor rules are the same:
  nothing moves before the transport took the batch, a failed send moves nothing and is tried again, and a
  restart sends again from the cursor.
- At least once (J-3, J-11): one request at a time, the file's order, at most 100 lines and at most 512 KiB to
  a request (`--batch N` lowers the count, 1 to 100). A batch that failed is sent again, and nothing after it
  is sent before it; it may be sent again smaller (N-1): a send that was `late` - its request not sent, or no
  whole answer, within its bound - makes the next batch half as many lines, down to one; a send taken doubles
  it, up to `--batch`. A collector that takes 50 lines within the bound and not 100 is sent 100, 50, 100, 50:
  never the same batch at the size it was late at.
- The order at the collector is the file's order, except for three things (M-2), and `n` orders the lines
  within a run (EVENT.md): a line in question that is taken when it is asked again arrives after the later line
  that was taken first; a send whose answer came too late, or was lost, may have been taken and is sent again
  with the lines after it; a send abandoned (Stop, a bound) may still reach the collector after the lines sent
  again.
- A line whose piece of the body alone is over 512 KiB is refused locally: counted and passed - never cut
  (K-2). A line longer than 512 KiB in the file is never read whole (M-3): its end is found and its sha256 made
  piece by piece; its id is not read, and it is named by its offset (in `ids`, `offset N`, N its first byte).
  A line of at most 512 KiB whose envelope is over it (hec) is read and named by its id.
- A line that is not JSON or not an event (`event.check`) is skipped and counted (`skipped`), never sent; a last
  line with no newline is not whole and waits for its newline (J-5, EVENT.md). More than 512 KiB after the
  last newline is not read into memory: it is looked through in pieces for its newline, and until one comes
  the forwarder is failing with the word `file` (L-8).
- The file's identity (J-5, N-3): the state keeps `head`, the sha256 of the file's first bytes and how many -
  at most 4096, and of them, once the cursor has passed any, only what it has passed (at the cursor 0: what the
  file holds). Where the file's first bytes are not the head, the file is shorter than the cursor, or the line
  that ends at the cursor is not the line whose sha256 was kept, the file is another: it is read again from its
  start, counted in `restarts` and said - the cursor at 0 included. The collector then gets lines twice;
  `watch.host` and `id` tell them apart. A head hashed shorter is hashed again, longer, as the cursor passes more
  of the first 4096 bytes (at 0: as the file grows); a head that still reaches past the cursor (hashed at 0, the
  cursor moved since) proves nothing either way, and the cursor's line decides. The check is the head, the
  length and the last line passed, not every byte before the cursor (K-2).
- What the run holds after the cursor (N-3) - the reach, the count in question, the line taken after them
  (the proof) and how far a tail was looked through - is held to the file too: where the file is shorter than
  any of them, or the line that ends at the reach is not what it was (its sha256 is kept beside the reach), it
  is given up, back to the cursor, and said; the lines after the cursor are then asked as new ones, and none of
  them is counted refused before it has been refused alone twice with a later take between. No restart is
  counted: the cursor's own line is the one passed. A file that only grew gives nothing up.
- Where a first run starts (J-12): at the file's start (Raqib sends everything it judged). `--from end` starts at
  the end of the file's last whole line, and `from` says from which offset. A later run of the same name goes on
  from its cursor; a name is one file, one destination and one shape (J-13), and another of these is a usage
  error.

## A refused line, a refused token, a failed send (J-4, L-1, J-10)

- A 4xx answer other than 401, 403, 408 and 429 to a batch: its lines are sent again one by one. A line refused
  alone is in question. A try sends at most 100 lines alone (M-1); what it has asked is not asked again while
  the forwarder runs: the run holds the lines in question as a reach and a count (how far it has asked lines
  alone, and how many wait there), never one by one. The next try goes on from the reach, a batch first, and
  also asks the first line in question again, alone, once a try: a collector put right is seen at once, the
  line is then taken, not refused, and so is the line in question after it while each is taken. The take of
  that earlier line is never the proof of a later one: the line after it that is refused stays in question. A
  collector that refuses one kind of line (a heartbeat a minute through a quiet night) does not stop the line
  of another kind after them.
- A try makes at most 201 requests: at most 100 lines alone; before each of them at most one batch that was
  refused (a refused batch of two lines or more is always followed by its first line alone, and no batch is
  sent once 100 lines have gone alone); and one batch that was taken or failed, which ends the try or begins
  the settling, which sends lines alone only. A try moved (N-2) where it took a line, passed a line or carried
  the reach further: the next try follows with no wait, and so does `--once`, until a try moves nothing. A
  file of a refused kind is therefore drained at the collector's own pace, two requests a refused line, not
  at a hundred a minute.
- When a later line is taken, each line in question before it is asked alone once more (M-2): refused again,
  it is counted in `refused`, its id kept in `ids` (the latest 50), and passed; taken now, it is taken. A
  refusal that would not come twice (a node behind a balancer that answers 404, a 400 of a moment) does not
  pass a line. The settling is bounded as a try is: at most 100 lines alone in a try, the next goes on.
- While the lines in question have no taken line after them - the file has no more whole lines, or the try has
  sent 100 lines alone - the cursor stays before the first of them, the forwarder is failing with the word
  `refusing` and the collector's status, and it tries again as below. `refusing` stays said for as long as
  lines are in question - a take while they wait does not end it, the settling included - and ends when none
  is. A collector that refuses everything (a wrong path, a missing channel) moves nothing and empties nothing
  into `refused`; its first tries carry the reach to the file's end (no wait between them), then each try asks
  the first line in question once and waits. A restarted forwarder starts at its cursor and asks the lines in
  question again from there.
- 401 and 403 are the token's: nothing moves, `failing` says `token`, and the token file is read again at every
  try (a file corrected between two tries is used at the next). A token file that fails its checks while the
  forwarder runs (others can read it, it is emptied, it cannot be read) is a failed try, `token-file`: nothing
  moves, the state says so, and it is read again at the next try; at the start it is a usage error (L-3).
- Every other failure is a failed send: nothing moves, and it is tried again after 1, 2, 4, 8, 16, 32 and then
  60 s, for as long as it runs. A collector that is down never ends it. It ends at Stop (the batch in flight is
  finished or abandoned unmoved, the state written) or at a usage error. A try that moved and then failed is
  followed by the next with no wait (N-2); the waits are for the tries that moved nothing. `--once` sends what
  the file holds - try after try while each moves, no second try of one that moved nothing - and ends: 0 every
  event line taken, 1 not all (a failed send, lines in question or a refused line), 2 usage.
- Whatever ends the run after its start - Stop, a usage error, an error the forwarder did not foresee - the
  state is written first (L-3). An unforeseen error ends the run with `failing` saying `unforeseen` and the
  output naming only the error's class: never a traceback's text. The start is the pid file taken, the state
  read and the first state written: a usage error before that (a second forwarder of the name, a damaged
  state) writes no state, so that the state that is there stays as it was.

The forwarder's own words for a failure (`failing.error`); an error is one of them and a status number, never
the collector's body:

| word | the failure |
|---|---|
| `connect` | no connection to the collector within 10 s of the send's start (name resolution included; over udp, a name that does not resolve) |
| `tls` | the TLS handshake or the certificate failed |
| `no-answer` | the connection ended with no answer |
| `late` | the TLS handshake not ended within 10 s of the send's start, the request (over syslog: the batch) not sent within 30 s of its start, or no whole answer within 30 s of the request's last byte |
| `redirect` | a 3xx answer (a redirect is never followed) |
| `busy` | 408 or 429 |
| `server` | a 5xx answer |
| `answer` | an answer that does not say the batch was taken (in the hec shape: a 2xx whose code is not 0) |
| `refusing` | the lines sent alone were refused (a 4xx) and no later line was taken: they are in question |
| `token` | 401 or 403 |
| `token-file` | the token file cannot be read, or fails its checks, at a try |
| `write` | syslog: the system did not take the batch's bytes or a datagram (the connection ended, no route) |
| `file` | the events file cannot be read, or more than 512 KiB follow its last newline |
| `stuck` | four sends abandoned have not ended (a name that never resolves, a connect that never returns): no send starts until one ends |
| `unforeseen` | an error the forwarder did not foresee ended the run (the state written first) |

## One send, bounded (L-4, M-4, M-5)

A send runs on a thread of its own, and the forwarder waits for it in slices of 0.25 s on a clock that does
not step:

- connecting - name resolution and the TLS handshake included - within 10 s of the send's start (`connect`
  where no connection came, `late` where the handshake did not end);
- sending the request: within 30 s of its start (`late`; the next batch is then half as many lines);
- the whole answer within 30 s from the request's last byte - not each read: a collector that answers one byte
  at a time is `late` at 30 s (the next batch is then half as many lines too);
- at each slice the forwarder looks for Stop and writes its state where a beat has passed since the last.
  Stop is honoured within 2 s during a send (it is abandoned unmoved), between the lines of a refused batch,
  in a walk over lines that are not events, in a walk through one long line or tail - looking for its end,
  hashing it, looking back for its start - at every piece of 64 KiB (N-8), and in a wait. `behind` looks back
  at most 1 MiB from the file's end, then reads once forward (at most 512 KiB) from the furthest line end the
  run knows: a state write never walks a long tail, and past that window `behind` is a lower bound.

A send abandoned (Stop, or a bound passed) has its sockets shut down - which ends a blocked connect, send or
read - and left to its own thread, which alone closes them: no descriptor is closed under a thread that may
still use it, and each socket call has its own timeout besides. Name resolution is the system's (getaddrinfo)
and cannot be bounded from Python: where the system's resolver does not return, the try is abandoned at 10 s
while the resolver's own thread waits for it, holding that send's body (at most 512 KiB) and headers. At most
four sends abandoned and not yet ended are out (M-5): while four are, no send starts and the forwarder is
failing with the word `stuck`; when one ends, sending goes on.

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

## Syslog (J-6)

- The forms: `syslog+udp://HOST[:PORT]` (514 unless written), `syslog+tcp://HOST[:PORT]` (514 unless
  written: RFC 6587 names no port, and 514 is what collectors listen on), `syslog+tls://HOST[:PORT]` (6514,
  RFC 5425, unless written). A syslog destination is a host and a port only: a path, a query or a fragment is
  a usage error. The state's `destination` has the path "" (empty).
- One line is one message, RFC 5424: `<PRI>1 TIMESTAMP HOSTNAME raqib - MSGID - MSG`. PRI is the facility
  times 8 plus the severity: the facility 13 (log audit) unless `--facility N` (0 to 23); the severity the
  event's - high 2, medium 4, low 5, a hole 4, none and info 6 (2 critical, 4 warning, 5 notice, 6
  informational; a severity the event contract does not have would be 4, never calm). VERSION 1; TIMESTAMP the
  event's `time` as written (UTC, milliseconds, Z); HOSTNAME the event's `watch.host`; APP-NAME `raqib`;
  PROCID `-`; MSGID the event's `kind`; STRUCTURED-DATA `-`; the MSG the line as written, without its newline
  (the raqib shape: the event is never rewritten). Where the event's `time`, `watch.host` or `kind` is not
  what RFC 5424 takes in that field (a host name with a space, a character outside printable US-ASCII, longer
  than 255, a kind longer than 32), that field is `-`; the event in the MSG still says it.
- Framing: over tcp and tls, octet counting (RFC 6587): each message is sent as its length in bytes, a space,
  then the message (`<length> <message>`). `--framing newline` sends each message followed by a newline
  instead, for a collector that wants lines (a line holds no newline: it is one line of the file). Over udp
  each message is one datagram, never framed; `--framing` with udp is a usage error.
- A batch is the same batch as over HTTP (at most `--batch` lines and 512 KiB, the file's order): over tcp and
  tls its messages are written on one connection, opened for the batch and closed after it (without a TLS
  close_notify: octet counting tells a collector where each message ends); over udp they are sent one datagram
  each, in order. One send is bounded as an HTTP one is: connecting - name resolution and the TLS handshake
  included - within 10 s of its start, writing the batch within 30 s; a send `late` in its writing halves the
  next batch, down to one line.
- A line whose message is longer than a datagram may be - over 65000 bytes, over udp - is refused locally as a
  line longer than one request is (K-2, M-3): never sent and never cut, counted in `refused`, named by its id
  in `ids`, passed, and said; the line after it is sent. Over tcp and tls such a line is sent whole; a line
  over 512 KiB is refused locally on every transport.
- Syslog has no refusal: a syslog collector answers nothing, so no line is ever in question, `refusing`,
  `token`, `redirect`, `busy`, `server`, `answer` and `no-answer` never arise, and `in_question` stays 0. A
  failed syslog send is `connect` (no connection, or name resolution failed), `tls` (the handshake or the
  certificate), `late` or `write` (the system did not take the bytes or a datagram: the connection ended, no
  route); `failing.status` is null.
- No token: syslog carries no Authorization, and `--token-file` with a syslog destination is a usage error
  that says so (the file is not read). `--shape hec` is HTTP's and a usage error over syslog; `--facility` and
  `--framing` are syslog's and a usage error with an http:// or https:// destination.
- The wire: `syslog+tls://` is verified by the same TLS context as https (below): the certificate and the host
  name, by the system's authorities or `--ca FILE`; nothing turns it off, and it needs no `--plain`.
  `syslog+udp://` and `syslog+tcp://` are plain: taken only to a loopback address unless `--plain` is given,
  and then the state's `plain` and every status say "plain: not encrypted" (said for loopback too).

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

- a URL that holds a control character anywhere (a tab or a newline would be dropped from it unsaid), a port 0,
  or a path or query that is not printable ASCII or holds a space (write a space as `%20`);
- a host that is no valid name or address (a name of ASCII letters, digits and inner hyphens; a name in another
  script is written in its `xn--` form);
- a `--beat` that is not a finite number of at least 1 (s);
- a state that is not what the forwarder writes - not JSON, not ASCII, JSON nested past what the reader takes,
  empty, another schema, a key missing (`head` and `in_question` may be missing: a state written before them),
  or a key the checks find of another type or value: the name, the pid, `written`, the destination, the
  shape, the delivery word, `plain`, `file`, a cursor of whole bytes with a sha256 or null (and not null above
  0), `from`, a beat above 0, the counts, `refused` with texts in `ids`, `last_id`, `last_ok`, `failing` (an
  object, with a `failing.error` that is a text and one of the words above, a status or null), `head` (a
  length of at most 4096 and a sha256) and `in_question` (a count, an instant or null). Whatever a JSON value
  holds, it is said in these words, never a traceback (N-6). It is never taken for a first run: `--from end`
  must not skip a file because its state was damaged. Move it away to start the name again;
- a second forwarder of one name while the first one's pid lives, and a pid file that is empty or cannot be
  read (whether a forwarder runs cannot be told, so the name is refused, never taken);
- an error of the system while the name is taken - the directory `~/.raqib/forward/` or the pid file cannot be
  made (M-6): exit 2 with the system's reason, never a traceback.

While it runs (M-7, M-8, N-4): at each state write the forwarder reads the pid file of its name. Gone, or
holding a pid no process has: it is written again with the forwarder's pid, and said. Unreadable at that write:
it is read again at the next, and the run goes on. Holding the pid of another process that lives (or whose life
cannot be told): the forwarder ends with exit 1 - not a usage error - the reason said once, writes nothing over
the state and leaves the pid file to the forwarder that took the name. Each read of the file inside a try makes
the same checks as each pass (the head, the length, the last line passed, and what the run holds after the
cursor): where the file was replaced or changed after the cursor during the try, the try ends, and the next
pass reads it again from its start and counts a restart, or gives up what it held after the cursor.

## The state (J-9)

After every batch, every failure, at least once a beat (`--beat S`, 60 s unless given) whatever it is doing -
waiting, in a send, in a try of many lines, in a walk over lines that are not events (M-4) - and before
whatever ends the run, the forwarder writes its state whole - written beside, flushed to the disk, then renamed over - to
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
| `destination` | object | `scheme` (`http`, `https`, `syslog+udp`, `syslog+tcp`, `syslog+tls`), `host`, `port`, `path` (over syslog ""): no query, no user information |
| `shape` | str | `raqib` or `hec` (over syslog always `raqib`) |
| `delivery` | str | what taken means: `acknowledged` (HTTP), `written` (syslog over tcp and tls), `sent` (syslog over udp) |
| `plain` | bool | true where the wire is plain: http, syslog over udp or tcp |
| `file` | str | the events file, absolute |
| `cursor` | object | `offset` (bytes) and `line_sha256` (of the line that ends at the offset; null at 0) |
| `from` | object | `start` (`start` or `end`) and `offset`: where the first run of the name started (J-12) |
| `beat` | number | the forwarder's beat in seconds: the status judges its silence by it |
| `sent` | count | event lines the collector took, counted when the cursor passes them (N-5) |
| `skipped` | count | lines passed that are not JSON or not an event |
| `refused` | object | `count` and `ids`, the latest 50 ids of lines refused and passed (alone twice, a later line taken between; or locally; `offset N` where the id was not read); a line in question is not counted |
| `restarts` | count | how many times the file was another and was read again from its start |
| `last_id` | str or null | the id of the last line taken |
| `last_ok` | instant or null | when a send was last taken |
| `behind` | count | bytes of whole lines after the cursor, not yet passed (lines in question among them); where the file ends in a tail longer than 1 MiB with no newline, a lower bound (N-8) |
| `failing` | object or null | `since` (instant), `tries` (count), `error` (a word above), `status` (the HTTP status or null); a restarted forwarder carries the `failing` its state held until its first try has an answer (M-6), or until it finds nothing waiting; `refusing` while any line is in question (N-2) |
| `head` | object or null | `length` (at most 4096) and `sha256` of the file's first bytes (N-3); null before the first look; a state without it is read as one written before it |
| `in_question` | object | `count`, the lines in question now, and `since`, when the first of them was refused alone in this run (null where none is; N-5); a state without it is read as none in question |

`from` and `beat` are not in J-9's list; they are what J-12 ("the state says from which offset") and J-9's
status ("more than two beats") need (K-2).

## The status (J-9, L-2)

`raqib forward --status [NAME]` reads the state (every state in `~/.raqib/forward/` without NAME) and says it in
a few lines; the first line of each says the count of lines refused. Its rule: exit 0 only where nothing is
failing and no whole line has waited longer than a beat; 1 where it is failing (`refusing` too) or behind; 3
where there is no state, it cannot be read, or it was written more than two beats ago or in the future (the
forwarder is silent). Behind is `behind` above 0 while the last taken send is more than a beat older than the
state; a forwarder whose sends are taken while the file grows faster than a beat's worth is 0 (K-2). A state
with `behind` above 0 and `last_ok` null - no send of this name was ever taken - is BEHIND (1) at once, and the
status says so. A state written in the future of the reader's clock has an age that cannot be told: it is not
fresh. Lines in question are whole lines that wait (N-5): where `in_question` holds a count and its `since` is
more than a beat older than the state, the status is 1 (BEHIND), the settling included, whatever `last_ok`
says. A state that is not what the forwarder writes (the list above, "What is refused at the start") is
UNREADABLE (3), never read as calm (M-6, N-6). Of several states, the worst: 3, then 1.

What `--status` says in each state of the machine (a test builds each row's state and holds it to the code):

| the forwarder's state | exit | word |
|---|---|---|
| `nothing waits` - the last send taken, no whole line after the cursor | 0 | `OK` |
| `growing` - whole lines after the cursor, the last send taken within a beat (K-2) | 0 | `OK` |
| `behind` - whole lines after the cursor, the last send taken more than a beat before the state | 1 | `BEHIND` |
| `never taken` - whole lines after the cursor, no send of this name ever taken | 1 | `BEHIND` |
| `in question` - lines in question for more than a beat and no `failing` (inside a long try) | 1 | `BEHIND` |
| `refusing` - lines in question and no later line taken: the cursor before them | 1 | `FAILING` |
| `settling` - a later line taken, the lines in question asked again: `refusing` until none is | 1 | `FAILING` |
| `failed send` - `connect`, `tls`, `late`, `busy`, `server`, `token` and the other words above | 1 | `FAILING` |
| `stuck` - four abandoned sends not ended | 1 | `FAILING` |
| `silent` - the state written more than two beats ago | 3 | `SILENT` |
| `future` - the state written in the future of the reader's clock | 3 | `SILENT` |
| `no state` - none written for the name | 3 | `SILENT` |
| `damaged` - a state the forwarder does not write | 3 | `UNREADABLE` |

## What a writer of its files can make it do (N-9)

The forwarder reads three files it does not own alone; where it runs as the watched account (until it runs as a
service), that account writes all three (docs/THREAT_MODEL.md).

- A writer of the events file can have any well-formed event sent (the forwarder checks the shape, not the
  truth); with lines of a kind the collector refuses, cost two requests a line and fill `ids` with their ids
  (the latest 50); with a tail of no newline, hold the forwarder `file` (it is looked through in pieces, never
  read whole); with a replacement, a restart (the head, the length or the cursor's line changed: the collector
  gets lines twice) or a give-up of what the run held after the cursor (asked again). A change to bytes after
  the head and before the cursor's line is not seen (K-2).
- A writer of the state can set the cursor a restarted forwarder starts from: a forged offset with the sha256
  of a later line (and a matching head) skips the lines between with no restart counted; an offset above 0
  with no hash, or anything the checks above refuse, is a damaged state (exit 2, never a first run). A fresh
  `written` keeps `--status` at 0 for a forwarder that is not there.
- A writer of the pid file can keep the name from starting (a live pid in it), and can end a running forwarder
  (exit 1) by writing the pid of another live process in it. Removing it, or writing a pid no process has,
  only has it written again at the next state write (said); making it unreadable for a moment delays nothing.

The answers are the collector's search for silence (below), judged by the collector's own clock, and a
forwarder under another account (the service, later).

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

The forwarder as a service, under an account of its own; the local sinks; OCSF and ECS documents built by
Raqib; more than one file; a syslog connection kept open across batches; RFC 5424 STRUCTURED-DATA.
