"""Raqib proxy capture source (M5.2, ADR-0003 and its Amendment A).

`python -m raqib proxy --listen 127.0.0.1:PORT --upstream URL --log PATH
[--cwd DIR]` is a local reverse proxy between an agent and its model API.
The agent's base URL points at http://127.0.0.1:PORT (that exact host: any
other Host header is refused); every request is relayed to URL (https; a
plain http URL only with --allow-plain-upstream and only to a loopback
address, 127.0.0.0/8 or ::1, for tests) and the answer is relayed back.

The proxy relays and never steers (A4):
- it listens on 127.0.0.1 only, plain HTTP;
- the upstream is HTTPS with certificate and host name verification on
  (ssl.create_default_context(), which honours SSL_CERT_FILE and
  SSL_CERT_DIR; verification is never turned off). HTTPS_PROXY is not used:
  the upstream is reached directly;
- request and response bodies are forwarded byte for byte; the headers too,
  except what relaying HTTP/1.1 requires: Host names the upstream, the
  hop-by-hop headers (Connection and the headers it names, Keep-Alive,
  Proxy-*, TE, Trailer) are not passed on, chunked framing is redone hop by
  hop (a Content-Length beside it is dropped), and an answer whose end is
  the end of the connection (no length, or chunked to an HTTP/1.0 agent)
  gets Connection: close. No other header is added (no Server, no Date);
- one upstream request per agent request: no retry, no request of its own;
- a streamed answer (chunked, text/event-stream) is passed on piece by
  piece as it arrives.

Refused, with a status of the proxy's own and a RAQIB-SILENCE line (folded
to one line per FOLD_SECONDS, with a count, ruling A-6): a Host that is not
127.0.0.1:PORT or any Origin header (403: a browser page, or a request not
meant for this port), an Upgrade request (501), a method other than GET,
POST, PUT, PATCH, DELETE, HEAD and OPTIONS (405), a target that is not a
path (400), a body that cannot be read (400/501).

What it records, from the JSON it reads but never changes:
- OpenAI chat/completions (a path ending in /chat/completions): each
  tool_calls entry of an answer (JSON or SSE deltas) is a `pre`; the
  role=tool message with its tool_call_id in a later request is its `post`;
- Anthropic messages (a path ending in /messages): each tool_use block of an
  answer is a `pre`; the tool_result block with its tool_use_id in a later
  request is its `post`.
Sessions follow the conversation (ruling A-3): a request's session id is its
conversation key, sha256 of the canonical JSON of [model, messages[0]]. A
key's first sight writes session_start (again after a session_end); an
answer with no tool call that ends the turn (finish_reason "stop",
stop_reason "end_turn") writes stop; shutdown writes session_end for every
key still open, read from the trace or seen by this run. Pairing is per key: the i-th
result with an id closes the oldest open pre with that id in the key, or,
if the key's first request holds it, goes into the key's one `history`
line (results that predate the proxy, ruling A-4), else it is a post with a
new seq (SILENCE-HALF: a result with no call). A result re-sent (every
request repeats the conversation) is not posted again; re-sent with another
output hash, it writes a RAQIB-SILENCE line (A-5). `tool` and `tool_use_id`
are printable ASCII of at most 64 and 128 characters, else "sha256:<16
hex>" and `tool_hashed: true` (A-2). Records carry hashes and
common.input_meta's extract only, and `source: "proxy"`; `cwd` is --cwd or
the proxy's own working directory. A pre is written before the bytes that
complete its call are passed on. The open pres are kept in memory: the
trace is read once at start, then only appended to (A-9).

Silence is an alarm (A3). Each of these appends one line starting with
RAQIB-SILENCE: to the trace (watch reads it as a capture failure; report as
an alarm) and to stderr:
- an upstream failure: no connection, TLS failure, a timeout, a connection
  cut mid-answer, an answer with status 5xx (relayed unchanged), an interim
  1xx other than 100 (not relayed). With no status from upstream the agent
  gets 502 (504 on a timeout);
- a recording step that failed, whatever the cause ("record failed:
  <class>"): the bytes pass all the same (A-1); a request body over
  PARSE_MAX bytes is relayed unrecorded;
- a request or a 2xx answer on a path above that cannot be read; an SSE
  `error` event; a stream that ended without its end event; an agent that
  left during the answer;
- a model request (JSON with "model" and "messages" or "tools") on another
  path, once per path per run: its tool calls are not read;
- a refused request (above).
A path is written without its query string. Of the header values only the
Content-Type and Content-Encoding of an answer that cannot be read appear,
bounded and redacted, in a RAQIB-SILENCE line. No request line is logged.
"""
from __future__ import annotations

import http.client
import http.server
import ipaddress
import json
import os
import socket
import socketserver
import ssl
import sys
import threading
import time
import urllib.parse
import zlib

from raqib.hooks import capture, common

SOURCE = "proxy"
MARKER = capture.SILENCE
OPENAI, ANTHROPIC, COUNT = "openai", "anthropic", "count"
UNKNOWN_TOOL = "?"           # the tool of a result whose call is not in the request either
SESSION_TOOL = "-"
HOP_BY_HOP = frozenset(("connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                        "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"))
RELAYED_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
CHUNK = 65536
CHUNK_SIZE_DIGITS = 16        # hex digits of a request chunk size; read in pieces of CHUNK at most
PARSE_MAX = 64 * 1024 * 1024  # bytes of one body read for records; the rest is still relayed
UPSTREAM_TIMEOUT = 600.0      # seconds of one upstream socket operation
AGENT_TIMEOUT = 600.0         # seconds of one agent socket operation (an idle keep-alive ends)
TEXT_MAX = 300                # characters of one detail in a RAQIB-SILENCE line
MODEL_KEYS = ("messages", "tools")
TOOL_MAX, ID_MAX = 64, 128    # ruling A-2
FOLD_SECONDS = 60.0           # ruling A-6: refused-request lines, one per window, with a count
INTERIM_MAX = 8               # interim 1xx answers read before the final one
STOP_REASONS = {OPENAI: ("stop",), ANTHROPIC: ("end_turn",)}


class UsageError(Exception):
    """A bad --listen or --upstream (exit 2)."""


class Unreadable(Exception):
    """A body the proxy cannot read for records; it is relayed all the same."""


# --- options --------------------------------------------------------------------------

def parse_listen(text):
    """(host, port) of --listen: 127.0.0.1:PORT only (PORT 0: any free port)."""
    host, sep, port = str(text).rpartition(":")
    if not sep or host != "127.0.0.1" or not port.isdigit() or int(port) > 65535:
        raise UsageError("--listen must be 127.0.0.1:PORT (the proxy listens on 127.0.0.1 only), not %r" % (text,))
    return host, int(port)


class Upstream:
    """The one place requests are relayed to."""

    def __init__(self, scheme, host, port, prefix):
        self.scheme, self.host, self.port, self.prefix = scheme, host, port, prefix
        default = 443 if scheme == "https" else 80
        name = "[%s]" % host if ":" in host else host
        self.netloc = name if port == default else "%s:%d" % (name, port)
        self.url = "%s://%s%s" % (scheme, self.netloc, prefix)

    def target(self, path):
        """The upstream request target for an agent's origin-form target."""
        return self.prefix + path

    def connection(self, timeout=None):
        timeout = UPSTREAM_TIMEOUT if timeout is None else timeout
        if self.scheme == "https":
            return http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=tls_context())
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout)


def tls_context():
    """Certificates and host names verified against the system's trust store
    (ADR-0003: the proxy never turns verification off)."""
    context = ssl.create_default_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    return context


def parse_upstream(text, allow_plain=False):
    """--upstream URL: https://host[:port][/path]. http:// only with
    allow_plain, and then only to a loopback address (127.0.0.1, ::1). No
    user name or password, query or fragment."""
    try:
        parts = urllib.parse.urlsplit(str(text))
        port = parts.port
        host = parts.hostname
    except ValueError as exc:
        raise UsageError("--upstream %r is not a URL (%s)" % (text, exc))
    if parts.scheme not in ("https", "http") or not host:
        raise UsageError("--upstream must be an https:// URL with a host, not %r" % (text,))
    if parts.username is not None or parts.password is not None:
        raise UsageError("--upstream must not carry a user name or password")
    if parts.query or parts.fragment or "?" in str(text) or "#" in str(text):
        raise UsageError("--upstream must not carry a query or a fragment")
    if parts.scheme == "http":
        if not allow_plain:
            raise UsageError("--upstream %s is plain http: the upstream must be https (a plain loopback upstream"
                             " needs --allow-plain-upstream, for tests)" % parts.geturl())
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise UsageError("--allow-plain-upstream allows a loopback address only (127.0.0.1, ::1), not %r" % host)
    prefix = parts.path.rstrip("/")
    return Upstream(parts.scheme, host, port or (443 if parts.scheme == "https" else 80), prefix)


def api_of(path):
    """Which API a request path speaks, from its path without the query."""
    if path.endswith("/chat/completions"):
        return OPENAI
    if path.endswith("/messages/count_tokens"):
        return COUNT  # counts tokens: no tool is called or answered there
    if path.endswith("/messages"):
        return ANTHROPIC
    return None


def safe(text, limit=TEXT_MAX):
    """One printable ASCII line, secrets redacted, at most limit characters."""
    text = common.redact(str(text)).replace("\r", " ").replace("\n", " ")
    text = text.encode("ascii", "backslashreplace").decode("ascii")
    text = "".join(c if c.isprintable() else "?" for c in text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def describe_error(exc):
    """The class of a failure and what the OS or TLS says about it; never an
    exception's own message, which can quote a header value."""
    name = type(exc).__name__
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "%s: %s (%s)" % (name, exc.reason, exc.verify_message)
    if isinstance(exc, ssl.SSLError):
        return "%s: %s" % (name, exc.reason or exc.strerror or "TLS error")
    if isinstance(exc, socket.gaierror):
        return "%s: %s" % (name, exc.strerror or "name not resolved")
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "%s: timed out" % name
    if isinstance(exc, OSError) and exc.strerror:
        return "%s: [Errno %s] %s" % (name, exc.errno, exc.strerror)
    return name


# --- reading bodies -------------------------------------------------------------------

class Decoder:
    """Content-Encoding identity, gzip or deflate, decoded for reading only,
    at most PARSE_MAX bytes; anything else is Unreadable."""

    def __init__(self, encoding, limit=PARSE_MAX):
        names = [e.strip().lower() for e in (encoding or "").split(",") if e.strip()]
        names = [e for e in names if e != "identity"]
        self.limit = limit
        self.size = 0
        self.deflate = names == ["deflate"]
        self.first = True
        if not names:
            self.zlib = None
        elif names in (["gzip"], ["x-gzip"]):
            self.zlib = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif self.deflate:
            self.zlib = zlib.decompressobj(zlib.MAX_WBITS)
        else:
            raise Unreadable("Content-Encoding %s cannot be read" % safe(encoding, 60))

    def feed(self, data):
        if self.zlib is None:
            out = bytes(data)
        else:
            try:
                out = self._inflate(data)
            except zlib.error as exc:
                raise Unreadable("the body does not decode (%s)" % type(exc).__name__)
        self.size += len(out)
        if self.size > self.limit:
            raise Unreadable("the body is larger than the %d bytes the proxy reads" % self.limit)
        return out

    def _inflate(self, data):
        room = self.limit - self.size + 1
        if self.deflate and self.first:
            self.first = False
            try:
                out = self.zlib.decompress(data, room)
            except zlib.error:  # deflate without the zlib wrapper, as some servers send it
                self.zlib = zlib.decompressobj(-zlib.MAX_WBITS)
                out = self.zlib.decompress(data, room)
        else:
            out = self.zlib.decompress(data, room)
        if self.zlib.unconsumed_tail:
            raise Unreadable("the body is larger than the %d bytes the proxy reads" % self.limit)
        return out


def decode_body(data, encoding):
    return Decoder(encoding).feed(data)


def tool_input_of(arguments):
    """The tool input of an OpenAI arguments string: its JSON value, else the
    string itself (hashed as given). Used for a call and for its copy in a
    later request alike, so both hash the same."""
    if not isinstance(arguments, str):
        return arguments
    try:
        return json.loads(arguments)
    except ValueError:
        return arguments


def bounded(value, limit):
    """(text, hashed) of a tool name or a tool call id (ruling A-2): the value
    itself when it is printable ASCII of 1..limit characters, else
    "sha256:<16 hex>" of its canonical JSON. A missing or empty value is
    (None, False)."""
    if value is None or value == "":
        return None, False
    if isinstance(value, str) and len(value) <= limit and all(" " <= c <= "~" for c in value):
        return value, False
    return "sha256:" + common.canonical_sha256(value)[:16], True


def conversation_key(body):
    """Ruling A-3: the session id of a request, sha256 of the canonical JSON
    of [model, messages[0]] (None when there is no first message)."""
    messages = body.get("messages")
    first = messages[0] if isinstance(messages, list) and messages else None
    return common.canonical_sha256([body.get("model"), first])


class Call:
    """A tool call the model asked for (a pre), name and id bounded (A-2)."""

    def __init__(self, call_id, name, tool_input):
        self.id, id_hashed = bounded(call_id, ID_MAX)
        named, name_hashed = bounded(name, TOOL_MAX)
        self.name = named if named is not None else UNKNOWN_TOOL
        self.hashed = id_hashed or name_hashed
        self.input = tool_input


class Result:
    """A tool result the agent sent back (a post), id bounded (A-2)."""

    def __init__(self, call_id, content, ok):
        self.id, self.hashed = bounded(call_id, ID_MAX)
        self.content = content
        self.ok = ok


def _list(value):
    return value if isinstance(value, list) else []


def _dict(value):
    return value if isinstance(value, dict) else {}


def request_results(api, body):
    """([Result], {call id: [Call, ...]}) of a request: the tool results it
    sends, in message order, and the calls its history holds, per id in
    order (an id may repeat in a conversation, Kimi-style)."""
    history, results = {}, []
    for message in _list(_dict(body).get("messages")):
        message = _dict(message)
        if api == OPENAI:
            if message.get("role") == "assistant":
                for tc in _list(message.get("tool_calls")):
                    call = _openai_call(_dict(tc))
                    history.setdefault(call.id, []).append(call)
            elif message.get("role") == "tool":
                results.append(Result(message.get("tool_call_id"), message.get("content"), True))
        else:
            for block in _list(message.get("content")):
                block = _dict(block)
                if block.get("type") == "tool_use":
                    call = Call(block.get("id"), block.get("name"), block.get("input"))
                    history.setdefault(call.id, []).append(call)
                elif block.get("type") == "tool_result":
                    results.append(Result(block.get("tool_use_id"), block.get("content"),
                                          block.get("is_error") is not True))
    return results, history


def _openai_call(tc):
    kind = tc.get("type") or "function"
    body = _dict(tc.get(kind)) or _dict(tc.get("function"))
    return Call(tc.get("id"), body.get("name"), tool_input_of(body.get("arguments", body.get("input"))))


class StreamCalls:
    """Tool calls out of a text/event-stream answer, as they complete; the
    finish reasons, whether an `error` event came, and whether the stream
    said it was complete ([DONE] or every choice finished; message_stop)."""

    def __init__(self, api):
        self.api = api
        self.pending = b""
        self.data = []
        self.event = None
        self.open = {}   # key -> state of a call still streaming, in start order
        self.done = []
        self.reasons = set()
        self.choices, self.finished = set(), set()
        self.error = False
        self.complete = False

    def feed(self, data):
        self.pending += data
        *lines, self.pending = self.pending.split(b"\n")
        for line in lines:
            self._line(line.rstrip(b"\r"))
        done, self.done = self.done, []
        return done

    def finish(self):
        """Calls of a stream that ended before it said they were complete."""
        if self.pending:
            self._line(self.pending.rstrip(b"\r"))
            self.pending = b""
        self._dispatch()
        for key in list(self.open):
            self._close(key)
        if self.api == OPENAI and self.choices and self.choices <= self.finished:
            self.complete = True
        done, self.done = self.done, []
        return done

    def _line(self, line):
        if not line:
            self._dispatch()
        elif line.startswith(b"data:"):
            value = line[5:]
            self.data.append(value[1:] if value.startswith(b" ") else value)
        elif line.startswith(b"event:"):
            self.event = line[6:].strip()

    def _dispatch(self):
        event, self.event = self.event, None
        if event == b"error":
            self.error = True
        if not self.data:
            return
        text = b"\n".join(self.data).decode("utf-8", "replace")
        self.data = []
        if text.strip() == "[DONE]":
            self.complete = True
            for key in list(self.open):
                self._close(key)
            return
        try:
            message = json.loads(text)
        except ValueError:
            return
        if isinstance(message, dict):
            if "error" in message or message.get("type") == "error":
                self.error = True
            (self._openai if self.api == OPENAI else self._anthropic)(message)

    def _openai(self, event):
        for choice in map(_dict, _list(event.get("choices"))):
            index = choice.get("index", 0)
            self.choices.add(index)
            for position, tc in enumerate(map(_dict, _list(_dict(choice.get("delta")).get("tool_calls")))):
                key = (index, tc.get("index", position))
                state = self.open.setdefault(key, {"id": None, "name": None, "args": []})
                if tc.get("id") and not state["id"]:
                    state["id"] = tc["id"]
                function = _dict(tc.get("function"))
                if function.get("name") and not state["name"]:
                    state["name"] = function["name"]
                if isinstance(function.get("arguments"), str):
                    state["args"].append(function["arguments"])
            if choice.get("finish_reason") is not None:
                self.reasons.add(choice["finish_reason"])
                self.finished.add(index)
                for key in [k for k in self.open if k[0] == index]:
                    self._close(key)

    def _anthropic(self, event):
        kind, index = event.get("type"), event.get("index")
        if kind == "content_block_start":
            block = _dict(event.get("content_block"))
            if block.get("type") == "tool_use":
                self.open[index] = {"id": block.get("id"), "name": block.get("name"), "input": block.get("input"),
                                    "args": []}
        elif kind == "content_block_delta" and index in self.open:
            delta = _dict(event.get("delta"))
            if delta.get("type") == "input_json_delta" and isinstance(delta.get("partial_json"), str):
                self.open[index]["args"].append(delta["partial_json"])
        elif kind == "content_block_stop" and index in self.open:
            self._close(index)
        elif kind == "message_delta":
            reason = _dict(event.get("delta")).get("stop_reason")
            if reason is not None:
                self.reasons.add(reason)
        elif kind == "message_stop":
            self.complete = True
            for key in list(self.open):
                self._close(key)

    def _close(self, key):
        state = self.open.pop(key)
        joined = "".join(state["args"])
        if self.api == OPENAI or joined.strip():
            tool_input = tool_input_of(joined)
        else:
            tool_input = state["input"] if state["input"] is not None else {}
        self.done.append(Call(state["id"], state["name"], tool_input))


class ResponseReader:
    """Reads the tool calls of a 2xx answer as its bytes pass (never changing
    them). feed() and finish() return the calls completed so far; `unread`
    says why the rest cannot be read; `calls`, `reasons`, `error` and
    `complete` describe the whole answer once finish() has run."""

    def __init__(self, api, content_type, content_encoding):
        self.api = api
        media = (content_type or "").split(";", 1)[0].strip().lower()
        self.stream = StreamCalls(api) if media == "text/event-stream" else None
        self.unread = None
        self.body = bytearray()
        self.calls = 0
        self.reasons = set()
        self.error = False
        self.complete = False
        try:
            self.decoder = Decoder(content_encoding)
        except Unreadable as exc:
            self.decoder, self.unread = None, str(exc)
        if self.unread is None and self.stream is None and not (media == "application/json" or media.endswith("+json")):
            self.unread = "Content-Type %s is neither JSON nor an event stream" % safe(content_type or "(none)", 60)

    def feed(self, data):
        if self.unread is not None or not data:
            return []
        try:
            text = self.decoder.feed(data)
        except Unreadable as exc:
            self.unread = str(exc)
            return []
        if self.stream is not None:
            return self._count(self.stream.feed(text))
        self.body += text
        return []

    def finish(self):
        if self.unread is not None:
            return []
        if self.stream is not None:
            calls = self._count(self.stream.finish())
            self.reasons, self.error, self.complete = self.stream.reasons, self.stream.error, self.stream.complete
            return calls
        try:
            body = json.loads(bytes(self.body).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.unread = "the body is not JSON"
            return []
        self.complete = True
        body = _dict(body)
        self.error = "error" in body
        if self.api == OPENAI:
            self.reasons = {_dict(c).get("finish_reason") for c in _list(body.get("choices"))} - {None}
        elif body.get("stop_reason") is not None:
            self.reasons = {body["stop_reason"]}
        return self._count(response_calls(self.api, body))

    def _count(self, calls):
        self.calls += len(calls)
        return calls

    def ends_turn(self):
        """A complete answer with no tool call that ends the turn (A-3: stop)."""
        return (self.unread is None and self.complete and not self.calls
                and any(r in STOP_REASONS[self.api] for r in self.reasons if isinstance(r, str)))


def response_calls(api, body):
    """[Call] of a whole (not streamed) answer body."""
    body = _dict(body)
    if api == OPENAI:
        return [_openai_call(_dict(tc)) for choice in _list(body.get("choices"))
                for tc in _list(_dict(_dict(choice).get("message")).get("tool_calls"))]
    # Only tool_use: server_tool_use and the like run upstream and get no result from the agent.
    return [Call(b.get("id"), b.get("name"), b.get("input")) for b in map(_dict, _list(body.get("content")))
            if b.get("type") == "tool_use"]


# --- the trace ------------------------------------------------------------------------

class Conversation:
    """What the proxy knows of one conversation key (A-3, A-9)."""

    def __init__(self):
        self.seq = 0
        self.open = False      # a session_start with no session_end after it
        self.pres = {}         # call id -> [open pre, oldest first]
        self.posted = {}       # call id -> [output_sha256 of each result recorded, in order]
        self.touched = False   # this run wrote a line for it
        self.reported = set()  # (call id, i) re-sent with another hash, already said (A-5)


class Recorder:
    """Appends proxy records to the trace. The state of every conversation is
    in memory: the trace is read once, here, and from then on only appended
    to, under capture's file lock and one thread lock (A-9). ts is taken
    under the lock, so lines are written in ts order."""

    def __init__(self, log_path, cwd=None, clock=None, err=None, monotonic=None):
        self.log_path = log_path
        self.cwd = cwd
        self.clock = clock or common.now_ts
        self.monotonic = monotonic or time.monotonic
        self.err = err if err is not None else sys.stderr
        self.lock = threading.RLock()
        self.convs = {}
        self.unread_paths = set()
        self.fold = {"last": None, "count": 0}
        self._load()

    # reading the trace once (A-9)

    def _load(self):
        try:
            with open(self.log_path, "rb") as f:
                text = f.read().decode("utf-8", "replace")
        except FileNotFoundError:
            return
        except OSError as exc:
            self.silence("could not read the trace at start (%s): pairing starts empty" % describe_error(exc))
            return
        pres = {}  # (key, seq) -> (call id, pre)
        for raw in text.splitlines():
            if '"proxy"' not in raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("source") != SOURCE:
                continue
            key, seq, phase = rec.get("session_id"), rec.get("seq"), rec.get("phase")
            if not isinstance(key, str) or not isinstance(seq, int) or isinstance(seq, bool):
                continue
            conv = self.convs.setdefault(key, Conversation())
            conv.seq = max(conv.seq, seq)
            use_id = rec.get("tool_use_id")
            if phase == "session_start":
                conv.open = True
            elif phase == "session_end":
                conv.open = False
            elif phase == "pre":
                pres[(key, seq)] = (use_id, {"seq": seq, "tool": rec.get("tool"), "input_sha256": rec.get("input_sha256"),
                                             "input_meta": rec.get("input_meta"),
                                             "hashed": rec.get("tool_hashed") is True})
            elif phase == "post":
                pres.pop((key, seq), None)
                conv.posted.setdefault(use_id, []).append(rec.get("output_sha256"))
            elif phase == "history":
                for hid, h in zip(_list(rec.get("tool_use_ids")), _list(rec.get("output_sha256s"))):
                    conv.posted.setdefault(hid, []).append(h)
        for (key, seq), (use_id, pre) in sorted(pres.items(), key=lambda x: x[0][1]):
            self.convs[key].pres.setdefault(use_id, []).append(pre)

    # writing

    def _cwd(self):
        return self.cwd if self.cwd else os.getcwd()

    def _append(self, lines):
        """Append lines under the locks. On failure, one RAQIB-SILENCE line on
        stderr (the trace cannot hold it). Never raises."""
        if not lines:
            return
        try:
            with self.lock:
                with open(self.log_path, "ab+") as f:
                    capture.lock(f)
                    try:
                        end = f.seek(0, os.SEEK_END)
                        torn = end > 0 and f.seek(end - 1) >= 0 and f.read(1) != b"\n"
                        f.write((b"\n" if torn else b"") + "".join(line + "\n" for line in lines).encode("ascii"))
                        f.flush()
                    finally:
                        capture.unlock(f)
        except Exception as exc:
            self._stderr("%s proxy could not write the trace %s: %s" % (MARKER, safe(self.log_path),
                                                                         describe_error(exc)))

    def _stderr(self, line):
        try:
            self.err.write(line + "\n")
            self.err.flush()
        except Exception:
            pass

    def _line(self, key, conv, phase, tool=SESSION_TOOL, use_id=None, hashed=False, fields=()):
        conv.seq += 1
        conv.touched = True
        rec = {"ts": self.clock(), "seq": conv.seq, "session_id": key, "phase": phase, "tool": tool}
        if use_id is not None:
            rec["tool_use_id"] = use_id
        if hashed:
            rec["tool_hashed"] = True
        rec.update(fields)
        rec["cwd"] = self._cwd()
        rec["source"] = SOURCE
        return json.dumps(rec, separators=(",", ":"), ensure_ascii=True)

    def _post(self, key, conv, seq, part, use_id, hashed):
        rec = {"ts": self.clock(), "seq": seq, "session_id": key, "phase": "post", "tool": part["tool"]}
        if use_id is not None:
            rec["tool_use_id"] = use_id
        if hashed:
            rec["tool_hashed"] = True
        for name in ("input_sha256", "input_meta", "output_sha256", "output_meta", "ok"):
            rec[name] = part[name]
        rec["cwd"] = self._cwd()
        rec["source"] = SOURCE
        conv.touched = True
        return json.dumps(rec, separators=(",", ":"), ensure_ascii=True)

    def silence_text(self, what, method="-", path="-", session="-"):
        return "%s proxy %s session=%s %s %s" % (MARKER, safe(what), safe(session, 80), safe(method, 20),
                                                 safe(path, 200))

    def silence(self, what, method="-", path="-", session="-"):
        """One RAQIB-SILENCE line, in the trace and on stderr (A3)."""
        line = self.silence_text(what, method, path, session)
        self._stderr(line)
        self._append([line])

    def silence_once(self, path, what, method):
        with self.lock:
            if path in self.unread_paths:
                return
            self.unread_paths.add(path)
        self.silence(what, method, path)

    def refused(self, what, method, path):
        """A refused request: one line, then at most one per FOLD_SECONDS
        that counts the ones not written (ruling A-6)."""
        now = self.monotonic()
        with self.lock:
            fold = self.fold
            if fold["last"] is not None and now - fold["last"] < FOLD_SECONDS:
                fold["count"] += 1
                return
            count, fold["count"], fold["last"] = fold["count"], 0, now
        more = "; %d more refused requests in the %g s before were not written one by one" % (
            count, FOLD_SECONDS) if count else ""
        self.silence("did not relay a request: %s%s" % (what, more), method, path)

    # the conversation

    def request(self, key, results, history, method="POST", path="-"):
        """A request of conversation `key`: session_start on first sight (or
        after a session_end), then its new results: posts, the one history
        line of a first request (A-4), a half for a result with no call; a
        RAQIB-SILENCE line for a result re-sent with another hash (A-5)."""
        prepared = []
        seen = {}
        for r in results:
            i = seen.get(r.id, 0)
            seen[r.id] = i + 1
            calls = history.get(r.id) or []
            call = calls[i] if i < len(calls) else (calls[-1] if calls else None)
            prepared.append((r, i, call, common.canonical_sha256(r.content)))
        with self.lock:
            lines, held = [], []
            conv = self.convs.get(key)
            first = conv is None
            if first:
                conv = self.convs[key] = Conversation()
            if not conv.open:
                lines.append(self._line(key, conv, "session_start"))
                conv.open = True
            conv.touched = True
            for r, i, call, out_sha in prepared:
                posted = conv.posted.setdefault(r.id, [])
                if i < len(posted):
                    if posted[i] != out_sha and (r.id, i) not in conv.reported:
                        conv.reported.add((r.id, i))
                        lines.append(self.silence_text("result for %s re-sent with a different hash (output_sha256 %s,"
                                                       " posted %s); the first post stays" % (
                                                           r.id, out_sha[:16], str(posted[i])[:16]),
                                                       method, path, key))
                        self._stderr(lines[-1])
                    continue
                posted.append(out_sha)
                pres = conv.pres.get(r.id)
                if pres:
                    pre = pres.pop(0)
                    lines.append(self._post(key, conv, pre["seq"], self._part(r, call, pre, out_sha), r.id,
                                            r.hashed or pre["hashed"] or (call is not None and call.hashed)))
                elif first:
                    held.append((r, out_sha))
                else:
                    conv.seq += 1
                    lines.append(self._post(key, conv, conv.seq, self._part(r, call, None, out_sha), r.id,
                                            r.hashed or (call is not None and call.hashed)))
            if held:
                lines.append(self._line(key, conv, "history", hashed=any(r.hashed for r, _ in held), fields={
                    "results": len(held), "tool_use_ids": [r.id for r, _ in held],
                    "output_sha256s": [h for _, h in held]}))
            self._append(lines)

    def _part(self, result, call, pre, out_sha):
        part = {"output_sha256": out_sha, "output_meta": common.output_meta({"tool_response": result.content}),
                "ok": result.ok}
        if call is not None:
            part.update(tool=call.name, input_sha256=common.canonical_sha256(call.input),
                        input_meta=common.input_meta(call.name, call.input))
        elif pre is not None:
            part.update(tool=pre["tool"], input_sha256=pre["input_sha256"], input_meta=pre["input_meta"])
        else:
            part.update(tool=UNKNOWN_TOOL, input_sha256=common.canonical_sha256(None), input_meta={})
        return part

    def pres(self, key, calls):
        """One pre per tool call of an answer, each with the next seq of its key."""
        if not calls:
            return
        prepared = [(c, common.canonical_sha256(c.input), common.input_meta(c.name, c.input)) for c in calls]
        with self.lock:
            conv = self.convs.setdefault(key, Conversation())
            lines = []
            for c, sha, meta in prepared:
                lines.append(self._line(key, conv, "pre", c.name, c.id, c.hashed,
                                        {"input_sha256": sha, "input_meta": meta}))
                conv.pres.setdefault(c.id, []).append({"seq": conv.seq, "tool": c.name, "input_sha256": sha,
                                                       "input_meta": meta, "hashed": c.hashed})
            self._append(lines)

    def stop(self, key):
        """An answer that ended the turn with no tool call (A-3)."""
        with self.lock:
            conv = self.convs.setdefault(key, Conversation())
            self._append([self._line(key, conv, "stop")])

    def shutdown(self):
        """session_end for every key still open (A-3: "every open key", those
        read from the trace too), and the count of refused requests not yet
        written (A-6)."""
        with self.lock:
            count, self.fold["count"] = self.fold["count"], 0
            lines = []
            for key, conv in self.convs.items():
                if conv.open:
                    lines.append(self._line(key, conv, "session_end"))
                    conv.open = False
            self._append(lines)
        if count:
            self.silence("did not relay %d more refused requests, not written one by one (folded, %g s)" % (
                count, FOLD_SECONDS))


# --- the relay ------------------------------------------------------------------------

class _ClientGone(Exception):
    """The agent closed its connection while the answer was being relayed."""


class _BadBody(Exception):
    """The agent's request body cannot be read to its end."""


class _Interim(Exception):
    """The upstream switched protocols, or sent too many interim answers."""


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = AGENT_TIMEOUT
    upstream = None   # Upstream
    recorder = None   # Recorder

    def log_message(self, format, *args):
        pass  # a request line can carry a key in its query: nothing is logged

    def do_GET(self):
        self.relay()

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_GET

    def __getattr__(self, name):
        # Every other method (TRACE, CONNECT, anything): 405 and a line (ruling A-8).
        if name.startswith("do_"):
            return self._unhandled
        raise AttributeError(name)

    def _unhandled(self):
        self.refuse(405, "the method %s is not relayed (only %s)" % (safe(self.command, 20), ", ".join(RELAYED_METHODS)))

    def refuse(self, status, why):
        self.recorder.refused(why, self.command, self._path_only())
        self._reply(status, "raqib proxy: %s\n" % why)

    def _reply(self, status, text):
        """A response of the proxy's own (never a relayed one); the
        connection is closed after it."""
        body = text.encode("ascii", "backslashreplace")
        self.close_connection = True
        try:
            self.send_response_only(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass

    def _path_only(self):
        path = getattr(self, "path", "") or ""
        return urllib.parse.urlsplit(path).path if path.startswith("/") else "(not a path)"

    def _guard(self, what, step, *args):
        """Run one recording step; whatever it raises becomes one line and the
        bytes still pass (ruling A-1). Returns the step's value, or None."""
        try:
            return step(*args)
        except Exception as exc:
            self.recorder.silence("record failed: %s (%s); the bytes are relayed" % (type(exc).__name__, what),
                                  self.command, self._path_only(), getattr(self, "key", None) or "-")
            return None

    def _allowed(self):
        port = self.server.server_address[1]
        if (self.headers.get_all("Host") or []) != ["127.0.0.1:%d" % port]:
            self.refuse(403, "its Host is not 127.0.0.1:%d, the listen address" % port)
            return False
        if self.headers.get_all("Origin"):
            self.refuse(403, "it carries an Origin header (a browser page)")
            return False
        if self.headers.get_all("Upgrade"):
            self.refuse(501, "an Upgrade request is not relayed")
            return False
        if not self.path.startswith("/"):
            self.refuse(400, "a target that is not a path (an absolute URL or authority form)")
            return False
        return True

    def _body_pieces(self):
        """(raw, data) pieces of a chunked request body as it is read: each
        size line, data in pieces of at most CHUNK bytes, the CRLFs, the last
        chunk and the trailers. _BadBody when it cannot be read."""
        try:
            while True:
                line = self.rfile.readline(1024)
                size_text = line.split(b";", 1)[0].strip()
                if (not line.endswith(b"\n") or not size_text or len(size_text) > CHUNK_SIZE_DIGITS
                        or any(c not in b"0123456789abcdefABCDEF" for c in size_text)):
                    raise _BadBody("bad chunk size line")
                yield line, b""
                size = int(size_text, 16)
                if size == 0:
                    while True:  # trailers, up to the empty line
                        trailer = self.rfile.readline(8192)
                        if not trailer.endswith(b"\n"):
                            raise _BadBody("bad trailer")
                        yield trailer, b""
                        if trailer in (b"\r\n", b"\n"):
                            return
                while size:
                    piece = self.rfile.read(min(size, CHUNK))
                    if not piece:
                        raise _BadBody("short chunk")
                    size -= len(piece)
                    yield piece, piece
                end = self.rfile.read(2)
                if end != b"\r\n":
                    raise _BadBody("a chunk not followed by CRLF")
                yield end, b""
        except OSError as exc:
            raise _BadBody(type(exc).__name__)

    def _exact_pieces(self, n):
        left = n
        try:
            while left:
                piece = self.rfile.read(min(left, CHUNK))
                if not piece:
                    raise _BadBody("the body ended %d bytes short" % left)
                left -= len(piece)
                yield piece
        except OSError as exc:
            raise _BadBody(type(exc).__name__)

    def _read_body(self):
        """(raw head, body or None, rest or None) of the request; the body is
        None and rest an iterator of raw bytes to stream when the body is over
        PARSE_MAX (A-1). None after refusing."""
        te = self.headers.get_all("Transfer-Encoding") or []
        lengths = self.headers.get_all("Content-Length") or []
        try:
            if te:
                if [v.strip().lower() for v in te] != ["chunked"] or lengths:
                    self.refuse(501, "a request Transfer-Encoding other than chunked")
                    return None
                pieces = self._body_pieces()
                raw, body = bytearray(), bytearray()
                for piece, data in pieces:
                    raw += piece
                    body += data
                    if len(body) > PARSE_MAX:
                        return bytes(raw), None, (p for p, _ in pieces)
                return bytes(raw), bytes(body), None
            if lengths:
                values = {v.strip() for v in lengths}
                if len(values) != 1 or not next(iter(values)).isdigit():
                    self.refuse(400, "a request with a bad Content-Length")
                    return None
                n = int(values.pop())
                if n > PARSE_MAX:
                    return b"", None, self._exact_pieces(n)
                data = b"".join(self._exact_pieces(n))
                return data, data, None
            return b"", b"", None
        except _BadBody as exc:
            self.refuse(400, "its body cannot be read (%s)" % exc)
            return None

    def relay(self):
        if "close" in connection_tokens(self.headers.get_all("Connection") or []):
            self.close_connection = True  # "Connection: close, X" too, not only a lone "close"
        self.key = None
        if not self._allowed():
            return
        got = self._read_body()
        if got is None:
            return
        raw, body, rest = got
        method, path = self.command, self._path_only()
        api = api_of(path)
        if method == "POST":
            if body is None:
                self.recorder.silence("did not read a request: its body is over the %d bytes the proxy reads;"
                                      " relayed unrecorded" % PARSE_MAX, method, path)
            else:
                self._guard("reading the request", self._read_request, api, path, body)
        try:
            conn = self.upstream.connection()
            conn.putrequest(method, self.upstream.target(self.path), skip_host=True, skip_accept_encoding=True)
            self._relay_request_headers(conn)
            conn.endheaders()
            if raw:
                conn.send(raw)
            if rest is not None:
                for piece in rest:
                    conn.send(piece)
            response = self._final_response(conn, conn.getresponse(), method, path)
        except _BadBody as exc:
            self.recorder.silence("did not relay a request: its body broke off while it was streamed (%s)" % exc,
                                  method, path, self.key or "-")
            self.close_connection = True
            return
        except Exception as exc:
            timeout = isinstance(exc, (TimeoutError, socket.timeout))
            self.recorder.silence("upstream failed before an answer: %s; the agent gets %d" % (
                describe_error(exc), 504 if timeout else 502), method, path, self.key or "-")
            self._reply(504 if timeout else 502, "raqib proxy: the upstream %s did not answer (%s)\n" % (
                self.upstream.url, describe_error(exc)))
            return
        try:
            self._relay_response(response, api, method, path)
        finally:
            response.close()
            conn.close()

    def _final_response(self, conn, response, method, path):
        """The final answer: an interim 1xx other than 100 (http.client gives
        it back as if final) is not relayed; one line each (ruling A-8)."""
        for _ in range(INTERIM_MAX):
            if not 100 <= response.status < 200:
                return response
            self.recorder.silence("upstream sent an interim %d answer; not relayed" % response.status, method, path,
                                  self.key or "-")
            if response.status == 101:
                raise _Interim("101 Switching Protocols to a request that asked for none")
            final = http.client.HTTPResponse(conn.sock, method=method)
            final.fp, response.fp = response.fp, None
            final.begin()
            response = final
        raise _Interim("more than %d interim answers" % INTERIM_MAX)

    def _read_request(self, api, path, body):
        """The conversation key of a request and the posts of its tool results,
        before it is relayed."""
        if api in (OPENAI, ANTHROPIC):
            try:
                parsed = json.loads(decode_body(body, self.headers.get("Content-Encoding")).decode("utf-8"))
            except (Unreadable, ValueError, UnicodeDecodeError) as exc:
                why = str(exc) if isinstance(exc, Unreadable) else "the body is not JSON"
                self.recorder.silence("did not read a request (%s): its tool results and the tool calls of its"
                                      " answer are not recorded" % why, "POST", path)
                return
            if not isinstance(parsed, dict):
                self.recorder.silence("did not read a request (not a JSON object): its tool results and the tool"
                                      " calls of its answer are not recorded", "POST", path)
                return
            key = conversation_key(parsed)
            results, history = request_results(api, parsed)
            self.recorder.request(key, results, history, "POST", path)
            self.key = key
        elif api is None and body:
            try:
                parsed = json.loads(decode_body(body, self.headers.get("Content-Encoding")).decode("utf-8"))
            except (Unreadable, ValueError, UnicodeDecodeError):
                return
            if isinstance(parsed, dict) and "model" in parsed and any(k in parsed for k in MODEL_KEYS):
                self.recorder.silence_once(path, "cannot read model requests on this path: their tool calls are"
                                                 " not recorded (only /chat/completions and /messages are read)",
                                           "POST")

    def _relay_request_headers(self, conn):
        named = connection_tokens(self.headers.get_all("Connection") or [])
        host_sent = False
        for name, value in self.headers.items():
            lower = name.lower()
            if lower == "host":
                if not host_sent:
                    conn.putheader(name, self.upstream.netloc)
                    host_sent = True
                continue
            if lower == "transfer-encoding":
                conn.putheader(name, value)  # chunked only (_read_body); the raw chunks are relayed as they came
                continue
            if lower in HOP_BY_HOP or lower in named:
                continue
            conn.putheader(name, value)
        if not host_sent:
            conn.putheader("Host", self.upstream.netloc)  # HTTP/1.1 requires it

    def _relay_response(self, response, api, method, path):
        status = response.status
        no_body = method == "HEAD" or status in (204, 304) or 100 <= status < 200
        chunked_in = bool(response.chunked) and not no_body
        chunked_out = chunked_in and self.request_version != "HTTP/1.0"
        until_close = not no_body and not chunked_in and response.length is None
        named = connection_tokens(response.msg.get_all("Connection") or [])
        reader = None
        if self.key is not None and api in (OPENAI, ANTHROPIC) and 200 <= status < 300 and not no_body:
            reader = self._guard("reading the answer", ResponseReader, api, response.msg.get("Content-Type"),
                                 response.msg.get("Content-Encoding"))
        try:
            self.send_response_only(status, response.reason)
            for name, value in response.msg.items():
                lower = name.lower()
                if lower == "transfer-encoding":
                    if chunked_out or no_body:
                        self.send_header(name, value)  # a HEAD answer names the framing GET would have
                    elif not chunked_in:
                        until_close = True  # a transfer coding the proxy does not undo: relayed as it came
                        self.send_header(name, value)
                    continue
                if lower == "content-length" and chunked_in:
                    continue  # the framing is the chunks, redone here: a length beside them would be stale (A-8)
                if lower in HOP_BY_HOP or lower in named:
                    continue
                self.send_header(name, value)
            if until_close or (chunked_in and not chunked_out):
                self.close_connection = True
                self.send_header("Connection", "close")  # the body ends when the connection does
            self.end_headers()
        except OSError:
            self.close_connection = True
            return
        failure, gone = None, False
        if not no_body:
            failure, gone, reader = self._relay_body(response, reader, chunked_out)
        say = self.recorder.silence
        key = self.key or "-"
        if gone:
            say("the agent left during the answer: the rest was not relayed and its tool calls are not recorded",
                method, path, key)
        if failure is not None:
            self.close_connection = True
            say("upstream failed during the answer (status %d already sent): %s" % (status, failure), method, path, key)
        elif status >= 500:
            say("upstream answered %d; relayed unchanged" % status, method, path, key)
        if reader is not None and not gone and failure is None:
            self._guard("reading the answer", self._after_answer, reader, method, path)

    def _after_answer(self, reader, method, path):
        say, key = self.recorder.silence, self.key
        if reader.unread:
            say("did not read an answer (%s): its tool calls are not recorded" % reader.unread, method, path, key)
            return
        if reader.error:
            say("the answer carried an error event", method, path, key)
        if reader.stream is not None and not reader.complete:
            say("the answer stream ended without its end event ([DONE], message_stop)", method, path, key)
        if reader.ends_turn():
            self.recorder.stop(key)

    def _relay_body(self, response, reader, chunked_out):
        """Relay the body piece by piece as it arrives. The calls a piece
        completes are recorded before the piece is passed on, and the calls
        of a whole body before its last byte (or its end) is; a recording
        step that fails stops recording, never the relay (A-1). (failure text
        of the upstream or None, the agent left, the reader still in use)."""
        sized = response.length is not None
        state = {"reader": reader, "finished": False}

        def feed(data):
            self.recorder.pres(self.key, state["reader"].feed(data))
            return True

        def finish():
            if not state["finished"]:
                state["finished"] = True
                self.recorder.pres(self.key, state["reader"].finish())
            return True

        def fed(step, *args):
            ok = self._guard("reading the answer", step, *args)
            if ok is None:
                state["reader"] = None

        def send(data):
            try:
                self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data) if chunked_out else data)
            except OSError:
                raise _ClientGone()
        try:
            while True:
                try:
                    data = response.read1(CHUNK)
                except Exception as exc:
                    return describe_error(exc), False, state["reader"]
                if not data:
                    break
                if state["reader"] is not None:
                    fed(feed, data)
                    if sized and response.length == 0 and state["reader"] is not None:
                        fed(finish)
                send(data)
                if sized and response.length == 0:
                    break
            if sized and response.length:
                return "the answer ended %d bytes short" % response.length, False, state["reader"]
            if state["reader"] is not None:
                fed(finish)
            if chunked_out:
                try:
                    self.wfile.write(b"0\r\n\r\n")
                except OSError:
                    raise _ClientGone()
        except _ClientGone:
            self.close_connection = True  # the agent went away; nothing more is read or relayed
            return None, True, state["reader"]
        return None, False, state["reader"]


def connection_tokens(values):
    return {t.strip().lower() for v in values for t in v.split(",") if t.strip()}


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def make_server(listen, upstream, recorder):
    """The proxy on (host, port); port 0: any free port."""
    host, port = listen
    if host != "127.0.0.1":
        raise UsageError("the proxy listens on 127.0.0.1 only")
    handler = type("ProxyHandler", (Handler,), {"upstream": upstream, "recorder": recorder})
    return Server((host, port), handler)


def check_log(path):
    """The trace must be writable before the proxy starts (A3)."""
    try:
        with open(path, "a", encoding="utf-8"):
            pass
    except OSError as exc:
        raise UsageError("cannot write the trace %s: %s" % (path, exc.strerror or exc))


def run(listen, upstream, log, allow_plain=False, out=None, err=None, cwd=None):
    """The `proxy` command: serve until interrupted, then write session_end
    for the open conversations. Exit 0 on Ctrl-C."""
    out = out or sys.stdout
    address = parse_listen(listen)
    target = parse_upstream(upstream, allow_plain)
    log = os.path.abspath(log)
    if cwd is not None and not os.path.isabs(cwd):
        raise UsageError("--cwd must be an absolute directory, not %r" % (cwd,))
    check_log(log)
    recorder = Recorder(log, cwd=cwd, err=err)
    try:
        server = make_server(address, target, recorder)
    except OSError as exc:
        raise UsageError("cannot listen on %s: %s" % (listen, exc.strerror or exc))
    out.write("raqib: proxy http://127.0.0.1:%d/ -> %s (trace %s, one session per conversation, cwd %s;"
              " Ctrl-C to stop)\n" % (server.server_address[1], target.url, log, cwd or os.getcwd()))
    out.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        recorder.shutdown()
    return 0
