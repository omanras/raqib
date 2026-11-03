"""Raqib proxy capture source (M5.2, ADR-0003).

`python -m raqib proxy --listen 127.0.0.1:PORT --upstream URL --log PATH`
is a local reverse proxy between an agent and its model API. The agent's
base URL points at http://127.0.0.1:PORT; every request is relayed to URL
(https; a plain http URL only with --allow-plain-upstream and only to a
loopback address, for tests) and the answer is relayed back.

The proxy relays and never steers (A4):
- it listens on 127.0.0.1 only, plain HTTP;
- the upstream is HTTPS with certificate and host name verification on
  (ssl.create_default_context(); it is never turned off);
- request and response bodies are forwarded byte for byte; the headers too,
  except what relaying HTTP/1.1 requires: Host names the upstream, the
  hop-by-hop headers (Connection and the headers it names, Keep-Alive,
  Proxy-*, TE, Trailer, Upgrade) are not passed on, chunked framing is
  redone hop by hop, and a body that ends at close gets Connection: close.
  No other header is added (no Server, no Date);
- one upstream request per agent request: no retry, no request of its own;
- a streamed answer (chunked, text/event-stream) is passed on piece by
  piece as it arrives.

What it records, from the JSON it reads but never changes (ADR-0003):
- OpenAI chat/completions (a path ending in /chat/completions): each
  tool_calls entry of a response (JSON or SSE deltas) is a `pre`; the
  role=tool message with its tool_call_id in a later request is its `post`;
- Anthropic messages (a path ending in /messages): each tool_use block of a
  response (JSON or SSE content blocks) is a `pre`; the tool_result block
  with its tool_use_id in a later request is its `post`.
A pre takes the next seq of the proxy's session (one per proxy run); a post
takes the seq of the open proxy pre with the same tool call id, anywhere in
the trace, so a restarted proxy still closes the calls of the run before.
A result that was posted before (every request repeats the conversation) is
not posted again. A result whose call the proxy never saw is a post with a
new seq: SILENCE-HALF reads it as a result with no call. Records carry
hashes and common.input_meta's extract only, never prompt text or tool
arguments, and `source: "proxy"`. cwd is the proxy's own working directory
(the API traffic does not carry the agent's). A pre is written before the
bytes that complete its call are passed on, so the post of a fast agent can
never come first.

Silence is an alarm (A3). Each of these appends one line starting with
RAQIB-SILENCE: to the trace (watch reads it as a capture failure; report as
a corrupt line) and to stderr:
- an upstream failure: no connection, TLS failure, a timeout, a connection
  cut mid-answer, or an answer with status 5xx. The agent gets the
  upstream's own status and bytes when there are any, else 502 (504 on a
  timeout) from the proxy;
- a request or a 2xx answer on a path above that cannot be read (not JSON,
  an unknown Content-Encoding, larger than PARSE_MAX bytes);
- a model request (JSON with "model" and "messages" or "tools") on another
  path, once per path per run: its tool calls are not read;
- a request that is not relayed (a target that is not a path, CONNECT, a
  body that cannot be read, an unknown Transfer-Encoding).
No header value is ever written anywhere, and a path is written without its
query string. The proxy never logs a request line.
"""
from __future__ import annotations

import datetime
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
import urllib.parse
import zlib

from raqib.hooks import capture, common

SOURCE = "proxy"
MARKER = capture.SILENCE
OPENAI, ANTHROPIC, COUNT = "openai", "anthropic", "count"
UNKNOWN_TOOL = "?"           # the tool of a result whose call is not in the request either
HOP_BY_HOP = frozenset(("connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                        "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"))
CHUNK = 65536
PARSE_MAX = 64 * 1024 * 1024  # bytes of one body read for records; the rest is still relayed
UPSTREAM_TIMEOUT = 600.0      # seconds of one upstream socket operation
AGENT_TIMEOUT = 600.0         # seconds of one agent socket operation (an idle keep-alive ends)
TEXT_MAX = 300                # characters of one detail in a RAQIB-SILENCE line
MODEL_KEYS = ("messages", "tools")


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


class Call:
    """A tool call the model asked for (a pre)."""

    def __init__(self, call_id, name, tool_input):
        self.id = common.tool_use_id(call_id)
        self.name = name if isinstance(name, str) and name else UNKNOWN_TOOL
        self.input = tool_input


class Result:
    """A tool result the agent sent back (a post)."""

    def __init__(self, call_id, content, ok):
        self.id = common.tool_use_id(call_id)
        self.content = content
        self.ok = ok


def _list(value):
    return value if isinstance(value, list) else []


def _dict(value):
    return value if isinstance(value, dict) else {}


def request_results(api, body):
    """([Result], {call id: Call}) of a request: the tool results it sends,
    in message order, and the calls its history holds."""
    history, results = {}, []
    for message in _list(_dict(body).get("messages")):
        message = _dict(message)
        if api == OPENAI:
            if message.get("role") == "assistant":
                for tc in _list(message.get("tool_calls")):
                    call = _openai_call(_dict(tc))
                    if call.id:
                        history[call.id] = call
            elif message.get("role") == "tool":
                results.append(Result(message.get("tool_call_id"), message.get("content"), True))
        else:
            for block in _list(message.get("content")):
                block = _dict(block)
                if block.get("type") == "tool_use":
                    call = Call(block.get("id"), block.get("name"), block.get("input"))
                    if call.id:
                        history[call.id] = call
                elif block.get("type") == "tool_result":
                    results.append(Result(block.get("tool_use_id"), block.get("content"),
                                          block.get("is_error") is not True))
    return results, history


def _openai_call(tc):
    kind = tc.get("type") or "function"
    body = _dict(tc.get(kind)) or _dict(tc.get("function"))
    return Call(tc.get("id"), body.get("name"), tool_input_of(body.get("arguments", body.get("input"))))


def response_calls(api, body):
    """[Call] of a whole (not streamed) response body."""
    body = _dict(body)
    if api == OPENAI:
        return [_openai_call(_dict(tc)) for choice in _list(body.get("choices"))
                for tc in _list(_dict(_dict(choice).get("message")).get("tool_calls"))]
    # Only tool_use: server_tool_use and the like run upstream and get no result from the agent.
    return [Call(b.get("id"), b.get("name"), b.get("input")) for b in map(_dict, _list(body.get("content")))
            if b.get("type") == "tool_use"]


class StreamCalls:
    """Tool calls out of a text/event-stream response, as they complete."""

    def __init__(self, api):
        self.api = api
        self.pending = b""
        self.data = []
        self.open = {}   # key -> state of a call still streaming, in start order
        self.done = []

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
        done, self.done = self.done, []
        return done

    def _line(self, line):
        if not line:
            self._dispatch()
        elif line.startswith(b"data:"):
            value = line[5:]
            self.data.append(value[1:] if value.startswith(b" ") else value)

    def _dispatch(self):
        if not self.data:
            return
        text = b"\n".join(self.data).decode("utf-8", "replace")
        self.data = []
        if text.strip() == "[DONE]":
            for key in list(self.open):
                self._close(key)
            return
        try:
            event = json.loads(text)
        except ValueError:
            return
        if isinstance(event, dict):
            (self._openai if self.api == OPENAI else self._anthropic)(event)

    def _openai(self, event):
        for choice in map(_dict, _list(event.get("choices"))):
            index = choice.get("index", 0)
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
        elif kind == "message_stop":
            for key in list(self.open):
                self._close(key)

    def _close(self, key):
        state = self.open.pop(key)
        joined = "".join(state["args"])
        if self.api == OPENAI:
            tool_input = tool_input_of(joined)
        elif joined.strip():
            tool_input = tool_input_of(joined)
        else:
            tool_input = state["input"] if state["input"] is not None else {}
        self.done.append(Call(state["id"], state["name"], tool_input))


class ResponseReader:
    """Reads the tool calls of a 2xx response as its bytes pass (never
    changing them). feed() and finish() return the calls completed so far;
    `unread` says why the rest cannot be read."""

    def __init__(self, api, content_type, content_encoding):
        self.api = api
        media = (content_type or "").split(";", 1)[0].strip().lower()
        self.stream = StreamCalls(api) if media == "text/event-stream" else None
        self.unread = None
        self.body = bytearray()
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
            return self.stream.feed(text)
        self.body += text
        return []

    def finish(self):
        if self.unread is not None:
            return []
        if self.stream is not None:
            return self.stream.finish()
        try:
            body = json.loads(bytes(self.body).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.unread = "the body is not JSON"
            return []
        return response_calls(self.api, body)


# --- the trace ------------------------------------------------------------------------

class Recorder:
    """Appends proxy records to the trace under capture's lock (the file
    lock, plus a thread lock for the proxy's own threads). ts is taken under
    the lock, so lines are written in ts order."""

    def __init__(self, log_path, session_id, cwd=None, clock=None, err=None):
        self.log_path = log_path
        self.session_id = session_id
        self.cwd = cwd
        self.clock = clock or common.now_ts
        self.err = err if err is not None else sys.stderr
        self.thread_lock = threading.Lock()
        self.unread_paths = set()
        self.unpaired = set()  # output hashes of results without an id, posted by this run

    def _cwd(self):
        return self.cwd if self.cwd else os.getcwd()

    def _locked(self, write):
        """write(log_text) -> lines; appended under the locks. On failure,
        one RAQIB-SILENCE line on stderr (the trace cannot hold it)."""
        try:
            with self.thread_lock:
                with open(self.log_path, "a+", encoding="utf-8", errors="replace", newline="") as f:
                    capture.lock(f)
                    try:
                        f.seek(0)
                        text = f.read()
                        lines = write(text)
                        if lines:
                            prefix = "\n" if text and not text.endswith("\n") else ""
                            f.write(prefix + "".join(line + "\n" for line in lines))
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

    def _state(self, text):
        """(max seq of this session, {call id: [open pre, oldest first]},
        posted call ids) over the proxy records of the trace."""
        max_seq, pres, closed, posted = 0, [], set(), set()
        for raw in text.splitlines():
            if '"proxy"' not in raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("source") != SOURCE:
                continue
            seq, sid = rec.get("seq"), rec.get("session_id")
            if not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(sid, str):
                continue
            if sid == self.session_id:
                max_seq = max(max_seq, seq)
            if rec.get("phase") == "pre":
                pres.append(rec)
            elif rec.get("phase") == "post":
                closed.add((sid, seq))
                if common.tool_use_id(rec.get("tool_use_id")):
                    posted.add(rec["tool_use_id"])
        open_pres = {}
        for rec in pres:
            use_id = common.tool_use_id(rec.get("tool_use_id"))
            if use_id and (rec["session_id"], rec["seq"]) not in closed:
                open_pres.setdefault(use_id, []).append(rec)
        return max_seq, open_pres, posted

    def _record(self, session_id, seq, phase, call, use_id):
        rec = {"ts": self.clock(), "seq": seq, "session_id": session_id, "phase": phase, "tool": call["tool"]}
        if use_id:
            rec["tool_use_id"] = use_id
        rec["input_sha256"] = call["input_sha256"]
        rec["input_meta"] = call["input_meta"]
        for key in ("output_sha256", "output_meta", "ok"):
            if key in call:
                rec[key] = call[key]
        rec["cwd"] = self._cwd()
        rec["source"] = SOURCE
        return json.dumps(rec, separators=(",", ":"), ensure_ascii=True)

    def pres(self, calls):
        """One pre per tool call of a response, each with the next seq."""
        if not calls:
            return
        prepared = [(c.id, {"tool": c.name, "input_sha256": common.canonical_sha256(c.input),
                            "input_meta": common.input_meta(c.name, c.input)}) for c in calls]

        def write(text):
            max_seq = self._state(text)[0]
            lines = []
            for use_id, part in prepared:
                max_seq += 1
                lines.append(self._record(self.session_id, max_seq, "pre", part, use_id))
            return lines
        self._locked(write)

    def posts(self, results, history):
        """One post per tool result not posted before: the seq of its open
        pre, else (a result with no call seen) the next seq."""
        if not results:
            return
        prepared = []
        for r in results:
            call = history.get(r.id) if r.id else None
            part = {"output_sha256": common.canonical_sha256(r.content),
                    "output_meta": common.output_meta({"tool_response": r.content}), "ok": r.ok}
            if call is not None:
                part.update(tool=call.name, input_sha256=common.canonical_sha256(call.input),
                            input_meta=common.input_meta(call.name, call.input))
            prepared.append((r.id, call is not None, part))

        def write(text):
            max_seq, open_pres, posted = self._state(text)
            lines = []
            for use_id, known, part in prepared:
                if use_id is None:
                    if part["output_sha256"] in self.unpaired:
                        continue
                    self.unpaired.add(part["output_sha256"])
                    pre = None
                elif open_pres.get(use_id):
                    pre = open_pres[use_id].pop(0)
                elif use_id in posted:
                    continue  # the conversation repeats a result already posted
                else:
                    pre = None
                if not known:  # the request does not hold the call: the pre's, else unknown
                    part = dict(part, tool=pre["tool"] if pre else UNKNOWN_TOOL,
                                input_sha256=pre["input_sha256"] if pre else common.canonical_sha256(None),
                                input_meta=pre["input_meta"] if pre else {})
                if pre is not None:
                    session_id, seq = pre["session_id"], pre["seq"]
                else:
                    max_seq += 1
                    session_id, seq = self.session_id, max_seq
                if use_id:
                    posted.add(use_id)
                lines.append(self._record(session_id, seq, "post", part, use_id))
            return lines
        self._locked(write)

    def silence(self, what, method="-", path="-"):
        """One RAQIB-SILENCE line, in the trace and on stderr (A3)."""
        line = "%s proxy %s session=%s %s %s" % (MARKER, safe(what), self.session_id, safe(method, 20),
                                                 safe(path, 200))
        self._stderr(line)

        def write(text):
            return [line]
        self._locked(write)

    def silence_once(self, path, what, method):
        with self.thread_lock:
            if path in self.unread_paths:
                return
            self.unread_paths.add(path)
        self.silence(what, method, path)


# --- the relay ------------------------------------------------------------------------

class _ClientGone(Exception):
    """The agent closed its connection while the answer was being relayed."""


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

    def do_CONNECT(self):
        self.refuse(405, "CONNECT is not relayed (this is a reverse proxy for one upstream)")

    def refuse(self, status, why):
        self.recorder.silence("did not relay a request: %s" % why, self.command, self._path_only())
        self._reply(status, "raqib proxy: %s\n" % why)

    def _reply(self, status, text):
        """A response of the proxy's own (never a relayed one)."""
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
        return urllib.parse.urlsplit(self.path).path if self.path.startswith("/") else "(not a path)"

    def _read_body(self):
        """(raw bytes to relay, decoded bytes) of the request body, or None
        after refusing it."""
        te = self.headers.get_all("Transfer-Encoding") or []
        lengths = self.headers.get_all("Content-Length") or []
        if te:
            if [v.strip().lower() for v in te] != ["chunked"] or lengths:
                self.refuse(501, "a request Transfer-Encoding other than chunked")
                return None
            return self._read_chunked()
        if lengths:
            values = {v.strip() for v in lengths}
            if len(values) != 1 or not next(iter(values)).isdigit():
                self.refuse(400, "a request with a bad Content-Length")
                return None
            n = int(values.pop())
            data = self._read_exactly(n)
            if data is None:
                return None
            return data, data
        return b"", b""

    def _read_exactly(self, n):
        chunks, left = [], n
        try:
            while left:
                piece = self.rfile.read(min(left, CHUNK))
                if not piece:
                    break
                chunks.append(piece)
                left -= len(piece)
        except OSError:
            pass
        if left:
            self.recorder.silence("did not relay a request: its body ended %d bytes short" % left, self.command,
                                  self._path_only())
            self.close_connection = True
            return None
        return b"".join(chunks)

    def _read_chunked(self):
        raw, body = bytearray(), bytearray()
        try:
            while True:
                line = self.rfile.readline(1024)
                raw += line
                size_text = line.split(b";", 1)[0].strip()
                if not line.endswith(b"\n") or not size_text or any(c not in b"0123456789abcdefABCDEF"
                                                                  for c in size_text):
                    raise ValueError("bad chunk size line")
                size = int(size_text, 16)
                if size == 0:
                    while True:  # trailers, up to the empty line
                        trailer = self.rfile.readline(8192)
                        raw += trailer
                        if trailer in (b"\r\n", b"\n"):
                            return bytes(raw), bytes(body)
                        if not trailer.endswith(b"\n"):
                            raise ValueError("bad trailer")
                piece = self.rfile.read(size + 2)
                if len(piece) != size + 2:
                    raise ValueError("short chunk")
                raw += piece
                body += piece[:size]
        except (OSError, ValueError):
            self.recorder.silence("did not relay a request: its chunked body cannot be read", self.command,
                                  self._path_only())
            self.close_connection = True
            return None

    def relay(self):
        if "close" in connection_tokens(self.headers.get_all("Connection") or []):
            self.close_connection = True  # "Connection: close, X" too, not only a lone "close"
        if not self.path.startswith("/"):
            self.refuse(400, "a target that is not a path (an absolute URL or authority form)")
            return
        got = self._read_body()
        if got is None:
            return
        raw, body = got
        method, path = self.command, self._path_only()
        api = api_of(path)
        if method == "POST":
            self._read_request(api, path, body)
        try:
            conn = self.upstream.connection()
            conn.putrequest(method, self.upstream.target(self.path), skip_host=True, skip_accept_encoding=True)
            self._relay_request_headers(conn)
            conn.endheaders()
            if raw:
                conn.send(raw)
            response = conn.getresponse()
        except Exception as exc:
            timeout = isinstance(exc, (TimeoutError, socket.timeout))
            self.recorder.silence("upstream failed before an answer: %s; the agent gets %d" % (
                describe_error(exc), 504 if timeout else 502), method, path)
            self._reply(504 if timeout else 502, "raqib proxy: the upstream %s did not answer (%s)\n" % (
                self.upstream.url, describe_error(exc)))
            return
        try:
            self._relay_response(conn, response, api, method, path)
        finally:
            conn.close()

    def _read_request(self, api, path, body):
        """Posts for the tool results of a request, before it is relayed."""
        if api in (OPENAI, ANTHROPIC):
            try:
                parsed = json.loads(decode_body(body, self.headers.get("Content-Encoding")).decode("utf-8"))
            except (Unreadable, ValueError, UnicodeDecodeError) as exc:
                why = str(exc) if isinstance(exc, Unreadable) else "the body is not JSON"
                self.recorder.silence("did not read a request (%s): its tool results are not recorded" % why,
                                      "POST", path)
                return
            results, history = request_results(api, parsed)
            self.recorder.posts(results, history)
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

    def _relay_response(self, conn, response, api, method, path):
        status = response.status
        no_body = method == "HEAD" or status in (204, 304) or 100 <= status < 200
        chunked_in = bool(response.chunked) and not no_body
        chunked_out = chunked_in and self.request_version != "HTTP/1.0"
        until_close = not no_body and not chunked_in and response.length is None
        named = connection_tokens(response.msg.get_all("Connection") or [])
        reader = None
        if api in (OPENAI, ANTHROPIC) and 200 <= status < 300 and not no_body:
            reader = ResponseReader(api, response.msg.get("Content-Type"), response.msg.get("Content-Encoding"))
        try:
            self.send_response_only(status, response.reason)
            for name, value in response.msg.items():
                lower = name.lower()
                if lower == "transfer-encoding":
                    if chunked_out:
                        self.send_header(name, value)
                    elif not chunked_in:
                        until_close = True  # a transfer coding the proxy does not undo: relayed as it came
                        self.send_header(name, value)
                    continue
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
        failure = None
        if not no_body:
            failure = self._relay_body(response, reader, chunked_out)
        if reader is not None and reader.unread and failure is None:
            self.recorder.silence("did not read an answer (%s): its tool calls are not recorded" % reader.unread,
                                  method, path)
        if failure is not None:
            self.close_connection = True
            self.recorder.silence("upstream failed during the answer (status %d already sent): %s" % (
                status, failure), method, path)
        elif status >= 500:
            self.recorder.silence("upstream answered %d; relayed unchanged" % status, method, path)

    def _relay_body(self, response, reader, chunked_out):
        """Relay the body piece by piece as it arrives. The calls a piece
        completes are recorded before the piece is passed on, and the calls
        of a whole body before its last byte (or its end) is. The failure
        text of the upstream, or None."""
        sized = response.length is not None
        finished = []

        def finish():
            if reader is not None and not finished:
                finished.append(True)
                self.recorder.pres(reader.finish())

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
                    return describe_error(exc)
                if not data:
                    break
                if reader is not None:
                    self.recorder.pres(reader.feed(data))
                    if sized and response.length == 0:
                        finish()
                send(data)
                if sized and response.length == 0:
                    break
            if sized and response.length:
                return "the answer ended %d bytes short" % response.length
            finish()
            if chunked_out:
                send_end = b"0\r\n\r\n"
                try:
                    self.wfile.write(send_end)
                except OSError:
                    raise _ClientGone()
        except _ClientGone:
            self.close_connection = True  # the agent went away; nothing more is read or relayed
        return None


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


def session_id(now=None, pid=None):
    """One session per proxy run: proxy-<UTC start>-<pid>."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return "proxy-%s-%d" % (now.strftime("%Y%m%dT%H%M%SZ"), os.getpid() if pid is None else pid)


def check_log(path):
    """The trace must be writable before the proxy starts (A3)."""
    try:
        with open(path, "a", encoding="utf-8"):
            pass
    except OSError as exc:
        raise UsageError("cannot write the trace %s: %s" % (path, exc.strerror or exc))


def run(listen, upstream, log, allow_plain=False, out=None, err=None):
    """The `proxy` command: serve until interrupted. Exit 0 on Ctrl-C."""
    out = out or sys.stdout
    address = parse_listen(listen)
    target = parse_upstream(upstream, allow_plain)
    log = os.path.abspath(log)
    check_log(log)
    recorder = Recorder(log, session_id(), err=err)
    try:
        server = make_server(address, target, recorder)
    except OSError as exc:
        raise UsageError("cannot listen on %s: %s" % (listen, exc.strerror or exc))
    out.write("raqib: proxy http://127.0.0.1:%d/ -> %s (trace %s, session %s; Ctrl-C to stop)\n" % (
        server.server_address[1], target.url, log, recorder.session_id))
    out.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
