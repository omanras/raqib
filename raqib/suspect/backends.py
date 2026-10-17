"""Suspicion backends (M2.1). Each has .name, .model and
.judge(system, user, schema) -> parsed JSON answer, raising BackendError.

- ollama     local model over HTTP (stdlib urllib, no proxy); the ADR default.
- anthropic  Claude through the official `anthropic` SDK. It is imported only
             here and only when this backend is chosen, so raqib stays
             stdlib-only (A-7, ADR-0001 B-3). Output is forced with structured
             outputs (output_config.format). Server-side fallback is off by
             default, so a refusal is an error line; allow_fallback
             (--allow-fallback) opts in to fallbacks: "default", and an answer
             from another model is then labelled and counted (B-5).
- fake       canned answers from a JSON file, for tests and dry runs.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from raqib.suspect.core import BackendError

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3.1:8b"
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5"
DEFAULT_EFFORT = "high"
EFFORTS = ("low", "medium", "high", "xhigh", "max")
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class OllamaBackend:
    name = "ollama"

    def __init__(self, model=None, url=None, timeout=300):
        self.model = model or DEFAULT_OLLAMA_MODEL
        self.url = (url or os.environ.get("OLLAMA_HOST") or DEFAULT_OLLAMA_URL).rstrip("/")
        if "://" not in self.url:
            self.url = "http://" + self.url
        self.timeout = timeout
        host = urllib.parse.urlsplit(self.url).hostname or ""
        # Not on this machine: trace metadata leaves it, over plain HTTP if
        # the URL says so. The CLI says this on stderr.
        self.remote = host not in ("localhost", "127.0.0.1", "::1")
        # A local model must never be reached through an HTTP proxy.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def judge(self, system, user, schema):
        body = {
            "model": self.model,
            "stream": False,
            "format": schema,
            "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        request = urllib.request.Request(
            self.url + "/api/chat", data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise BackendError("ollama answered HTTP %d" % exc.code)
        except (urllib.error.URLError, OSError) as exc:
            raise BackendError("ollama unreachable at %s: %s" % (self.url, exc))
        except ValueError:
            raise BackendError("ollama answered something that is not JSON")
        content = (data.get("message") or {}).get("content") if isinstance(data, dict) else None
        if not isinstance(content, str):
            raise BackendError("ollama answer has no message.content")
        try:
            return json.loads(content)
        except ValueError:
            raise BackendError("ollama message.content is not JSON")


class AnthropicBackend:
    name = "anthropic"

    def __init__(self, model=None, effort=DEFAULT_EFFORT, client=None, allow_fallback=False):
        if effort not in EFFORTS:
            raise ValueError("effort must be one of %s" % ", ".join(EFFORTS))
        self.model = model or DEFAULT_ANTHROPIC_MODEL
        self.effort = effort
        self.allow_fallback = allow_fallback is True
        self._client = client
        self.last_model = None  # the model that answered the last call (response.model)

    @staticmethod
    def _sdk():
        try:
            import anthropic
        except ImportError:
            raise BackendError("the anthropic backend needs the official SDK: pip install anthropic")
        return anthropic

    def judge(self, system, user, schema):
        anthropic = self._sdk()
        try:
            client = self._client or anthropic.Anthropic(max_retries=2)
        except Exception as exc:
            raise BackendError("anthropic: cannot create a client: %s: %s" % (type(exc).__name__, exc))
        self._client = client
        # A watcher must know which model judged (B-5): no other model may
        # answer unless the caller opted in.
        fallback = {"betas": [FALLBACK_BETA], "fallbacks": "default"} if self.allow_fallback else {}
        try:
            response = client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"effort": self.effort,
                               "format": {"type": "json_schema", "schema": schema}},
                **fallback,
            )
        except anthropic.AuthenticationError:
            raise BackendError("anthropic: authentication failed (check ANTHROPIC_API_KEY)")
        except anthropic.RateLimitError:
            raise BackendError("anthropic: rate limited (429)")
        except anthropic.APIStatusError as exc:
            raise BackendError("anthropic: HTTP %s" % exc.status_code)
        except anthropic.APIConnectionError:
            raise BackendError("anthropic: connection failed")
        except TypeError as exc:
            # The SDK raises TypeError while building the request when it
            # finds no API key, auth token or other credentials.
            if "authentication" in str(exc):
                raise BackendError("anthropic: no credentials (set ANTHROPIC_API_KEY)")
            raise BackendError("anthropic: TypeError: %s" % exc)
        except Exception as exc:
            raise BackendError("anthropic: %s: %s" % (type(exc).__name__, exc))
        self.last_model = getattr(response, "model", None)
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise BackendError("anthropic: refused (category %s)" % (category or "none"))
        if response.stop_reason == "max_tokens":
            raise BackendError("anthropic: answer cut off at max_tokens")
        text = next((b.text for b in response.content if getattr(b, "type", None) == "text"), None)
        if text is None:
            raise BackendError("anthropic: answer has no text block")
        try:
            return json.loads(text)
        except ValueError:
            raise BackendError("anthropic: answer is not JSON")


class FakeBackend:
    """Canned answers: {"<session_id>:<first>-<last>" or "<session_id>" or "*": answer}.
    An answer may be {"error": "..."} to simulate a backend failure."""

    name = "fake"

    def __init__(self, answers, model="canned"):
        if not isinstance(answers, dict):
            raise ValueError("fake answers must be a JSON object")
        self.answers = answers
        self.model = model

    @classmethod
    def from_file(cls, path):
        try:
            with open(path, encoding="utf-8") as f:
                return cls(json.load(f))
        except (OSError, ValueError) as exc:
            raise ValueError("cannot read fake answers %s: %s" % (path, exc))

    def judge(self, system, user, schema):
        session, first, last = _window_of(user)
        for key in ("%s:%d-%d" % (session, first, last), session, "*"):
            if key in self.answers:
                answer = self.answers[key]
                if isinstance(answer, dict) and set(answer) == {"error"}:
                    raise BackendError("fake: %s" % answer["error"])
                return answer
        raise BackendError("fake: no canned answer for %s:%d-%d" % (session, first, last))


def _window_of(user):
    """(session_id, first seq, last seq) of a rendered window:
    "Window of seq A to B (N lines).", then <session>, its JSON, </session>."""
    head, tag, session_json = user.split("\n", 3)[:3]
    if tag != "<session>":
        raise BackendError("fake: cannot read the window header")
    first, rest = head[len("Window of seq "):].split(" to ", 1)
    return json.loads(session_json)["session_id"], int(first), int(rest.split(" ", 1)[0])


def make_backend(name, model=None, ollama_url=None, effort=DEFAULT_EFFORT, answers=None,
                 allow_fallback=False):
    if allow_fallback and name != "anthropic":
        raise ValueError("--allow-fallback applies to the anthropic backend only")
    if name == "ollama":
        return OllamaBackend(model=model, url=ollama_url)
    if name == "anthropic":
        return AnthropicBackend(model=model, effort=effort, allow_fallback=allow_fallback)
    if name == "fake":
        if not answers:
            raise ValueError("the fake backend needs --answers FILE")
        return FakeBackend.from_file(answers)
    raise ValueError("unknown backend %r (ollama, anthropic, fake)" % (name,))
