"""The rig's scripted model (probe): an OpenAI chat-completions endpoint on the runner itself that answers a real
agent with a fixed list of shell commands, one tool call a turn, then a last word. The agent is real; what it is
asked to do is fixed and known. It holds no key, asks no model and reaches nothing: it only answers the agent.

    python tools/rig/model.py --port 8790 --log MODEL.log [--host 0.0.0.0]
"""
import argparse
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT = [
    "curl -s --max-time 20 --limit-rate 2000 --output rig.bin https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe",
    "curl -s --max-time 10 https://example.com/",
    "whoami",
]
SHELL = re.compile(r"shell|bash|command|terminal|exec", re.I)
LOCK = threading.Lock()
LOG = None


def log(obj):
    with LOCK:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, sort_keys=True) + "\n")


def shell_tool(tools):
    """(name, the command's parameter, the other required parameters with a filler) of the agent's shell tool."""
    for t in tools or ():
        fn = t.get("function") if isinstance(t, dict) else None
        if not isinstance(fn, dict) or not SHELL.search(str(fn.get("name"))):
            continue
        params = fn.get("parameters") if isinstance(fn.get("parameters"), dict) else {}
        props = params.get("properties") if isinstance(params.get("properties"), dict) else {}
        key = next((k for k in ("command", "cmd", "script", "input") if k in props), None)
        if key is None:
            continue
        fill = {}
        for name in params.get("required") or ():
            if name == key:
                continue
            kind = (props.get(name) or {}).get("type")
            fill[name] = {"boolean": False, "number": 0, "integer": 0, "array": [], "object": {}}.get(kind, "rig")
        return fn["name"], key, fill
    return None


def answer(body):
    messages = body.get("messages") or []
    step = sum(1 for m in messages if isinstance(m, dict) and m.get("role") == "tool")
    tools = body.get("tools") or []
    names = [((t.get("function") or {}).get("name")) for t in tools if isinstance(t, dict)]
    tool = shell_tool(tools)
    if tool is None or step >= len(SCRIPT):
        text = "rig: done" if tool is not None else ('{"next_speaker": "user", "reasoning": "rig"}' if not tools else
                                                    "rig: no shell tool")
        log({"step": step, "tools": names, "reply": text})
        return {"content": text}
    name, key, fill = tool
    args = dict(fill, **{key: SCRIPT[step]})
    log({"step": step, "tools": names, "tool": name, "args": args})
    return {"tool": name, "args": json.dumps(args), "id": "call_rig_%d" % step}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        log({"get": self.path})
        self._json(200, {"object": "list", "data": [{"id": "rig-model", "object": "model", "owned_by": "rig"}]})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        try:
            body = json.loads(raw)
        except ValueError:
            body = {}
        log({"post": self.path, "stream": bool(body.get("stream")), "model": body.get("model"), "bytes": n})
        if not self.path.rstrip("/").endswith("chat/completions"):
            return self._json(404, {"error": {"message": "the rig's model speaks chat/completions only"}})
        got = answer(body)
        base = {"id": "chatcmpl-rig", "created": int(time.time()), "model": body.get("model") or "rig-model"}
        if "tool" in got:
            call = {"id": got["id"], "type": "function", "function": {"name": got["tool"], "arguments": got["args"]}}
            message, finish = {"role": "assistant", "content": None, "tool_calls": [call]}, "tool_calls"
            delta = {"role": "assistant", "content": None, "tool_calls": [dict(call, index=0)]}
        else:
            message, finish = {"role": "assistant", "content": got["content"]}, "stop"
            delta = dict(message)
        usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        if not body.get("stream"):
            return self._json(200, dict(base, object="chat.completion", usage=usage,
                                        choices=[{"index": 0, "message": message, "finish_reason": finish}]))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        chunks = [dict(base, object="chat.completion.chunk", choices=[{"index": 0, "delta": delta, "finish_reason": None}]),
                  dict(base, object="chat.completion.chunk", choices=[{"index": 0, "delta": {}, "finish_reason": finish}]),
                  dict(base, object="chat.completion.chunk", choices=[], usage=usage)]
        for c in chunks:
            self.wfile.write(("data: %s\n\n" % json.dumps(c)).encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


def main(argv=None):
    global LOG
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8790)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--log", required=True)
    a = p.parse_args(argv)
    LOG = a.log
    log({"listening": "%s:%d" % (a.host, a.port)})
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
