"""The rig's stand-in HTTP collector (ADR-0011 J-14): loopback only, in the shape of an HTTP event collector
(Splunk's HEC: a body of JSON envelopes, `Authorization: Splunk <token>`, an answer {"text", "code"}), or in
raqib's own shape (application/x-ndjson, the lines as the file holds them). It checks the token, read from its
token file at every request, and can be told to refuse (400 to a batch that holds a named id, as HEC answers a
bad event), to fail (an answer of a given status to the next N requests, or no answer at all), to redirect and
to be late; given a certificate it answers over https. It keeps every request it took and every event in the
order it took them. Stdlib only; no part of raqib.

    python tools/rig/collector.py --port N --token-file FILE --out FILE [--shape hec|raqib] [--fail N]
                                  [--fail-status S] [--late S] [--refuse ID ...] [--for S]

As a module: Collector(...).start() -> port; .events (the event lines it took, ASCII text); .requests; .stop().
"""
import argparse
import http.server
import json
import ssl
import sys
import threading

HOST = "127.0.0.1"   # loopback only (J-14)
OK = {"text": "Success", "code": 0}


class Collector:
    def __init__(self, token_file=None, shape="hec", refuse=(), fail=0, fail_status=503, late=0.0, code=0,
                 redirect=False, port=0, out=None, cert=None, key=None):
        self.token_file, self.shape, self.refuse = token_file, shape, set(refuse)
        self.fail, self.fail_status, self.late, self.code, self.redirect = fail, fail_status, late, code, redirect
        self.port, self.out, self.cert, self.key = port, out, cert, key
        self.events, self.requests, self.lock, self.quit = [], [], threading.Lock(), threading.Event()
        self.server = self.thread = None

    def token(self):
        if self.token_file is None:
            return None
        with open(self.token_file, "rb") as f:
            return f.read().strip().decode("ascii")

    def judge(self, headers, body):
        """(status, answer body, [event line]) of one request."""
        token = self.token()
        given = headers.get("Authorization")
        prefix = "Splunk " if self.shape == "hec" else "Bearer "
        if token is not None and given is None:
            return 401, {"text": "Token is required", "code": 2}, []
        if token is not None and given != prefix + token:
            return 403, {"text": "Invalid token", "code": 4}, []
        lines = []
        try:
            text = body.decode("ascii")
            if self.shape == "hec":
                dec, at = json.JSONDecoder(), 0
                while text[at:].strip():
                    while text[at] in " \r\n\t":
                        at += 1
                    env, at = dec.raw_decode(text, at)
                    if sorted(env) != ["event", "host", "source", "sourcetype", "time"] or env["source"] != "raqib" \
                            or env["sourcetype"] != "raqib:event" or env["host"] != env["event"]["watch"]["host"]:
                        raise ValueError("not raqib's envelope")
                    lines.append(json.dumps(env["event"], sort_keys=True, separators=(",", ":")))
            else:
                if not text.endswith("\n"):
                    raise ValueError("not whole lines")
                lines = [json.dumps(json.loads(x), sort_keys=True, separators=(",", ":")) for x in
                         text.split("\n")[:-1]]
        except (UnicodeDecodeError, ValueError, KeyError, TypeError, IndexError):
            return 400, {"text": "Invalid data format", "code": 6}, []
        for i, x in enumerate(lines):
            if json.loads(x).get("id") in self.refuse:
                return 400, {"text": "Invalid data format", "code": 6, "invalid-event-number": i}, []
        return 200, dict(OK, code=self.code), lines

    def start(self):
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                with owner.lock:
                    failing = owner.fail > 0
                    if failing:
                        owner.fail -= 1
                if owner.late and owner.quit.wait(owner.late):
                    return
                if owner.redirect:
                    status, answer, lines = 302, {"text": "moved", "code": 0}, []
                elif failing and owner.fail_status is None:   # no answer at all
                    owner.requests.append({"headers": dict(self.headers), "body": body, "status": None})
                    self.close_connection = True
                    return
                elif failing:
                    status, answer, lines = owner.fail_status, {"text": "Server is busy", "code": 9}, []
                else:
                    status, answer, lines = owner.judge(self.headers, body)
                with owner.lock:
                    owner.requests.append({"headers": dict(self.headers), "body": body, "status": status})
                    owner.events.extend(lines)
                    if owner.out and lines:
                        with open(owner.out, "a", encoding="ascii") as f:
                            f.write("".join(x + "\n" for x in lines))
                data = json.dumps(answer).encode("ascii")
                try:   # a sender gone before its answer (the rig's X21 kills one)
                    self.send_response(status)
                    if status == 302:
                        self.send_header("Location", "http://%s:%d/elsewhere" % (HOST, owner.server.server_port))
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    self.close_connection = True

        self.server = http.server.ThreadingHTTPServer((HOST, self.port), Handler)
        self.server.daemon_threads = True
        if self.cert:   # https: the tests' own certificate, made where the machine has openssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.cert, self.key)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05})
        self.thread.start()
        return self.port

    def stop(self):
        self.quit.set()
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join()
            self.server = None


def main(argv=None):
    p = argparse.ArgumentParser(prog="tools/rig/collector.py")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--token-file")
    p.add_argument("--out", required=True)
    p.add_argument("--shape", choices=("hec", "raqib"), default="hec")
    p.add_argument("--fail", type=int, default=0)
    p.add_argument("--fail-status", type=int, default=503)
    p.add_argument("--late", type=float, default=0.0)
    p.add_argument("--refuse", nargs="*", default=())
    p.add_argument("--for", dest="seconds", type=float, default=600.0)
    a = p.parse_args(argv)
    c = Collector(a.token_file, a.shape, a.refuse, a.fail, a.fail_status, a.late, port=a.port, out=a.out)
    port = c.start()
    print("COLLECTOR %s:%d" % (HOST, port), flush=True)
    try:
        c.quit.wait(a.seconds)
    except KeyboardInterrupt:
        pass
    finally:
        c.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
