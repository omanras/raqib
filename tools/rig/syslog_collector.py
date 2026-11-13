"""The rig's stand-in syslog collector (ADR-0011 J-6, J-14): loopback only, over udp and over tcp at once (a port
of each, both bound by it). Over tcp it reads frames as RFC 6587 says - octet counting ("<length> <message>")
or a newline after each message, told apart by each frame's first byte (a digit is a count) or fixed by
`framing` - and over udp each datagram is one message. It holds every message to the shape J-6 rules for
raqib's (RFC 5424: <PRI>1 TIMESTAMP HOSTNAME raqib - MSGID - MSG; the PRI the facility times 8 plus the event's
severity, high 2, medium 4, low 5, a hole 4, none and info 6; the TIMESTAMP the event's time; the HOSTNAME its
watch.host; the MSGID its kind; the MSG one event line) and keeps a problem for each one that is not. The
severity map is written here again, not imported: the stand-in is no part of raqib. It can be made down (its
tcp port bound, nothing listening) and then brought up on that port. It keeps the event lines it took in the
order they came, per transport. Stdlib only.

    python tools/rig/syslog_collector.py --out FILE [--tcp-port N] [--udp-port N] [--facility N]
                                         [--framing octet|newline] [--for S]

As a module: SyslogCollector(...).start() -> (tcp port, udp port); .events["tcp"], .events["udp"] (the event
lines, ASCII text, keys sorted); .problems; .connections; .framings; .up(); .stop().
"""
import argparse
import json
import re
import socket
import sys
import threading

HOST = "127.0.0.1"   # loopback only (J-14)
HEADER = re.compile(rb"<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) - (.*)\Z", re.S)
PRINTUS = re.compile(r"[\x21-\x7e]+\Z")
SEVERITY = {"high": 2, "medium": 4, "low": 5, "hole": 4, "none": 6, "info": 6}   # J-6
COUNT_MAX = 10   # the digits of an octet count the stand-in reads before it calls the frame broken
RCVBUF = 8 * 1024 * 1024


def field(value, most):
    return value if isinstance(value, str) and len(value) <= most and PRINTUS.match(value) else "-"


class SyslogCollector:
    def __init__(self, facility=13, framing=None, tcp_port=0, udp_port=0, out=None, down=False):
        self.facility, self.framing, self.out, self.down = facility, framing, out, down
        self.tcp_port, self.udp_port = tcp_port, udp_port
        self.events = {"tcp": [], "udp": []}
        self.problems, self.framings, self.connections, self.messages = [], set(), 0, 0
        self.lock, self.quit = threading.Lock(), threading.Event()
        self.tcp = self.udp = None
        self.threads = []

    # --- one message -----------------------------------------------------------------------------------------
    def check(self, msg):
        """(the event line, keys sorted, or None; the problem or None) of one message."""
        m = HEADER.match(msg)
        if not m:
            return None, "not RFC 5424 with no structured data: %r" % msg[:60]
        pri, stamp, host, app, procid, msgid, body = m.groups()
        try:
            e = json.loads(body.decode("ascii"))
            if not isinstance(e, dict):
                raise ValueError("not an object")
            line = json.dumps(e, sort_keys=True, separators=(",", ":"))
        except (UnicodeDecodeError, ValueError) as exc:
            return None, "the MSG is not one JSON line (%s)" % type(exc).__name__
        watch = e.get("watch") if isinstance(e.get("watch"), dict) else {}
        want = {"PRI": b"%d" % (self.facility * 8 + SEVERITY.get(e.get("severity"), 4)),
                "TIMESTAMP": (e.get("time") or "-").encode("ascii", "replace"),
                "HOSTNAME": field(watch.get("host"), 255).encode("ascii"), "APP-NAME": b"raqib", "PROCID": b"-",
                "MSGID": field(e.get("kind"), 32).encode("ascii")}
        got = {"PRI": pri, "TIMESTAMP": stamp, "HOSTNAME": host, "APP-NAME": app, "PROCID": procid, "MSGID": msgid}
        wrong = [k for k in want if want[k] != got[k]]
        return line, ("%s of %s not as J-6 rules" % (", ".join(wrong), e.get("id")) if wrong else None)

    def take(self, transport, msg, framing):
        line, problem = self.check(msg)
        with self.lock:
            self.messages += 1
            self.framings.add(framing)
            if line is not None:
                self.events[transport].append(line)
                if self.out:
                    with open(self.out, "a", encoding="ascii") as f:
                        f.write(line + "\n")
            if problem:
                self.problems.append("%s: %s" % (transport, problem))

    def frames(self, buf):
        """Takes every whole frame at the head of buf; returns what is left (a frame not yet whole), or None where
        the stream is broken."""
        while buf:
            octet = self.framing == "octet" or self.framing is None and buf[:1].isdigit()
            if octet:
                i = buf.find(b" ")
                if i < 0:
                    return buf if len(buf) <= COUNT_MAX and buf.isdigit() else None
                if not buf[:i].isdigit() or i > COUNT_MAX:
                    return None
                n = int(buf[:i])
                if len(buf) < i + 1 + n:
                    return buf
                self.take("tcp", buf[i + 1:i + 1 + n], "octet")
                buf = buf[i + 1 + n:]
            else:
                j = buf.find(b"\n")
                if j < 0:
                    return buf
                self.take("tcp", buf[:j], "newline")
                buf = buf[j + 1:]
        return buf

    # --- the wires -------------------------------------------------------------------------------------------
    # Stop drains: each loop ends only at a wait with nothing to take after Stop, so whatever a sender handed to the
    # system before Stop (a connection still in the backlog, bytes or datagrams not yet read) is taken.
    def serve_tcp(self):
        while True:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                if self.quit.is_set():
                    break
                continue
            with self.lock:
                self.connections += 1
            t = threading.Thread(target=self.read, args=(conn,), name="rig-syslog-conn", daemon=True)
            self.threads.append(t)
            t.start()

    def read(self, conn):
        buf = b""
        conn.settimeout(0.05)
        try:
            while True:
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    if self.quit.is_set():
                        break
                    continue
                except OSError:
                    break
                if not data:
                    break
                buf = self.frames(buf + data)
                if buf is None:
                    with self.lock:
                        self.problems.append("tcp: a frame that is neither an octet count nor a line")
                    break
            if buf:
                with self.lock:
                    self.problems.append("tcp: a frame cut at the connection's end (%d byte(s))" % len(buf))
        finally:
            conn.close()

    def serve_udp(self):
        while True:
            try:
                data, _ = self.udp.recvfrom(65535)
            except socket.timeout:
                if self.quit.is_set():
                    break
                continue
            except OSError:   # Windows: an ICMP answer to another datagram; or the socket closed at stop
                if self.quit.is_set():
                    break
                continue
            self.take("udp", data, "datagram")

    def start(self):
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind((HOST, self.tcp_port))   # bound from here: held while it is down
        self.tcp.settimeout(0.05)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
        except OSError:
            pass
        self.udp.bind((HOST, self.udp_port))
        self.udp.settimeout(0.05)
        self.tcp_port, self.udp_port = self.tcp.getsockname()[1], self.udp.getsockname()[1]
        t = threading.Thread(target=self.serve_udp, name="rig-syslog-udp", daemon=True)
        self.threads.append(t)
        t.start()
        if not self.down:
            self.up()
        return self.tcp_port, self.udp_port

    def up(self):
        """Listen on the tcp port it bound, and read."""
        self.down = False
        self.tcp.listen(16)
        t = threading.Thread(target=self.serve_tcp, name="rig-syslog-tcp", daemon=True)
        self.threads.append(t)
        t.start()

    def stop(self):
        """Stop: what was sent before it is drained (above), then every thread is joined and both sockets closed."""
        self.quit.set()
        for t in list(self.threads):   # the udp and the accept loops first: they start no thread after they end
            if t.name != "rig-syslog-conn":
                t.join(30)
        for t in list(self.threads):
            t.join(30)
        for s in (self.tcp, self.udp):
            if s is not None:
                s.close()
        self.tcp = self.udp = None


def main(argv=None):
    p = argparse.ArgumentParser(prog="tools/rig/syslog_collector.py")
    p.add_argument("--tcp-port", type=int, default=0)
    p.add_argument("--udp-port", type=int, default=0)
    p.add_argument("--facility", type=int, default=13)
    p.add_argument("--framing", choices=("octet", "newline"))
    p.add_argument("--out", required=True)
    p.add_argument("--for", dest="seconds", type=float, default=600.0)
    a = p.parse_args(argv)
    c = SyslogCollector(a.facility, a.framing, a.tcp_port, a.udp_port, out=a.out)
    tcp, udp = c.start()
    print("SYSLOG %s tcp %d udp %d" % (HOST, tcp, udp), flush=True)
    try:
        c.quit.wait(a.seconds)
    except KeyboardInterrupt:
        pass
    finally:
        c.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
