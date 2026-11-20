"""The rig's claims of siem/ (ADR-0017 S-2 and Amendment A, M16.1 and its REDO), against a search engine on this
machine's own port. It installs siem/<engine>/'s pipeline and template and feeds them:
  - the examples of docs/specs/EVENT.md and a real watch's events file (its whole lines);
  - made-up events of each class the Sigma rules and the searches name, and a near miss for each (MADE);
  - the made-up hosts of the Table's measurement for silence and for the runs with no end (SILENCE_HOSTS), read
    at once and after waits;
  - each odd line of Amendment A's SA-5 with a line after it (ODD), and two documents with a shipper's own fields.
Then it prints one row a claim, MET or MISSED with its numbers, what was fed and the tools' versions:
  X39 no line refused by the engine: each line an event or an error document as check_of() below says, and the
      line after each odd line kept;
  X40 every field the Mapping names holds the value ecs_of() computes from the event, for every event line;
      event.ingested between the runner's clock before and after the send; a shipper's own fields kept;
  X41 each search of siem/<engine>/searches counts what a count made here from the fed lines says (the silence
      and the runs with no end by the runner's own send times, never by the engine's numbers);
  X42 each Sigma rule of siem/sigma/rules, converted by sigma-cli with siem/sigma/pipeline-ecs.yml, counts what a
      count made here says, matches at least one line, and passes over each of its near misses.
A MISSED claim is reported and does not fail the job (ADR-0012): the exit is 0 unless the usage is wrong (2). An
engine that did not answer, or a sigma-cli that is not there, is said as n/a with its reason, never as MET.
It talks to the engine's URL only (default http://127.0.0.1:9200) and runs sigma-cli on this machine; nothing is
sent off it. Standard library and raqib's own YAML reader only; raqib never imports it.

    python tools/rig/siem_run.py docs/specs/EVENT.md ~/.raqib/host/events.jsonl [--url URL] [--wait S]
                                 [--sigma PATH] [--summary FILE]"""
import argparse
import calendar
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from raqib.rules import yamlite  # noqa: E402

SIEM = os.path.join(ROOT, "siem")
SPEC = os.path.join(ROOT, "docs", "specs", "EVENT.md")
EXAMPLE = re.compile(r"^```json\n(.+?)\n```", re.M)
INSTANT = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)\Z")
INDEX, ODD_INDEX, SILENCE_INDEX = "raqib-events-rig", "raqib-events-rig-odd", "raqib-events-rig-silence"
PIPELINE_ID, TEMPLATE_ID = "raqib-event-1", "raqib-events"
SEVERITY = {"high": 4, "medium": 3, "low": 2, "info": 1, "hole": 3}
KINDS = ("finding", "source-finding", "note", "tree", "hole", "knock", "heartbeat", "watch")
BASE = ("schema", "id", "n", "time", "kind", "about", "rev", "severity", "watch")
WATCH_BASE = ("run", "host", "beat")
# the bounds of SA-5 (the pipeline holds the same numbers)
MAX_DEPTH, MAX_TEXT, MAX_KEYS, MAX_UNKNOWN = 10, 8000, 200, 50
LONG = 2 ** 63
# a key's type in EVENT.md's Keys table -> the code the pipeline checks it by (None: not checked)
CODE = {"str": "s", "instant": "s", "link": "s", "int": "i", "pos": "p", "count": "c", "bool": "b",
        "number": "f", "object": "o", "ids": "S"}
CHECKED_PARTS = {"watch": None, "rule": None, "subject": ("pid", "image")}   # None: every key of the part
NAMED = ("@timestamp", "event.id", "event.action", "event.severity", "event.kind", "message", "host.name",
         "observer.product", "observer.version", "rule.id", "rule.category", "threat.technique.id",
         "process.pid", "process.name")
CLAIMS = ((39, "no line refused by the engine, each an event or an error document as the count here says"),
          (40, "every field the Mapping names holds the value the event holds"),
          (41, "each search counts what a count made here says"),
          (42, "each Sigma rule, converted by sigma-cli, counts what a count made here says"))
SHIPPER = {"host": {"hostname": "shipper.example", "ip": "192.0.2.7", "name": "shipper.example"},
           "agent": {"type": "filebeat"}, "log": {"offset": 7}}

# made-up events: label -> (the example it is made from, what is changed); POSITIVE and NEAR say which rule each
# is for (MISS: a near miss, matching nothing new)
RULE = {"DESTRUCT-CMD": ("DESTRUCT", "signature", ["T1485"]), "PERSIST-RUN-KEY": ("PERSIST", "signature",
        ["T1547.001"]), "SECRET-OUTPUT": ("SECRET", "signature", ["T1552"]), "NET-ADMIN-PORT": ("NET", "signature",
        ["T1021"]), "NEW-AGENT-UNKNOWN": ("HOST", "anchor", ["T1059"]), "NEW-AGENT": ("HOST", "anchor", ["T1059"]),
        "EDIT-NO-TEST": ("DRIFT", "demand", [])}
MADE = (
    ("destruct", "source-finding: settled", {"rule": "DESTRUCT-CMD", "alarm": True}),
    ("persist", "source-finding: settled", {"rule": "PERSIST-RUN-KEY", "alarm": True}),
    ("secret", "source-finding: settled", {"rule": "SECRET-OUTPUT", "alarm": True}),
    ("net", "finding", {"rule": "NET-ADMIN-PORT", "alarm": True}),
    ("unnamed", "finding", {"rule": "NEW-AGENT-UNKNOWN", "alarm": True}),
    ("incomplete", "watch end", {"result": {"exit": 3, "word": "INCOMPLETE"}}),
    ("not-watching", "heartbeat", {"state": "CAPTURE FAILED"}),
    ("drift", "source-finding: settled", {"rule": "EDIT-NO-TEST", "alarm": False}),
    ("named-agent", "finding", {"rule": "NEW-AGENT", "alarm": True}),
    ("heartbeat-incomplete", "heartbeat", {"state": "WATCHING", "result": {"exit": 3, "word": "INCOMPLETE"}}),
    ("watch-clean", "watch end", {"result": {"exit": 0, "word": "CLEAN"}}),
    ("knock-persist", "knock", {"knocked.event": "PERSIST-RUN-KEY"}),
)
POSITIVE = {"raqib_alarm.yml": "destruct", "raqib_persist.yml": "persist", "raqib_network.yml": "net",
            "raqib_destruction.yml": "destruct", "raqib_secret.yml": "secret", "raqib_unnamed_agent.yml": "unnamed",
            "raqib_watch_incomplete.yml": "incomplete", "raqib_heartbeat_not_watching.yml": "not-watching",
            "raqib_hole.yml": None}
NEAR = {"raqib_alarm.yml": ["drift"], "raqib_hole.yml": ["knock-persist"],
        "raqib_persist.yml": ["knock-persist", "drift"], "raqib_network.yml": ["drift"],
        "raqib_destruction.yml": ["drift"], "raqib_secret.yml": ["drift"], "raqib_unnamed_agent.yml": ["named-agent"],
        "raqib_watch_incomplete.yml": ["heartbeat-incomplete", "watch-clean"],
        "raqib_heartbeat_not_watching.yml": ["heartbeat-incomplete"]}
# the Table's measured hosts (ADR-0017 Amendment A): (host, run, example, beat in s, what else); the first group is
# sent at once, c.example's second run a second later
SILENCE_HOSTS = (
    ("a.example", "a1", "watch start", 1, {}), ("a.example", "a1", "heartbeat", 1, {}),
    ("b.example", "b1", "heartbeat", 600, {}),
    ("c.example", "c1", "heartbeat", 3, {}),
    ("d.example", "d1", "watch start", 1, {}),
    ("e.example", "e1", "heartbeat", 600, {"time": "2000-01-01T00:00:00.000Z"}),
    ("f.example", "f1", "heartbeat", 1, {"time": "2099-01-01T00:00:00.000Z"}),
    ("g.example", "g1", "watch start", 1, {}), ("g.example", "g1", "watch end", 1, {}),
)
SILENCE_LATER = (("c.example", "c2", "heartbeat", 1, {}),)
SILENCE_READS = (0.0, 3.6, 8.0)   # seconds after the first send: at once (after the later send), and after waits


def _deep(n):
    out = cur = {}
    for _ in range(n):
        cur["k"] = {}
        cur = cur["k"]
    return out


# each odd line of SA-5 (and of the review's list): label -> how a made heartbeat is changed (a function of it)
ODD = (
    ("an-empty-key", lambda ev: dict(ev, **{"": 1})),
    ("run-an-object", lambda ev: _set(ev, ("watch", "run"), {"x": 1})),
    ("kind-unknown", lambda ev: dict(ev, kind="no-such-kind")),
    ("n-missing", lambda ev: {k: v for k, v in ev.items() if k != "n"}),
    ("n-beyond-a-long", lambda ev: dict(ev, n=2 ** 70)),
    ("alarm-a-string", lambda ev: dict(ev, alarm="true")),
    ("deep-unknown-key", lambda ev: dict(ev, zz=_deep(25))),
    ("deep-evidence", lambda ev: dict(ev, evidence=_deep(25))),
    ("many-unknown-keys", lambda ev: dict(ev, **{"u%04d" % i: i for i in range(1001)})),
    ("a-long-word", lambda ev: dict(ev, knocked={"status": "sent", "called": "x" * 40000})),
    ("not-json", lambda ev: "{not json"),
    ("schema-2", lambda ev: dict(ev, schema="raqib-event/2")),
    ("fp-budget-a-text", lambda ev: dict(ev, rule={"id": "NET-TOOL", "class": "NET", "kind": "signature",
                                                   "fp_budget": "x", "attack": ["T1105"]})),
    ("attack-objects", lambda ev: dict(ev, rule={"id": "NET-TOOL", "class": "NET", "kind": "signature",
                                                 "fp_budget": 0.05, "attack": [{"a": 1}]})),
    ("a-dotted-key", lambda ev: dict(ev, **{"watch.run": {"x": 1}})),
    ("an-unknown-key", lambda ev: dict(ev, zz=1)),
    ("sixty-unknown-keys", lambda ev: dict(ev, **{"u%02d" % i: i for i in range(60)})),
)


def _set(ev, path, value):
    ev = copy.deepcopy(ev)
    cur = ev
    for k in path[:-1]:
        cur = cur.setdefault(k, {})
    cur[path[-1]] = value
    return ev


def line_of(ev):
    return ev if isinstance(ev, str) else json.dumps(ev, sort_keys=True, separators=(",", ":"))


def instant_ms(text):
    """An ISO 8601 instant as epoch milliseconds (its fraction cut to milliseconds), else None."""
    m = INSTANT.match(text) if isinstance(text, str) else None
    if not m:
        return None
    y, mo, d, h, mi, s, frac, zone = m.groups()
    ms = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(s))) * 1000 + int((frac or "0")[:3].ljust(3, "0"))
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        ms -= sign * (int(zone[1:3]) * 60 + int(zone[4:6])) * 60000
    return ms


def spec_keys(text):
    """key -> its type word, from EVENT.md's Keys table, in its order."""
    out = {}
    for row in text.split("## Keys", 1)[1].split("## Mapping", 1)[0].splitlines():
        if row.startswith("| `"):
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            out[cells[0].strip("`")] = cells[1].strip("`")
    return out


def known(keys):
    """(top, parts, checked): the spec's top keys -> their code; each part -> its keys; the parts' keys whose kind
    of value the pipeline checks -> their code (the parts kept whole are not checked inside, but for subject's
    two named keys)."""
    top = {k: CODE.get(t) for k, t in keys.items() if "." not in k}
    parts, checked = {}, {}
    for k, t in keys.items():
        if "." in k:
            parent, sub = k.split(".", 1)
            parts.setdefault(parent, []).append(sub)
            if parent in CHECKED_PARTS and (CHECKED_PARTS[parent] is None or sub in CHECKED_PARTS[parent]):
                checked.setdefault(parent, {})[sub] = CODE.get(t)
    return top, parts, checked


def typed(v, code):
    if code is None:
        return True
    whole = isinstance(v, int) and not isinstance(v, bool) and -LONG <= v < LONG
    return {"s": isinstance(v, str), "i": whole, "p": whole and v >= 1, "c": whole and v >= 0,
            "b": isinstance(v, bool), "o": isinstance(v, dict),
            "f": whole or (isinstance(v, float) and not isinstance(v, bool)),
            "S": isinstance(v, list) and all(isinstance(x, str) for x in v)}[code]


def walk(v, depth, tally):
    """The shape an engine would refuse (SA-5), the pipeline's own walk: a reason, else None."""
    if depth > MAX_DEPTH:
        return "deeper than %d levels" % MAX_DEPTH
    if isinstance(v, dict):
        for k, x in v.items():
            if k == "":
                return "an empty key"
            tally[0] += 1
            if tally[0] > MAX_KEYS:
                return "more than %d keys" % MAX_KEYS
            why = walk(x, depth + 1, tally)
            if why:
                return why
    elif isinstance(v, list):
        for x in v:
            why = walk(x, depth + 1, tally)
            if why:
                return why
    elif isinstance(v, str) and len(v) > MAX_TEXT:
        return "a text longer than %d characters" % MAX_TEXT
    return None


def check_of(line, keys):
    """Why the pipeline keeps a line as an error document (its own checks, SA-5), else None (an event)."""
    try:
        r = json.loads(line)
    except ValueError:
        return "not JSON"
    if not isinstance(r, dict) or r.get("schema") != "raqib-event/1":
        return "another schema"
    why = walk(r, 1, [0])
    if why:
        return why
    top, _, checked = known(keys)
    for k in BASE:
        if k not in r:
            return "the base key %s is missing" % k
    for k, code in top.items():
        if k in r and not typed(r[k], code):
            return "%s is not of its kind of value" % k
    if r["kind"] not in KINDS:
        return "the kind is not one of the spec's eight"
    for k in WATCH_BASE:
        if k not in r["watch"]:
            return "the base key watch.%s is missing" % k
    for parent, subs in checked.items():
        part = r.get(parent)
        for k, code in subs.items():
            if isinstance(part, dict) and k in part and not typed(part[k], code):
                return "%s.%s is not of its kind of value" % (parent, k)
    if instant_ms(r["time"]) is None:
        return "time is not an instant"
    return None


def event_of(line):
    """The event a line holds (parsed), else None: what the stand-ins and the counts read."""
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    return ev if isinstance(ev, dict) and ev.get("schema") == "raqib-event/1" else None


def ecs_of(line, keys):
    """The document siem's pipeline makes of an event's line, computed here from the event (EVENT.md, Mapping):
    every named key to its ECS field, every other key the spec knows under raqib, the names of the keys it does
    not know under raqib.unknown_keys (at most 50, sorted), the line in event.original."""
    top, parts, _ = known(keys)
    r = json.loads(line)
    unknown = []
    for k in list(r):
        if k not in top:
            unknown.append(k)
            del r[k]
    for parent, subs in parts.items():
        part = r.get(parent)
        if isinstance(part, dict):
            for k in list(part):
                if k not in subs:
                    unknown.append(parent + "." + k)
                    del part[k]
    if unknown:
        r["unknown_keys"] = sorted(unknown)[:MAX_UNKNOWN]
    doc = {"@timestamp": r.pop("time"), "event": {"original": line, "id": r.pop("id"), "action": r.pop("kind")}}
    if r.get("severity") in SEVERITY:
        doc["event"]["severity"] = SEVERITY[r.pop("severity")]
    doc["event"]["kind"] = "alert" if r.pop("alarm", None) is True else "event"
    if "summary" in r:
        doc["message"] = r.pop("summary")
    w = r["watch"]
    doc["host"] = {"name": w.pop("host")}
    doc["observer"] = {"product": "Raqib"}
    if "version" in w:
        doc["observer"]["version"] = w.pop("version")
    if not w:
        del r["watch"]
    rule = r.get("rule")
    if isinstance(rule, dict):
        if "id" in rule:
            doc["rule"] = {"id": rule.pop("id")}
        if "class" in rule:
            doc.setdefault("rule", {})["category"] = rule.pop("class")
        if "attack" in rule:
            doc["threat"] = {"technique": {"id": rule.pop("attack")}}
        if not rule:
            del r["rule"]
    subject = r.get("subject")
    if isinstance(subject, dict):
        proc = {}
        if "pid" in subject:
            proc["pid"] = subject.pop("pid")
        if "image" in subject:
            proc["name"] = subject.pop("image")
        if proc:
            doc["process"] = proc
        if not subject:
            del r["subject"]
    doc["raqib"] = r
    return doc


def get(doc, dotted):
    """The value at a dotted name of a nested document (or of an event), else None."""
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def leaves(doc, prefix=""):
    out = {}
    for k, v in doc.items():
        if isinstance(v, dict):
            out.update(leaves(v, prefix + k + "."))
        else:
            out[prefix + k] = v
    return out


def differences(want, have, window, extra=None):
    """Where the engine's document differs from want's: the named fields, the namespace, the line, the arrival
    (within the runner's clock around the send) and the shipper's own fields (all but host.name)."""
    out = []
    for field in NAMED:
        a, b = get(want, field), get(have, field)
        if field == "@timestamp":
            a, b = instant_ms(a), instant_ms(b)
        if a != b:
            out.append("%s: the event says %s, the engine holds %s" % (field, json.dumps(a), json.dumps(b)))
    if get(have, "raqib") != want["raqib"]:
        out.append("raqib: the namespace differs from the event's other keys")
    if get(have, "event.original") != want["event"]["original"]:
        out.append("event.original: not the line")
    arrived = instant_ms(get(have, "event.ingested"))
    if arrived is None or not window[0] <= arrived <= window[1]:
        out.append("event.ingested: %s is not between the runner's clock before and after the send (%d, %d)" % (
            get(have, "event.ingested"), window[0], window[1]))
    for field, value in leaves(extra or {}).items():
        if field != "host.name" and get(have, field) != value:
            out.append("%s: the shipper sent %s, the engine holds %s" % (field, json.dumps(value),
                                                                         json.dumps(get(have, field))))
    return out


def sigma_match(detection, ev):
    """Whether an event matches a rule's detection, for the subset siem/sigma/rules is written in: a selection and
    an optional filter (each key a key of the event, a value or a list of values, the modifier startswith), the
    condition `selection` or `selection and not filter`."""
    def matches(block):
        for key, want in block.items():
            name, _, modifier = key.partition("|")
            have = get(ev, name)
            wants = want if isinstance(want, list) else [want]
            if modifier == "startswith":
                ok = isinstance(have, str) and any(have.startswith(w) for w in wants)
            elif modifier == "":
                ok = any((have is w) if isinstance(w, bool) or isinstance(have, bool) else have == w for w in wants)
            else:
                raise ValueError("the modifier %s is not read here" % modifier)
            if not ok:
                return False
        return True
    condition = detection.get("condition")
    if condition == "selection":
        return matches(detection["selection"])
    if condition == "selection and not filter":
        return matches(detection["selection"]) and not matches(detection["filter"])
    raise ValueError("the condition %r is not read here" % condition)


def http_ask(base):
    def ask(method, path, body=None, ndjson=False):
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(base + path, data=data, method=method, headers={
            "Content-Type": "application/x-ndjson" if ndjson else "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")
            try:
                return exc.code, json.loads(text)
            except ValueError:
                return exc.code, {"text": text[:400]}
    return ask


def sigma_cli(path):
    def run(target, pipeline, rule):
        done = subprocess.run([path, "convert", "-t", target, "-p", pipeline, rule], capture_output=True,
                              text=True, timeout=120)
        lines = [x.strip() for x in done.stdout.splitlines() if x.strip()]
        if done.returncode != 0 or not lines:
            raise RuntimeError("sigma convert exit %d: %s" % (done.returncode, (done.stderr or done.stdout)[-300:]))
        return lines[0] if len(lines) == 1 else " OR ".join("(%s)" % x for x in lines)
    return run


def versions():
    """The versions of sigma-cli and pySigma in this Python, as installed by the rig's job."""
    out = []
    try:
        from importlib import metadata
    except ImportError:   # pragma: no cover
        return "sigma-cli ?, pySigma ?"
    for name in ("sigma-cli", "pySigma", "pysigma-backend-elasticsearch", "pysigma-backend-opensearch"):
        try:
            out.append("%s %s" % (name, metadata.version(name)))
        except Exception:
            out.append("%s not installed" % name)
    return ", ".join(out)


def lines_of(paths, say):
    """(the examples, the files' whole lines): a last line with no newline is not whole (EVENT.md)."""
    examples, files = [], []
    for path in paths:
        if not os.path.exists(path):
            say("EVENTS %s: missing" % os.path.basename(path))
            continue
        with open(path, encoding="utf-8", newline="") as f:
            text = f.read()
        if path.endswith(".md"):
            got = EXAMPLE.findall(text)
            examples += got
        else:
            got = [x for x in text.split("\n")[:-1] if x.strip()]
            files += got
        say("EVENTS %s: %d line(s)" % (os.path.basename(path), len(got)))
    return examples, files


def examples_by_label(text):
    out = {}
    for m in re.finditer(r"^### example: (.+)\n(?:.*\n)*?```json\n(.+?)\n```", text, re.M):
        out.setdefault(m.group(1), json.loads(m.group(2)))
    return out


class Maker:
    """Made-up events from EVENT.md's examples, each with a run, a host, an id and an n of its own."""

    def __init__(self, text):
        self.examples, self.n = examples_by_label(text), 1000

    def make(self, label, host, run, beat=None, **over):
        ev = copy.deepcopy(self.examples[label])
        self.n += 1
        ev["watch"].update(host=host, run=run)
        if beat is not None:
            ev["watch"]["beat"] = float(beat)
        ev.update(id="%s:%d" % (run, self.n), n=self.n, about="%s:%d" % (ev["kind"], self.n))
        for key, value in over.items():
            if key == "rule":
                cls, kind, attack = RULE[value]
                ev["rule"] = dict(ev.get("rule", {}), id=value, **{"class": cls, "kind": kind, "attack": attack})
            elif "." in key:
                ev = _set(ev, tuple(key.split(".")), value)
            else:
                ev[key] = value
        return ev


def wait_engine(ask, seconds, clock, sleep):
    end = clock() + seconds
    while True:
        try:
            code, body = ask("GET", "/")
            if code == 200:
                version = body.get("version", {})
                return version.get("distribution", "elasticsearch"), version.get("number")
        except OSError:
            pass
        if clock() >= end:
            return None
        sleep(min(3, max(0.1, end - clock())))


class Feed:
    """What was sent to an index: each line, its kind here (an event or the reason it is not), the shipper's
    fields sent with it, and the runner's clock before and after its send."""

    def __init__(self, ask, keys, clock):
        self.ask, self.keys, self.clock, self.sent, self.refused = ask, keys, clock, [], []

    def send(self, index, lines, extra=None):
        before = int(self.clock() * 1000)
        body = "".join('{"index":{}}\n' + json.dumps(dict(extra or {}, message=x)) + "\n" for x in lines)
        code, got = self.ask("POST", "/%s/_bulk?refresh=true" % index, body.encode("utf-8"), True)
        after = -(-int(self.clock() * 1000000) // 1000)
        items = got.get("items", []) if code == 200 else []
        for i, line in enumerate(lines):
            item = items[i].get("index", {}) if i < len(items) else {"error": "http %s: %s" % (
                code, json.dumps(got)[:200])}
            if item.get("error"):
                self.refused.append((index, line, str(item["error"])[:200]))
            self.sent.append({"index": index, "line": line, "why": check_of(line, self.keys), "extra": extra,
                              "window": (before, after)})
        return before, after

    def events(self, index):
        return [s for s in self.sent if s["index"] == index and s["why"] is None]


def sources(ask, index, query=None):
    code, got = ask("POST", "/%s/_search" % index, {"size": 10000, "query": query or {"match_all": {}}})
    return [h.get("_source", {}) for h in got.get("hits", {}).get("hits", [])] if code == 200 else None


def total(code, got):
    if code != 200:
        return "error %s" % code
    value = got.get("hits", {}).get("total")
    return value.get("value") if isinstance(value, dict) else value


def run_search(ask, index, search, params=None):
    """(count, http code, the response) of one search file against index, with its params where given."""
    body = copy.deepcopy(search["body"])
    if search["request"].endswith("/_search/template"):
        body["source"].update({"size": 0, "track_total_hits": True})
        body["params"].update(params or {})
        code, got = ask("POST", "/%s/_search/template" % index, body)
    else:
        body.update({"size": 0, "track_total_hits": True})
        code, got = ask("POST", "/%s/_search" % index, body)
    return total(code, got), code, got


def deadlines(sent, by):
    """by(event) -> the key it is grouped by; for each key the range of its latest deadline by the runner's clock
    (the earliest and the latest it can be: each line's send window and two of its own beats, as the engine
    computes it), and whether the group said a watch's end."""
    out = {}
    for s in sent:
        ev = json.loads(s["line"])
        beat = ev["watch"]["beat"]
        lo, hi = s["window"][0] + int(2000 * beat), s["window"][1] + int(2000 * beat)
        key = by(ev)
        was = out.get(key, (lo, hi, False))
        out[key] = (max(was[0], lo), max(was[1], hi),
                    was[2] or (ev.get("kind") == "watch" and ev.get("state") == "end"))
    return out


def judge_deadlines(groups, read, got, runs):
    """(ok, text): the engine's list against the groups whose deadline has surely passed, or surely not, at the
    read window (the runner's clock before and after the search)."""
    sure = sorted(k for k, (lo, hi, end) in groups.items() if hi < read[0] and not (runs and end))
    never = sorted(k for k, (lo, hi, end) in groups.items() if lo >= read[1] or (runs and end))
    if not isinstance(got, list):
        return False, got
    keys = [k for k, _ in got]
    ok = set(sure) <= set(keys) and not set(never) & set(keys)
    if not runs:   # the hosts nearest their deadline's passing first
        order = [d for _, d in got if d is not None]
        ok = ok and order == sorted(order)
    return ok, "engine %s; here %s surely, %d not sure" % (",".join(keys) or "none", ",".join(sure) or "none",
                                                           len(groups) - len(sure) - len(never))


def buckets(code, got, name):
    if code != 200:
        return "error %s: %s" % (code, json.dumps(got)[:200])
    out = []
    for b in got.get("aggregations", {}).get(name, {}).get("buckets", []):
        key = "/".join(b["key"]) if isinstance(b.get("key"), list) else b.get("key")
        out.append((key, (b.get("deadline") or {}).get("value")))
    return out


def claim_x39(ask, feed):
    docs = {}
    for index in sorted({s["index"] for s in feed.sent}):
        for d in sources(ask, index) or []:
            docs.setdefault((index, get(d, "event.original")), []).append(d)
    wrong, said = [], []
    for s in feed.sent:
        have = docs.get((s["index"], s["line"])) or [None]
        doc = have[0]
        kind = None if doc is None else ("error" if get(doc, "event.kind") == "pipeline_error" else "event")
        want = "event" if s["why"] is None else "error"
        if kind != want or (kind == "error" and not get(doc, "error.message")):
            wrong.append("%s %s: %s here, %s in the engine" % (s["index"], s["line"][:60], want, kind or "nothing"))
        if s.get("label"):
            said.append("%s %s" % (s["label"], kind or "lost"))
    nexts = [s for s in feed.sent if s.get("after_odd")]
    kept_next = sum(1 for s in nexts if (s["index"], s["line"]) in docs)
    errors = sum(1 for s in feed.sent if s["why"] is not None)
    ok = not feed.refused and not wrong and kept_next == len(nexts)
    text = ("%d line(s) sent, %d refused, %d kept as events and %d as error documents here (%d wrong); the line "
            "after each of %d odd lines kept: %d; the odd lines: %s") % (
        len(feed.sent), len(feed.refused), len(feed.sent) - errors, errors, len(wrong), len(nexts), kept_next,
        ", ".join(said))
    first = wrong[:2] + ["refused %s %s: %s" % r for r in feed.refused[:2]]
    return ok, text + ("; first: %s" % " | ".join(first) if first else "")


def claim_x40(ask, feed):
    by_line = {}
    for index in sorted({s["index"] for s in feed.sent}):
        for d in sources(ask, index) or []:
            by_line.setdefault((index, get(d, "event.original")), []).append(d)
    diffs, missing, shipper = [], 0, 0
    events = [s for s in feed.sent if s["why"] is None]
    for s in events:
        have = by_line.get((s["index"], s["line"]))
        if not have:
            missing += 1
            continue
        diffs += ["%s %s" % (s["line"][:40], d) for d in differences(ecs_of(s["line"], feed.keys), have.pop(),
                                                                      s["window"], s["extra"])]
    for s in (x for x in feed.sent if x["why"] is not None and x["extra"]):
        have = by_line.get((s["index"], s["line"])) or [{}]
        shipper += 1
        for field, value in leaves(s["extra"]).items():
            if get(have[0], field) != value:
                diffs.append("error document %s: %s not kept" % (s["line"][:30], field))
    text = ("%d event line(s), %d found in the engine, %d difference(s) in %d named field(s), the namespace, the "
            "line, the arrival and the shipper's fields (%d document(s) with a shipper's fields, %d of them an "
            "error document)") % (len(events), len(events) - missing, len(diffs), len(NAMED),
                                  sum(1 for s in feed.sent if s["extra"]), shipper)
    return not diffs and not missing, text + ("; first: %s" % " | ".join(diffs[:3]) if diffs else "")


def claim_x41(ask, searches, feed, reads):
    rows, ok = [], True
    events = [json.loads(s["line"]) for s in feed.events(INDEX)]

    def one(name, got, want):
        nonlocal ok
        ok = ok and got == want
        rows.append("%s %s/%s" % (name, got, want))

    kinds = {"alarm.json": lambda e: e.get("alarm") is True,
             "hole.json": lambda e: e.get("kind") == "hole",
             "watch-not-0.json": lambda e: (e.get("kind") == "watch" and e.get("state") == "end"
                                            and isinstance(e.get("result"), dict) and "exit" in e["result"]
                                            and e["result"]["exit"] != 0)}
    for name, test in kinds.items():
        one(name[:-5], run_search(ask, INDEX, searches[name])[0], sum(1 for e in events if test(e)))
    for rule_id in sorted({get(e, "rule.id") for e in events if get(e, "rule.id")} | {"NO-SUCH-RULE"}):
        one("rule " + rule_id, run_search(ask, INDEX, searches["rule.json"], {"rule_id": rule_id})[0],
            sum(1 for e in events if get(e, "rule.id") == rule_id))
    for label, index, read in reads:
        sent = feed.events(index)
        for name, by, runs in (("silence.json", lambda e: e["watch"]["host"], False),
                               ("runs-no-end.json", lambda e: "%s/%s" % (e["watch"]["host"], e["watch"]["run"]),
                                True)):
            _, code, got = read[name]
            good, text = judge_deadlines(deadlines(sent, by), read["window"], buckets(
                code, got, "runs" if runs else "hosts"), runs)
            ok = ok and good
            rows.append("%s %s %s: %s%s" % (name[:-5], index[len(INDEX):] or "-main", label, text,
                                            "" if good else " (MISSED)"))
    return ok, "; ".join(rows) + " (each: the engine's/the count here)"


def claim_x42(ask, sigma, target, feed, made_ids):
    rules_dir = os.path.join(SIEM, "sigma", "rules")
    pipeline = os.path.join(SIEM, "sigma", "pipeline-ecs.yml")
    events = [json.loads(s["line"]) for s in feed.events(INDEX)]
    rows, ok = [], True
    for name in sorted(os.listdir(rules_dir)):
        with open(os.path.join(rules_dir, name), encoding="utf-8") as f:
            rule = yamlite.loads(f.read())
        want = sum(1 for e in events if sigma_match(rule["detection"], e))
        try:
            query = sigma(target, pipeline, os.path.join(rules_dir, name))
        except Exception as exc:   # the conversion's own failure is the claim's number, never a MET
            ok = False
            rows.append("%s not converted (%s)" % (name, str(exc)[:160]))
            continue

        def count(extra=None):
            q = {"query_string": {"query": query}}
            if extra:
                q = {"bool": {"filter": [q, {"term": {"event.id": extra}}]}}
            return total(*ask("POST", "/%s/_search" % INDEX, {"size": 0, "track_total_hits": True, "query": q}))
        got = count()
        positive = POSITIVE.get(name)
        hit = count(made_ids[positive]) if positive else None
        misses = {m: count(made_ids[m]) for m in NEAR.get(name, [])}
        good = (got == want and want >= 1 and (positive is None or hit == 1) and bool(misses)
                and all(v == 0 for v in misses.values()))
        ok = ok and good
        rows.append("%s %s/%s%s, near miss %s%s" % (
            name[:-4], got, want, "" if positive is None else ", its own %s %s" % (positive, hit),
            ",".join("%s %s" % kv for kv in sorted(misses.items())) or "none", "" if good else " (MISSED)"))
    return ok, "; ".join(rows) + " (each: the engine's/the count here; target %s)" % target


def put(ask, path, body, say, what):
    code, got = ask("PUT", path, body)
    say("INSTALL %s: http %s%s" % (what, code, "" if code == 200 else " " + json.dumps(got)[:400]))
    return code == 200


def main(argv=None, ask=None, sigma=None, out=print, clock=time.time, sleep=time.sleep):
    parser = argparse.ArgumentParser(description="the rig's claims of siem/ (X39 to X42)")
    parser.add_argument("events", nargs="+", help="EVENT.md (its examples) and events files")
    parser.add_argument("--url", default="http://127.0.0.1:9200")
    parser.add_argument("--wait", type=float, default=180.0, help="seconds to wait for the engine")
    parser.add_argument("--sigma", default=None, help="sigma-cli's path (default: sigma on PATH)")
    parser.add_argument("--summary", default=None, help="a file the rows are appended to")
    args = parser.parse_args(argv)
    ask = ask or http_ask(args.url.rstrip("/"))
    rows, fed = [], []

    def row(n, word, text):
        line = "%-7s X%d %s: %s [fed: %s]" % (word, n, dict(CLAIMS)[n], text, "; ".join(fed) or "nothing")
        rows.append(line)
        out(line)

    with open(SPEC, encoding="utf-8") as f:
        spec = f.read()
    keys = spec_keys(spec)
    examples, files = lines_of(args.events, out)
    engine = wait_engine(ask, args.wait, clock, sleep)
    if engine is None:
        out("ENGINE did not answer at %s in %d s" % (args.url, args.wait))
        for n, _ in CLAIMS:
            row(n, "n/a", "the engine did not answer at %s in %d s: not run" % (args.url, args.wait))
        return finish(rows, args.summary)
    distribution, number = engine
    folder = "opensearch" if distribution == "opensearch" else "elastic"
    target = "opensearch_lucene" if folder == "opensearch" else "lucene"
    fed.append("engine %s %s, siem/%s" % (distribution, number, folder))
    out("ENGINE %s %s (the content of siem/%s; sigma target %s)" % (distribution, number, folder, target))
    content = os.path.join(SIEM, folder)
    with open(os.path.join(content, "pipeline.json"), encoding="utf-8") as f:
        pipeline = json.load(f)
    with open(os.path.join(content, "template.json"), encoding="utf-8") as f:
        template = json.load(f)
    searches = {}
    for name in sorted(os.listdir(os.path.join(content, "searches"))):
        with open(os.path.join(content, "searches", name), encoding="utf-8") as f:
            searches[name] = json.load(f)
    for index in (INDEX, ODD_INDEX, SILENCE_INDEX):
        ask("DELETE", "/" + index)
    installed = (put(ask, "/_ingest/pipeline/" + PIPELINE_ID, pipeline, out, "the pipeline")
                 & put(ask, "/_index_template/" + TEMPLATE_ID, template, out, "the template"))
    if not installed:
        for n, _ in CLAIMS:
            row(n, "MISSED", "the engine refused the content of siem/%s (above)" % folder)
        return finish(rows, args.summary)

    feed, maker = Feed(ask, keys, clock), Maker(spec)
    made = {label: maker.make(base, "made.example", "made-run", **over) for label, base, over in MADE}
    made_ids = {label: ev["id"] for label, ev in made.items()}
    feed.send(INDEX, examples + files + [line_of(made[label]) for label, _, _ in MADE])
    shipped = [line_of(maker.make("heartbeat", "shipped.example", "shipped-run")), "{a line a shipper sent"]
    for line in shipped:
        feed.send(INDEX, [line], extra=SHIPPER)
    odd_lines = []
    for label, change in ODD:
        odd_lines += [line_of(change(maker.make("heartbeat", "odd.example", "odd", 600))),
                      line_of(maker.make("heartbeat", "odd.example", "odd-next", 600))]
    feed.send(ODD_INDEX, odd_lines)
    for i, (label, _) in enumerate(ODD):
        feed.sent[-2 * len(ODD) + 2 * i]["label"] = label
        feed.sent[-2 * len(ODD) + 2 * i + 1]["after_odd"] = True
    fed += ["%d example(s) of EVENT.md" % len(examples), "%d line(s) of the events file(s)" % len(files),
            "%d made-up event(s) of the rules' classes and %d near miss(es)" % (
                len({v for v in POSITIVE.values() if v}), len(MADE) - len({v for v in POSITIVE.values() if v})),
            "%d odd line(s) and the line after each" % len(ODD), "%d document(s) with a shipper's fields" % len(shipped)]

    def read(label, index):
        before = int(clock() * 1000)
        got = {name: run_search(ask, index, searches[name]) for name in ("silence.json", "runs-no-end.json")}
        got["window"] = (before, -(-int(clock() * 1000000) // 1000))
        return label, index, got
    reads = [read("at once", INDEX)]
    t0 = clock()
    feed.send(SILENCE_INDEX, [line_of(maker.make(ex, host, run, beat, **over))
                              for host, run, ex, beat, over in SILENCE_HOSTS])
    sleep(max(0.0, t0 + 1.0 - clock()))
    feed.send(SILENCE_INDEX, [line_of(maker.make(ex, host, run, beat, **over))
                              for host, run, ex, beat, over in SILENCE_LATER])
    for at in SILENCE_READS:
        sleep(max(0.0, t0 + at - clock()))
        reads.append(read("at +%.1f s" % (clock() - t0), SILENCE_INDEX))
    fed.append("%d line(s) of %d made-up host(s) for silence, read at once and after waits" % (
        len(SILENCE_HOSTS) + len(SILENCE_LATER), len({h[0] for h in SILENCE_HOSTS})))

    for n, claim in ((39, lambda: claim_x39(ask, feed)), (40, lambda: claim_x40(ask, feed)),
                     (41, lambda: claim_x41(ask, searches, feed, reads))):
        ok, text = claim()
        row(n, "MET" if ok else "MISSED", text)
    if sigma is None:
        path = args.sigma or shutil.which("sigma")
        if not path:
            row(42, "n/a", "sigma-cli is not installed here (no sigma on PATH): not run")
            return finish(rows, args.summary)
        sigma = sigma_cli(path)
    fed.append(versions())
    ok, text = claim_x42(ask, sigma, target, feed, made_ids)
    row(42, "MET" if ok else "MISSED", text)
    return finish(rows, args.summary)


def finish(rows, summary):
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("```\n" + "\n".join(rows) + "\n```\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
