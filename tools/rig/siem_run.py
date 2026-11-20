"""The rig's claims of siem/ (ADR-0017 S-2, M16.1 E6), against a search engine on this machine's own port:
installs siem/<engine>/'s pipeline and template, puts lines of raqib-event/1 through them (the examples of
docs/specs/EVENT.md and a real watch's events file), and prints one row a claim, MET or MISSED with its numbers:
  X39 no line refused and none kept as an error (and two lines that are not events kept, each with its reason);
  X40 every field the Mapping names holds the value the event holds, for every line, against ecs_of() below,
      the mapping computed here from the event;
  X41 each search of siem/<engine>/searches counts what a count made here says (the search for silence by the
      engine's own clock of arrival, at three times);
  X42 each Sigma rule of siem/sigma/rules, converted by sigma-cli with siem/sigma/pipeline-ecs.yml, counts what
      a count made here says.
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
EXAMPLE = re.compile(r"^```json\n(.+?)\n```", re.M)
INSTANT = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)\Z")
INDEX = "raqib-events-rig"
BAD_INDEX = "raqib-events-rig-notevents"
PIPELINE_ID = "raqib-event-1"
TEMPLATE_ID = "raqib-events"
# two lines that are not events: a torn write, and JSON of another schema; each must be kept with its reason
NOT_EVENTS = ('{"schema": "raqib-event/1", "id": "torn', '{"schema": "other/1", "id": "not-an-event"}')
SEVERITY = {"high": 4, "medium": 3, "low": 2, "info": 1, "hole": 3}
NAMED = ("@timestamp", "event.id", "event.action", "event.severity", "event.kind", "message", "host.name",
         "observer.product", "observer.version", "rule.id", "rule.category", "threat.technique.id",
         "process.pid", "process.name")
CLAIMS = ((39, "no line refused and none kept as an error"),
          (40, "every field the Mapping names holds the value the event holds"),
          (41, "each search counts what a count made here says"),
          (42, "each Sigma rule, converted by sigma-cli, counts what a count made here says"))


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


def event_of(line):
    """The event a line holds, else None (not JSON, not an object, or not raqib-event/1)."""
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    return ev if isinstance(ev, dict) and ev.get("schema") == "raqib-event/1" else None


def ecs_of(line):
    """The document siem's pipeline makes of an event's line, computed here from the event (EVENT.md, Mapping):
    every named key to its ECS field, every other key under raqib, the line in event.original."""
    r = copy.deepcopy(json.loads(line))
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


def differences(want, have):
    """The named fields, the namespace and the line where the engine's document differs from want's."""
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
    if instant_ms(get(have, "event.ingested")) is None:
        out.append("event.ingested: no instant of arrival")
    return out


def sigma_match(detection, ev):
    """Whether an event matches a rule's detection, for the subset siem/sigma/rules is written in: one selection
    (each key a key of the event, a value or a list of values, the modifier startswith), condition: selection."""
    if detection.get("condition") != "selection":
        raise ValueError("only condition: selection is read here")
    for key, want in detection["selection"].items():
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
        lines = [x for x in done.stdout.splitlines() if x.strip()]
        if done.returncode != 0 or not lines:
            raise RuntimeError("sigma convert exit %d: %s" % (done.returncode, (done.stderr or done.stdout)[-300:]))
        return lines[-1].strip()
    return run


def lines_of(paths, say):
    out = []
    for path in paths:
        if not os.path.exists(path):
            say("EVENTS %s: missing" % os.path.basename(path))
            continue
        with open(path, encoding="utf-8", newline="") as f:
            text = f.read()
        if path.endswith(".md"):
            got = EXAMPLE.findall(text)
        else:
            whole = text.split("\n")[:-1]   # a last line with no newline is not whole (EVENT.md, for a reader)
            got = [x for x in whole if x.strip()]
        say("EVENTS %s: %d line(s)" % (os.path.basename(path), len(got)))
        out += got
    return out


def wait_engine(ask, seconds):
    end = time.monotonic() + seconds
    while True:
        try:
            code, body = ask("GET", "/")
            if code == 200:
                version = body.get("version", {})
                return version.get("distribution", "elasticsearch"), version.get("number")
        except OSError:
            pass
        if time.monotonic() >= end:
            return None
        time.sleep(min(3, max(0.1, end - time.monotonic())))


def bulk(ask, index, lines):
    kept, refused = 0, []
    for start in range(0, len(lines), 500):
        part = lines[start:start + 500]
        body = "".join('{"index":{}}\n' + json.dumps({"message": x}) + "\n" for x in part).encode("utf-8")
        code, got = ask("POST", "/%s/_bulk?refresh=true" % index, body, True)
        items = got.get("items", []) if code == 200 else []
        bad = [i.get("index", {}).get("error") for i in items if i.get("index", {}).get("error")]
        refused += bad + ["http %s: %s" % (code, json.dumps(got)[:200])] * (len(part) - len(items))
        kept += len(items) - len(bad)
    return kept, refused


def sources(ask, index, query=None):
    code, got = ask("POST", "/%s/_search" % index, {"size": 10000, "query": query or {"match_all": {}}})
    return [h.get("_source", {}) for h in got.get("hits", {}).get("hits", [])] if code == 200 else None


def total(code, got):
    if code != 200:
        return "error %s" % code
    value = got.get("hits", {}).get("total")
    return value.get("value") if isinstance(value, dict) else value


def run_search(ask, index, search, params=None):
    """(count, the response) of one search file against index, with its params replaced where given."""
    body = copy.deepcopy(search["body"])
    if search["request"].endswith("/_search/template"):
        body["source"].update({"size": 0, "track_total_hits": True})
        body["params"].update(params or {})
        code, got = ask("POST", "/%s/_search/template" % index, body)
    else:
        body.update({"size": 0, "track_total_hits": True})
        code, got = ask("POST", "/%s/_search" % index, body)
    return total(code, got), code, got


def claim_x39(ask, lines, events):
    kept, refused = bulk(ask, INDEX, lines)
    errors = total(*ask("POST", "/%s/_search" % INDEX, {"size": 0, "track_total_hits": True,
                                                        "query": {"term": {"event.kind": "pipeline_error"}}}))
    not_events = len(lines) - len(events)
    bad_kept, bad_refused = bulk(ask, BAD_INDEX, list(NOT_EVENTS))
    docs = sources(ask, BAD_INDEX) or []
    said = [d for d in docs if get(d, "event.kind") == "pipeline_error" and get(d, "error.message")
            and get(d, "event.original") in NOT_EVENTS]
    ok = not refused and errors == not_events == 0 and len(said) == len(NOT_EVENTS) and not bad_refused
    text = ("%d line(s) sent, %d kept, %d refused, %s kept as an error (%d not events by the count here); "
            "%d line(s) that are not events: %d kept with event.kind pipeline_error and a reason") % (
        len(lines), kept, len(refused), errors, not_events, len(NOT_EVENTS), len(said))
    why = sorted(set(str(r)[:160] for r in refused))[:3]
    return ok, text + ("; refused: %s" % " | ".join(why) if why else "")


def claim_x40(ask, events_lines):
    docs = sources(ask, INDEX)
    if docs is None:
        return False, "the engine's documents could not be read"
    by_line = {}
    for d in docs:
        by_line.setdefault(get(d, "event.original"), []).append(d)
    diffs, missing = [], 0
    for i, line in enumerate(events_lines, 1):
        have = by_line.get(line)
        if not have:
            missing += 1
            continue
        diffs += ["line %d %s" % (i, d) for d in differences(ecs_of(line), have.pop())]
    text = "%d line(s), %d found in the engine, %d difference(s) in %d named field(s), the namespace and the line" % (
        len(events_lines), len(events_lines) - missing, len(diffs), len(NAMED))
    return not diffs and not missing, text + ("; first: %s" % " | ".join(diffs[:3]) if diffs else "")


def claim_x41(ask, searches, events, now_ms):
    rows, ok = [], True

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
    beats = sources(ask, INDEX, {"term": {"event.action": "heartbeat"}}) or []
    one("heartbeats", len(beats), sum(1 for e in events if e.get("kind") == "heartbeat"))
    hosts = {}
    for d in beats:
        last, beat = instant_ms(get(d, "event.ingested")), get(d, "raqib.watch.beat")
        if last is None or not isinstance(beat, (int, float)):
            continue
        was = hosts.get(get(d, "host.name"), (last, beat))
        hosts[get(d, "host.name")] = (max(was[0], last), max(was[1], beat))
    deadlines = {h: float(last) + 2000.0 * beat for h, (last, beat) in hosts.items()}
    nows = [now_ms] + ([int(min(deadlines.values())) + 1, int(max(deadlines.values())) + 1] if deadlines else [])
    for now in nows:
        want = sorted(h for h, d in deadlines.items() if d < now)
        _, code, got = run_search(ask, INDEX, searches["silence.json"], {"now": str(now)})
        buckets = got.get("aggregations", {}).get("hosts", {}).get("buckets", []) if code == 200 else None
        have = sorted(b.get("key") for b in buckets) if buckets is not None else "error %s" % code
        one("silent at %d" % now, len(have) if isinstance(have, list) else have, len(want))
        ok = ok and have == want
    return ok, "; ".join(rows) + " (each: the engine's/the count here)"


def claim_x42(ask, sigma, target, events):
    rules_dir = os.path.join(SIEM, "sigma", "rules")
    pipeline = os.path.join(SIEM, "sigma", "pipeline-ecs.yml")
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
        got = total(*ask("POST", "/%s/_search" % INDEX, {"size": 0, "track_total_hits": True,
                                                         "query": {"query_string": {"query": query}}}))
        ok = ok and got == want
        rows.append("%s %s/%s" % (name[:-4], got, want))
    return ok, "; ".join(rows) + " (each: the engine's/the count here; target %s)" % target


def put(ask, path, body, say, what):
    code, got = ask("PUT", path, body)
    say("INSTALL %s: http %s%s" % (what, code, "" if code == 200 else " " + json.dumps(got)[:400]))
    return code == 200


def main(argv=None, ask=None, sigma=None, out=print):
    parser = argparse.ArgumentParser(description="the rig's claims of siem/ (X39 to X42)")
    parser.add_argument("events", nargs="+", help="EVENT.md (its examples) and events files")
    parser.add_argument("--url", default="http://127.0.0.1:9200")
    parser.add_argument("--wait", type=float, default=180.0, help="seconds to wait for the engine")
    parser.add_argument("--sigma", default=None, help="sigma-cli's path (default: sigma on PATH)")
    parser.add_argument("--summary", default=None, help="a file the rows are appended to")
    args = parser.parse_args(argv)
    ask = ask or http_ask(args.url.rstrip("/"))
    rows = []

    def row(n, word, text):
        line = "%-7s X%d %s: %s" % (word, n, dict(CLAIMS)[n], text)
        rows.append(line)
        out(line)

    lines = lines_of(args.events, out)
    engine = wait_engine(ask, args.wait)
    if engine is None:
        out("ENGINE did not answer at %s in %d s" % (args.url, args.wait))
        for n, _ in CLAIMS:
            row(n, "n/a", "the engine did not answer at %s in %d s: not run" % (args.url, args.wait))
        return finish(rows, args.summary)
    distribution, number = engine
    folder = "opensearch" if distribution == "opensearch" else "elastic"
    target = "opensearch_lucene" if folder == "opensearch" else "lucene"
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
    for index in (INDEX, BAD_INDEX):
        ask("DELETE", "/" + index)
    installed = (put(ask, "/_ingest/pipeline/" + PIPELINE_ID, pipeline, out, "the pipeline")
                 & put(ask, "/_index_template/" + TEMPLATE_ID, template, out, "the template"))
    if not installed:
        for n, _ in CLAIMS:
            row(n, "MISSED", "the engine refused the content of siem/%s (above)" % folder)
        return finish(rows, args.summary)
    events_lines = [x for x in lines if event_of(x) is not None]
    events = [event_of(x) for x in events_lines]
    for n, claim in ((39, lambda: claim_x39(ask, lines, events)), (40, lambda: claim_x40(ask, events_lines)),
                     (41, lambda: claim_x41(ask, searches, events, int(time.time() * 1000)))):
        ok, text = claim()
        row(n, "MET" if ok else "MISSED", text)
    if sigma is None:
        path = args.sigma or shutil.which("sigma")
        if not path:
            row(42, "n/a", "sigma-cli is not installed here (no sigma on PATH): not run")
            return finish(rows, args.summary)
        sigma = sigma_cli(path)
    ok, text = claim_x42(ask, sigma, target, events)
    row(42, "MET" if ok else "MISSED", text)
    return finish(rows, args.summary)


def finish(rows, summary):
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("```\n" + "\n".join(rows) + "\n```\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
