"""Probe only (never merged): what a search engine of a SOC (Elasticsearch, OpenSearch) does with Raqib's events,
before the ready content of M16 is ruled. It measures, against an engine on this machine's own port:
  A. the events as they are (the file's lines, each a document), with the engine's own guessing of the fields:
     how many it refuses, and why (two events that hold one key as two kinds of value);
  B. the same lines through a pipeline that follows docs/specs/EVENT.md's Mapping (ECS names, the rest under
     `raqib`), with one template: how many it refuses, and that each named field is there and can be searched;
  C. the searches a SOC would keep (an alarm; a hole of the capture; the hosts' latest heartbeat by the engine's
     own clock of arrival), each run against B and its count said.
The events are the examples of EVENT.md and, where a file is named, a real watch's events file.
It is never imported by raqib; it talks to 127.0.0.1 only."""
import json
import re
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:9200"
EXAMPLE = re.compile(r"^```json\n(.+?)\n```", re.M)

PIPELINE = {
    "description": "raqib-event/1 to ECS, as docs/specs/EVENT.md's Mapping names it; the rest stays under raqib",
    "processors": [
        {"set": {"field": "event.original", "copy_from": "message"}},
        {"json": {"field": "message", "target_field": "raqib"}},
        {"fail": {"if": "ctx.raqib?.schema != 'raqib-event/1'", "message": "not a raqib-event/1 line"}},
        {"date": {"field": "raqib.time", "formats": ["ISO8601"], "target_field": "@timestamp"}},
        {"set": {"field": "event.ingested", "value": "{{{_ingest.timestamp}}}"}},
        {"script": {"lang": "painless", "source": (
            "def s = ['high': 4, 'medium': 3, 'low': 2, 'info': 1, 'hole': 3];"
            "if (s.containsKey(ctx.raqib.severity)) { ctx.event.severity = s[ctx.raqib.severity]; }"
            "ctx.event.kind = ctx.raqib.alarm == true ? 'alert' : 'event';"
            "ctx.event.action = ctx.raqib.kind; ctx.event.id = ctx.raqib.id;"
            "ctx.event.module = 'raqib'; ctx.event.dataset = 'raqib.event';"
            "ctx.message = ctx.raqib.summary;"
            "ctx.observer = ['product': 'Raqib', 'vendor': 'Raqib', 'type': 'agent-watcher'];"
            "if (ctx.raqib.watch != null) {"
            "  if (ctx.raqib.watch.host != null) { ctx.host = ['name': ctx.raqib.watch.host]; }"
            "  if (ctx.raqib.watch.version != null) { ctx.observer.version = ctx.raqib.watch.version; } }"
            "if (ctx.raqib.rule != null) { ctx.rule = ['id': ctx.raqib.rule.id, 'name': ctx.raqib.rule.id];"
            "  if (ctx.raqib.rule['class'] != null) { ctx.rule.category = ctx.raqib.rule['class']; }"
            "  if (ctx.raqib.rule.attack != null) { ctx.threat = ['technique': ['id': ctx.raqib.rule.attack]]; } }"
            "if (ctx.raqib.subject != null) { def p = [:];"
            "  if (ctx.raqib.subject.pid != null) { p.pid = ctx.raqib.subject.pid; }"
            "  if (ctx.raqib.subject.image != null) { p.name = ctx.raqib.subject.image; }"
            "  if (p.size() > 0) { ctx.process = p; } }")}},
    ],
    "on_failure": [{"set": {"field": "error.message", "value": "{{{_ingest.on_failure_message}}}"}},
                   {"set": {"field": "event.kind", "value": "pipeline_error"}}],
}
# what the engine must not guess: the parts whose shape differs from kind to kind are kept whole and searched as
# keywords (flattened / flat_object), the named ones are ECS's own kinds
TEMPLATE_ES = {"index_patterns": ["raqib-ecs*"], "template": {"mappings": {
    "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword",
                                                                                 "ignore_above": 1024}}}],
    "properties": {
        "@timestamp": {"type": "date"}, "message": {"type": "text"},
        "event": {"properties": {"original": {"type": "keyword", "index": False, "doc_values": False},
                                 "ingested": {"type": "date"}, "severity": {"type": "long"}}},
        "process": {"properties": {"pid": {"type": "long"}}},
        "raqib": {"properties": {"time": {"type": "date"}, "n": {"type": "long"}, "rev": {"type": "long"},
                                 "evidence": {"type": "FLAT"}, "counts": {"type": "FLAT"},
                                 "result": {"type": "FLAT"}, "knocked": {"type": "FLAT"},
                                 "subject": {"type": "FLAT"}, "hole": {"type": "FLAT"}}}}}}}

SEARCHES = (
    ("an alarm", {"bool": {"filter": [{"term": {"event.kind": "alert"}}]}}),
    ("a finding of a rule, by its id", {"bool": {"filter": [{"exists": {"field": "rule.id"}}]}}),
    ("a finding with an ATT&CK technique", {"bool": {"filter": [{"exists": {"field": "threat.technique.id"}}]}}),
    ("a hole of the capture", {"bool": {"filter": [{"term": {"event.action": "hole"}}]}}),
    ("a heartbeat", {"bool": {"filter": [{"term": {"event.action": "heartbeat"}}]}}),
    ("a watch that ended with a result that is not 0",
     {"bool": {"filter": [{"term": {"event.action": "watch"}}, {"exists": {"field": "raqib.result"}}],
               "must_not": [{"term": {"raqib.result.exit": "0"}}]}}),
)


def ask(method, path, body=None, ndjson=False):
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={
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


def wait_engine():
    end = time.monotonic() + 180
    while time.monotonic() < end:
        try:
            code, body = ask("GET", "/")
            if code == 200:
                version = body.get("version", {})
                return version.get("distribution", "elasticsearch"), version.get("number")
        except OSError:
            pass
        time.sleep(3)
    sys.exit("the engine did not answer in 180 s")


def lines_of(paths):
    out = []
    for path in paths:
        text = open(path, encoding="utf-8").read()
        got = EXAMPLE.findall(text) if path.endswith(".md") else [x for x in text.splitlines() if x.strip()]
        print("EVENTS %s: %d line(s)" % (path.rsplit("/", 1)[-1], len(got)))
        out += got
    return out


def bulk(index, docs, pipeline=None):
    body = "".join('{"index":{}}\n' + json.dumps(d) + "\n" for d in docs).encode("utf-8")
    code, got = ask("POST", "/%s/_bulk?refresh=true%s" % (index, "&pipeline=" + pipeline if pipeline else ""),
                    body, ndjson=True)
    items = got.get("items", [])
    bad = [i["index"]["error"] for i in items if i.get("index", {}).get("error")]
    return code, len(items) - len(bad), bad


def reasons(bad):
    seen = {}
    for err in bad:
        why = "%s: %s" % (err.get("type"), re.sub(r"\[[^\]]{60,}\]", "[...]", str(err.get("reason")))[:230])
        seen[why] = seen.get(why, 0) + 1
    for why, n in sorted(seen.items(), key=lambda kv: -kv[1])[:12]:
        print("    %d x %s" % (n, why))


def count(index, query):
    code, got = ask("POST", "/%s/_search" % index, {"size": 0, "track_total_hits": True, "query": query})
    return got.get("hits", {}).get("total", {}).get("value") if code == 200 else "error %s: %s" % (
        code, json.dumps(got)[:300])


def main(argv):
    distribution, number = wait_engine()
    print("ENGINE %s %s" % (distribution, number))
    lines = lines_of(argv)
    events = [json.loads(x) for x in lines]
    kinds = {}
    for e in events:
        kinds[e.get("kind")] = kinds.get(e.get("kind"), 0) + 1
    print("KINDS %s" % json.dumps(kinds, sort_keys=True))

    code, kept, bad = bulk("raqib-raw", events)
    print("A. the events as they are, the engine guessing: http %s, %d kept, %d refused" % (code, kept, len(bad)))
    reasons(bad)

    flat = "flat_object" if distribution == "opensearch" else "flattened"
    template = json.loads(json.dumps(TEMPLATE_ES).replace('"FLAT"', '"%s"' % flat))
    code, got = ask("PUT", "/_index_template/raqib-ecs", template)
    print("B. the template: http %s %s" % (code, "" if code == 200 else json.dumps(got)[:400]))
    code, got = ask("PUT", "/_ingest/pipeline/raqib-event-1", PIPELINE)
    print("B. the pipeline: http %s %s" % (code, "" if code == 200 else json.dumps(got)[:600]))
    code, kept, bad = bulk("raqib-ecs", [{"message": x} for x in lines], pipeline="raqib-event-1")
    print("B. the lines through the pipeline: http %s, %d kept, %d refused" % (code, kept, len(bad)))
    reasons(bad)
    print("   pipeline errors kept as documents: %s" % count("raqib-ecs", {"term": {"event.kind": "pipeline_error"}}))
    code, got = ask("POST", "/raqib-ecs/_search", {"size": 1, "query": {"term": {"event.kind": "pipeline_error"}}})
    for hit in got.get("hits", {}).get("hits", []):
        print("   one: %s" % json.dumps(hit["_source"].get("error"))[:400])
    for field in ("@timestamp", "event.id", "event.action", "event.severity", "event.ingested", "message",
                  "host.name", "observer.version", "rule.id", "rule.category", "threat.technique.id",
                  "process.pid", "process.name", "raqib.about", "raqib.watch.run", "raqib.hole.kind",
                  "raqib.knocked.status", "raqib.evidence"):
        print("   %-22s in %s document(s)" % (field, count("raqib-ecs", {"exists": {"field": field}})))
    code, got = ask("GET", "/raqib-ecs/_mapping")
    props = next(iter(got.values()), {}).get("mappings", {}).get("properties", {}) if code == 200 else {}
    print("   the fields the engine made under raqib: %s" % sorted(props.get("raqib", {}).get("properties", {})))

    print("C. the searches a SOC would keep, against B:")
    for name, query in SEARCHES:
        print("   %-48s %s" % (name, count("raqib-ecs", query)))
    code, got = ask("POST", "/raqib-ecs/_search", {"size": 0, "query": {"term": {"event.action": "heartbeat"}},
                    "aggs": {"hosts": {"terms": {"field": "host.name"},
                                       "aggs": {"last": {"max": {"field": "event.ingested"}}}}}})
    rows = got.get("aggregations", {}).get("hosts", {}).get("buckets", []) if code == 200 else []
    print("   the hosts' latest heartbeat by the engine's own clock: %s" % (
        [(b["key"], b["last"].get("value_as_string")) for b in rows] if code == 200 else json.dumps(got)[:300]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
