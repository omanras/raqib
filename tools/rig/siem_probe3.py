"""Probe only (never merged): the search for silence as the review of M16.1 asks it to be ruled (ADR-0017 S-5), tried
against a real engine before the ruling. With the content of claude/M16.1 installed (siem/<engine>/pipeline.json and
template.json), made-up hosts under .example say lines and the engine's own clock judges them:
  A. a deadline for every line - its arrival and two of its own beats - and a host silent where the engine's clock
     has passed the latest deadline any of its lines gave: is that one search, with no time given by the caller?
  B. the runs that stopped with no end (killed): by host and run, the same deadline, and no end said.
  C. a search on a key inside a part kept whole (result.word of a watch's end).
  D. lines that are not as the spec has them: refused by the engine, kept as an error, or kept as an event; and
     whether the line after each is kept.
  E. what a shipper's own host fields become.
It talks to 127.0.0.1 only."""
import copy
import json
import re
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:9200"
INDEX = "raqib-events-probe"


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
                v = body.get("version", {})
                return v.get("distribution", "elasticsearch"), v.get("number")
        except OSError:
            pass
        time.sleep(3)
    sys.exit("the engine did not answer in 180 s")


def send(lines, index=INDEX, extra=None):
    docs = []
    for x in lines:
        doc = {"message": x if isinstance(x, str) else json.dumps(x, sort_keys=True, separators=(",", ":"))}
        doc.update(extra or {})
        docs.append(doc)
    body = "".join('{"index":{}}\n' + json.dumps(d) + "\n" for d in docs).encode("utf-8")
    code, got = ask("POST", "/%s/_bulk?refresh=true" % index, body, ndjson=True)
    items = got.get("items", [])
    return [(i.get("index", {}).get("status"), (i.get("index", {}).get("error") or {}).get("type"),
             str((i.get("index", {}).get("error") or {}).get("reason"))[:150]) for i in items] or [(code, "bulk", json.dumps(got)[:200])]


DEADLINE = ("doc['event.ingested'].value.toInstant().toEpochMilli()"
            " + (long)(2000 * doc['raqib.watch.beat'].value)")


def silent_hosts(clock):
    code, got = ask("POST", "/%s/_search" % INDEX, {"size": 0, "aggs": {"hosts": {
        "terms": {"field": "host.name", "size": 10000, "order": {"deadline": "asc"}},
        "aggs": {"deadline": {"max": {"script": {"source": DEADLINE}}},
                 "silent": {"bucket_selector": {"buckets_path": {"d": "deadline"},
                                                "script": "params.d < %s" % clock}}}}}})
    if code != 200:
        return "error %s: %s" % (code, json.dumps(got)[:400])
    return sorted(b["key"] for b in got["aggregations"]["hosts"]["buckets"])


def killed_runs(clock):
    code, got = ask("POST", "/%s/_search" % INDEX, {"size": 0, "aggs": {"runs": {
        "multi_terms": {"terms": [{"field": "host.name"}, {"field": "raqib.watch.run"}], "size": 10000},
        "aggs": {"deadline": {"max": {"script": {"source": DEADLINE}}},
                 "ends": {"filter": {"bool": {"filter": [{"term": {"event.action": "watch"}},
                                                         {"term": {"raqib.state": "end"}}]}}},
                 "killed": {"bucket_selector": {"buckets_path": {"d": "deadline", "e": "ends._count"},
                                                "script": "params.e == 0 && params.d < %s" % clock}}}}}})
    if code != 200:
        return "error %s: %s" % (code, json.dumps(got)[:400])
    return sorted("/".join(b["key"]) for b in got["aggregations"]["runs"]["buckets"])


def main(spec, content):
    distribution, number = wait_engine()
    print("ENGINE %s %s" % (distribution, number))
    for what, path, file_ in (("pipeline", "/_ingest/pipeline/raqib-event-1", "pipeline.json"),
                              ("template", "/_index_template/raqib-events", "template.json")):
        code, got = ask("PUT", path, json.load(open("%s/%s" % (content, file_), encoding="utf-8")))
        print("INSTALL the %s: http %s %s" % (what, code, "" if code == 200 else json.dumps(got)[:300]))
    text = open(spec, encoding="utf-8").read()

    def example(label):
        m = re.search(r"### example: %s\n(?:.*\n)*?```json\n(.+?)\n```" % re.escape(label), text)
        return json.loads(m.group(1))
    beat, start, end = example("heartbeat"), example("watch start"), example("watch end")
    n = [0]

    def made(base, host, run, beat_s, **over):
        ev = copy.deepcopy(base)
        n[0] += 1
        ev["watch"].update(host=host, run=run, beat=float(beat_s))
        ev["id"], ev["n"] = "%s:%d" % (run, n[0]), n[0]
        ev.update(over)
        return ev
    t0 = time.time()
    first = [made(start, "a.example", "a1", 1), made(beat, "a.example", "a1", 1),
             made(beat, "b.example", "b1", 600),
             made(beat, "c.example", "c1", 3),
             made(start, "d.example", "d1", 1),
             made(beat, "e.example", "e1", 600, time="2000-01-01T00:00:00.000Z"),
             made(beat, "f.example", "f1", 1, time="2099-01-01T00:00:00.000Z"),
             made(start, "g.example", "g1", 1), made(end, "g.example", "g1", 1)]
    print("SEND 9 lines of 7 hosts: %s" % sorted(set(str(s[0]) for s in send(first))))
    time.sleep(1.0)
    print("SEND c again with a beat of 1: %s" % send([made(beat, "c.example", "c2", 1)])[0][0])
    for clock in ("System.currentTimeMillis()", "new Date().getTime()"):
        print("A. now, by %s: silent %s" % (clock, silent_hosts(clock)))
    clock = "System.currentTimeMillis()"
    if isinstance(silent_hosts(clock), str):
        clock = "new Date().getTime()"
    if isinstance(silent_hosts(clock), str):
        clock = None
        print("A. the engine's own clock cannot be read in the selector: a time must be given by the caller")
    for wait_until, expect in ((3.6, "a, d, f, g (a beat of 1 s: two beats passed)"),
                               (8.0, "a, c, d, f, g (c's first line gave it 6 s)")):
        time.sleep(max(0.0, t0 + wait_until - time.time()))
        got = silent_hosts(clock or "%dL" % int(time.time() * 1000))
        print("A. %.1f s after the first lines: silent %s; expected %s; never b (600 s) nor e (its time is 2000,"
              " its arrival is now)" % (time.time() - t0, got, expect))
    print("B. the runs that stopped with no end: %s; expected a.example/a1, c.example/c1, c.example/c2,"
          " d.example/d1, f.example/f1, and never g.example/g1 (it said its end)" % (
              killed_runs(clock or "%dL" % int(time.time() * 1000)),))
    inc = made(end, "h.example", "h1", 600, result={"exit": 3, "word": "INCOMPLETE"})
    print("SEND a watch's end that is INCOMPLETE: %s" % send([inc])[0][0])
    for q in ("event.action:watch AND raqib.result.word:INCOMPLETE", "raqib.result.word:INCOMPLETE",
              "raqib.result.exit:3"):
        code, got = ask("POST", "/%s/_search" % INDEX, {"size": 0, "track_total_hits": True,
                                                        "query": {"query_string": {"query": q}}})
        print("C. %-52s -> %s" % (q, got.get("hits", {}).get("total", {}).get("value") if code == 200 else
                                  "error %s: %s" % (code, json.dumps(got)[:200])))

    def odd(label, change):
        ev = made(beat, "odd.example", "odd", 600)
        line = change(ev)
        got = send([line, made(beat, "odd.example", "odd-next", 600)], index=INDEX + "-odd-" + label)
        code, hit = ask("POST", "/%s-odd-%s/_search" % (INDEX, label), {"size": 5, "_source": ["event.kind",
                                                                                              "error.message"]})
        kinds = [h["_source"].get("event", {}).get("kind") for h in hit.get("hits", {}).get("hits", [])] if code == 200 else code
        print("D. %-34s the line: %s %s; the line after it: %s; kept as: %s" % (
            label, got[0][0], got[0][1] or "", got[1][0] if len(got) > 1 else "?", kinds))

    def setk(path, value):
        def change(ev):
            cur = ev
            for k in path[:-1]:
                cur = cur.setdefault(k, {})
            cur[path[-1]] = value
            return ev
        return change
    deep = {}
    cur = deep
    for _ in range(25):
        cur["k"] = {}
        cur = cur["k"]
    odd("an-empty-key", setk([""], 1))
    odd("run-an-object", setk(["watch", "run"], {"x": 1}))
    odd("kind-unknown", setk(["kind"], "no-such-kind"))
    odd("n-missing", lambda ev: {k: v for k, v in ev.items() if k != "n"})
    odd("n-beyond-a-long", setk(["n"], 2 ** 70))
    odd("alarm-a-string", setk(["alarm"], "true"))
    odd("deep-unknown-key", setk(["zz"], deep))
    odd("deep-evidence", setk(["evidence"], deep))
    odd("many-unknown-keys", lambda ev: dict(ev, **{"u%04d" % i: i for i in range(1001)}))
    odd("a-long-word", setk(["knocked"], {"status": "sent", "called": "x" * 40000}))
    odd("not-json", lambda ev: "{not json")
    odd("schema-2", setk(["schema"], "raqib-event/2"))
    got = send([made(beat, "real.example", "s1", 600)], index=INDEX + "-shipper",
               extra={"host": {"hostname": "shipper-name", "ip": "192.0.2.7"}, "agent": {"type": "filebeat"}})
    code, hit = ask("POST", "/%s-shipper/_search" % INDEX, {"size": 1, "_source": ["host", "agent"]})
    print("E. a shipper's own host fields: sent %s; kept %s" % (got[0][0], json.dumps(
        hit.get("hits", {}).get("hits", [{}])[0].get("_source")) if code == 200 else code))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
