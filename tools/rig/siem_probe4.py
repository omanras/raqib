"""Probe only (never merged): what the second review of M16.1 suspects and nobody fed (ADR-0017). With the content of
claude/M16.1 installed, on a real engine:
  D2. lines the pipeline's check passes and the engine may refuse: a key of 40000 characters (top-level and unknown;
      inside a part kept whole; inside an item of a list), a number beyond a double (1e400), a beat of 1e308.
  E2. a shipper's own fields of another shape: `host`, `event`, `error` as a text, with an event and with a line
      that is not JSON.
  F.  the runs with no end, ordered so that a bound cuts the ended runs first: which orders an engine takes in a
      multi_terms, what its answer says of a cut, and the same by a composite.
It talks to 127.0.0.1 only."""
import copy
import json
import re
import sys

import siem_probe3 as p3

ask, send, INDEX = p3.ask, p3.send, p3.INDEX


def main(spec, content):
    distribution, number = p3.wait_engine()
    print("ENGINE %s %s" % (distribution, number))
    text = open(spec, encoding="utf-8").read()
    m = re.search(r"### example: heartbeat\n(?:.*\n)*?```json\n(.+?)\n```", text)
    beat = json.loads(m.group(1))
    n = [1000]

    def made(host="odd2.example", run="odd2", beat_s=600, **over):
        ev = copy.deepcopy(beat)
        n[0] += 1
        ev["watch"].update(host=host, run=run, beat=float(beat_s))
        ev["id"], ev["n"] = "%s:%d" % (run, n[0]), n[0]
        ev.update(over)
        return ev

    def line(ev):
        return json.dumps(ev, sort_keys=True, separators=(",", ":"))

    def odd(label, first, extra=None):
        index = INDEX + "-odd2-" + label
        got = send([first], index=index, extra=extra) + send([made(run="odd2-next")], index=index)
        code, hit = ask("POST", "/%s/_search" % index, {"size": 5, "_source": [
            "event.kind", "error.message", "host", "raqib.unknown_keys", "raqib.watch.beat", "error", "event.action"]})
        kept = [json.dumps(h["_source"], sort_keys=True)[:230] for h in hit.get("hits", {}).get("hits", [])] if code == 200 else code
        print("%-30s the line: %s %s %s; the line after it: %s\n      kept: %s" % (
            label, got[0][0], got[0][1] or "", (got[0][2] if got[0][1] else "")[:150], got[1][0], kept))

    long_key = "k" * 40000
    odd("D2 a-long-unknown-key", line(made(**{long_key: 1})))
    odd("D2 a-300-unknown-key", line(made(**{"k" * 300: 1})))
    odd("D2 a-2000-unknown-key", line(made(**{"k" * 2000: 1})))
    odd("D2 a-long-key-in-result", line(made(result={"exit": 0, "word": "CLEAN", long_key: "x"})))
    odd("D2 a-long-key-in-evidence", line(made(evidence={"cites": [{long_key: "x"}]})))
    odd("D2 a-long-key-in-watch", line(made(watch=dict(made()["watch"], **{long_key: "x"}))))
    odd("D2 beat-1e400", line(made()).replace('"beat":600.0', '"beat":1e400'))
    odd("D2 beat-1e308", line(made()).replace('"beat":600.0', '"beat":1e308'))
    odd("D2 beat-negative", line(made()).replace('"beat":600.0', '"beat":-5'))
    with_rule = made(kind="finding", rule={"id": "X", "class": "NET", "kind": "pattern", "fp_budget": 0.5})
    odd("D2 fp_budget-1e400", line(with_rule).replace('"fp_budget":0.5', '"fp_budget":1e400'))
    odd("D2 n-a-float-1.0", line(made()).replace('"n":%d' % n[0], '"n":1.0'))
    for field in ("host", "event", "error", "observer", "rule", "process"):
        odd("E2 %s-a-text, an event" % field, line(made()), extra={field: "a-shipper-text"})
        odd("E2 %s-a-text, not JSON" % field, "{not json", extra={field: "a-shipper-text"})
    odd("E2 message-missing", line(made()), extra={"message": None})
    # F: the order of the runs with no end, on probe3's own index (its hosts a..h are there, read minutes later)
    deadline = {"max": {"script": {"source": p3.DEADLINE}}}
    ends = {"filter": {"bool": {"filter": [{"term": {"event.action": "watch"}}, {"term": {"raqib.state": "end"}}]}}}
    for order in ([{"ends": "asc"}, {"deadline": "desc"}], [{"ends._count": "asc"}, {"deadline": "desc"}],
                  [{"ends>_count": "asc"}, {"deadline": "desc"}], {"deadline": "desc"}, None):
        mt = {"terms": [{"field": "host.name"}, {"field": "raqib.watch.run"}], "size": 3}
        if order is not None:
            mt["order"] = order
        code, got = ask("POST", "/%s/_search" % INDEX, {"size": 0, "query": {"exists": {"field": "raqib.watch.beat"}},
                        "aggs": {"runs": {"multi_terms": mt, "aggs": {"deadline": deadline, "ends": ends}}}})
        if code != 200:
            print("F. multi_terms order %s -> error %s: %s" % (json.dumps(order), code, json.dumps(got)[:260]))
            continue
        runs = got["aggregations"]["runs"]
        print("F. multi_terms order %s, size 3 -> %s; sum_other_doc_count %s" % (json.dumps(order), [
            "%s ends=%d deadline=%d" % ("/".join(b["key"]), b["ends"]["doc_count"], b["deadline"]["value"])
            for b in runs["buckets"]], runs.get("sum_other_doc_count")))
    after, pages, listed = None, 0, []
    while pages < 10:
        comp = {"size": 3, "sources": [{"host": {"terms": {"field": "host.name"}}},
                                       {"run": {"terms": {"field": "raqib.watch.run"}}}]}
        if after:
            comp["after"] = after
        code, got = ask("POST", "/%s/_search" % INDEX, {"size": 0, "query": {"exists": {"field": "raqib.watch.beat"}},
                        "aggs": {"runs": {"composite": comp, "aggs": {"deadline": deadline, "ends": ends, "stopped": {
                            "bucket_selector": {"buckets_path": {"d": "deadline", "e": "ends._count"},
                                                "script": "params.e == 0 && params.d < System.currentTimeMillis()"}}}}}})
        if code != 200:
            print("F. composite with a selector -> error %s: %s" % (code, json.dumps(got)[:260]))
            break
        runs = got["aggregations"]["runs"]
        pages += 1
        listed += ["%s/%s" % (b["key"]["host"], b["key"]["run"]) for b in runs["buckets"]]
        after = runs.get("after_key")
        if not after:
            break
    print("F. composite with a selector, pages of 3: %d page(s), listed %s" % (pages, listed))
    code, got = ask("POST", "/%s/_search" % INDEX, {"size": 0, "aggs": {"runs": {"multi_terms": {"terms": [
        {"field": "host.name"}, {"field": "raqib.watch.run"}], "size": 100}, "aggs": {"deadline": deadline, "ends": ends}}}})
    print("F. every run of the index: %s" % (["%s ends=%d" % ("/".join(b["key"]), b["ends"]["doc_count"])
                                              for b in got.get("aggregations", {}).get("runs", {}).get("buckets", [])],))
    capped = p3.DEADLINE.replace("doc['raqib.watch.beat'].value", "Math.min(doc['raqib.watch.beat'].value, 86400.0)")
    code, got = ask("POST", "/%s/_search" % INDEX, {"size": 0, "aggs": {"hosts": {"terms": {"field": "host.name", "size": 50},
                    "aggs": {"deadline": {"max": {"script": {"source": capped}}}, "plain": deadline}}}})
    print("G. a beat counted to a day at most: %s" % (["%s %d (plain %d)" % (b["key"], b["deadline"]["value"], b["plain"]["value"])
          for b in got.get("aggregations", {}).get("hosts", {}).get("buckets", [])] if code == 200 else json.dumps(got)[:260],))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
