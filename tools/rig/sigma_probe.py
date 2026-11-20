"""Probe only (never merged): the drafts of Sigma rules over Raqib's events, converted by sigma-cli and run against
the engine on this machine's own port (M16, before it is ruled). argv: files of queries, one query a line."""
import json
import sys
import urllib.error
import urllib.request


def count(query):
    body = json.dumps({"size": 0, "track_total_hits": True,
                       "query": {"query_string": {"query": query}}}).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:9200/raqib-ecs/_search", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))["hits"]["total"]["value"]
    except urllib.error.HTTPError as exc:
        return "error %s: %s" % (exc.code, exc.read().decode("utf-8", "replace")[:300])


for path in sys.argv[1:]:
    for line in open(path, encoding="utf-8"):
        if line.strip():
            print("SIGMA %s\n      -> %s document(s)" % (line.strip()[:400], count(line.strip())))
