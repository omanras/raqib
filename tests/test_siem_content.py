"""M16.1 (ADR-0017 S-1 to S-5): the ready content of siem/, held without an engine (E5), and the rig's runner
tools/rig/siem_run.py held against a stand-in engine (E6): its mapping, its counts, its rows, and what it says
when the engine does not answer. No engine, no network: the stand-in is a function, and the engine that does not
answer is a closed port of this machine's loopback."""
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tools" / "rig"))

from raqib.rules import yamlite  # noqa: E402
import siem_content  # noqa: E402
import siem_run  # noqa: E402

SIEM = ROOT / "siem"
EVENT_MD = (ROOT / "docs" / "specs" / "EVENT.md").read_text(encoding="utf-8")
EXAMPLES = siem_run.EXAMPLE.findall(EVENT_MD)
ENGINES = ("elastic", "opensearch")


def keys_table():
    """key -> its ECS column's first field, from EVENT.md's Keys table."""
    rows = EVENT_MD.split("## Keys", 1)[1].split("## Mapping", 1)[0].splitlines()
    out = {}
    for row in rows:
        if row.startswith("| `"):
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            out[cells[0].strip("`")] = re.search(r"`([^`]+)`", cells[5]).group(1)
    return out


KEYS = keys_table()
NAMED_ECS = sorted({v for v in KEYS.values() if not v.startswith("raqib.")} | {"observer.product"})


def load(path):
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix == ".json" else yamlite.loads(text)


def sigma_rules():
    return {p.name: load(p) for p in sorted((SIEM / "sigma" / "rules").glob("*.yml"))}


# ---------------------------------------------------------------- E5: the content, without an engine

def test_e5_every_json_and_yaml_file_of_siem_parses_with_the_standard_library_or_the_repos_reader():
    files = [p for p in SIEM.rglob("*") if p.is_file()]
    parsed = [p for p in files if p.suffix in (".json", ".yml", ".yaml")]
    assert len(parsed) >= 2 + 2 + 10 + 1 + 8 + 1
    for path in parsed:
        assert load(path) is not None, path
    assert {p.suffix for p in files} <= {".json", ".yml", ".md"}


def test_e1_one_pipeline_serves_both_engines_and_the_templates_differ_only_in_the_whole_object_type():
    assert (SIEM / "elastic" / "pipeline.json").read_bytes() == (SIEM / "opensearch" / "pipeline.json").read_bytes()
    es = (SIEM / "elastic" / "template.json").read_text(encoding="ascii")
    os_ = (SIEM / "opensearch" / "template.json").read_text(encoding="ascii")
    assert es.count('"flattened"') == 6 and "flat_object" not in es and "copy_from" not in es
    assert es.replace('"flattened"', '"flat_object"') == os_
    template = json.loads(es)
    assert template["template"]["settings"]["index"]["default_pipeline"] == "raqib-event-1"
    mappings = template["template"]["mappings"]
    assert mappings["date_detection"] is False   # the trap of S-4: a string that looks like a date is not guessed
    assert mappings["dynamic_templates"][0]["strings"]["mapping"]["type"] == "keyword"
    whole = {k for k, v in mappings["properties"]["raqib"]["properties"].items() if v.get("type") == "flattened"}
    assert whole == {"subject", "evidence", "hole", "knocked", "result", "counts"}   # subject.started among them
    assert "copy_from" not in (SIEM / "elastic" / "pipeline.json").read_text(encoding="ascii")


def test_e1_every_ecs_field_the_mapping_names_is_set_by_the_pipelines_text():
    text = json.dumps(load(SIEM / "elastic" / "pipeline.json"))   # one line: the needles below are compact
    sets = {"@timestamp": '"target_field": "@timestamp"', "event.id": "ctx.event.id =",
            "event.action": "ctx.event.action =", "event.severity": "ctx.event.severity =",
            "event.kind": "ctx.event.kind =", "message": "ctx.message =", "host.name": "ctx.host = ['name':",
            "observer.product": "ctx.observer = ['product': 'Raqib']", "observer.version": "ctx.observer.version =",
            "rule.id": "ctx.rule = ['id':", "rule.category": "ctx.rule.category =",
            "threat.technique.id": "ctx.threat = ['technique': ['id':", "process.pid": "p.pid =",
            "process.name": "p.name ="}
    assert sorted(sets) == NAMED_ECS   # a named key added to the Mapping fails here until the pipeline sets it
    for field, needle in sets.items():
        assert needle in text, field
    for needle in ('"field": "event.original", "value": "{{{message}}}"', '"target_field": "raqib"',
                   '"field": "event.ingested", "value": "{{{_ingest.timestamp}}}"', "pipeline_error",
                   '"field": "error.message", "value": "{{{_ingest.on_failure_message}}}"'):
        assert needle in text, needle
    assert sorted(siem_run.NAMED) == NAMED_ECS


def test_e1_the_runners_mapping_names_exactly_the_mappings_fields_and_keeps_every_other_key_under_raqib():
    assert len(EXAMPLES) >= 18
    for line in EXAMPLES:
        ev = json.loads(line)
        doc = siem_run.ecs_of(line)
        assert doc["event"]["original"] == line and doc["@timestamp"] == ev["time"]
        assert doc["event"]["kind"] == ("alert" if ev.get("alarm") is True else "event")
        assert doc["host"]["name"] == ev["watch"]["host"] and doc["observer"]["product"] == "Raqib"
        assert doc["event"]["severity"] == {"high": 4, "medium": 3, "low": 2, "info": 1, "hole": 3}[ev["severity"]]
        for key in ("time", "id", "kind", "severity", "alarm", "summary"):
            assert key not in doc["raqib"]
        assert "host" not in doc["raqib"]["watch"] and "version" not in doc["raqib"]["watch"]
        for part in ("rule", "subject"):
            for key in ("id", "class", "attack", "pid", "image"):
                assert key not in doc["raqib"].get(part, {})
        put_back = dict(doc["raqib"])
        assert put_back.get("about") == ev["about"] and put_back["n"] == ev["n"]


def test_e2_each_search_is_a_file_with_one_sentence_and_the_same_in_both_engines():
    names = sorted(p.name for p in (SIEM / "elastic" / "searches").iterdir())
    assert names == ["alarm.json", "hole.json", "rule.json", "silence.json", "watch-not-0.json"]
    for name in names:
        es, os_ = (SIEM / e / "searches" / name for e in ENGINES)
        assert es.read_bytes() == os_.read_bytes(), name
        search = load(es)
        assert set(search) == {"finds", "request", "body"}
        assert search["finds"].endswith(".") and search["finds"].count(". ") == 0, name
        assert search["request"] in ("POST raqib-events*/_search", "POST raqib-events*/_search/template")
    silence = load(SIEM / "elastic" / "searches" / "silence.json")
    text = json.dumps(silence["body"])
    assert "event.ingested" in text and "@timestamp" not in text and "raqib.watch.beat" in text
    assert "2000.0 * params.beat" in text and '"term": {"event.action": "heartbeat"}' in text


def test_e2_every_field_a_search_names_is_a_field_the_pipeline_writes():
    fields = set(NAMED_ECS) | {"event.ingested", "event.original"} | {v for v in KEYS.values()}
    for path in (SIEM / "elastic" / "searches").iterdir():
        body = json.dumps(load(path)["body"])
        for field in re.findall(r'"field": "([^"]+)"', body):
            assert field in fields, (path.name, field)
        for field in re.findall(r'\{"term": \{"([^"]+)"', body):
            assert field in fields, (path.name, field)


def test_e3_every_key_a_sigma_rule_or_its_pipeline_names_is_a_key_of_the_spec():
    pipeline = load(SIEM / "sigma" / "pipeline-ecs.yml")
    by_id = {t["id"]: t for t in pipeline["transformations"]}
    assert by_id["raqib_ecs_fields"]["mapping"] == KEYS   # every key to its ECS column, and no other
    assert by_id["raqib_alarm_true_is_alert"]["field_name_conditions"][0]["fields"] == ["alarm"]
    assert by_id["raqib_severity_number"]["mapping"] == {"high": "4", "medium": "3", "low": "2", "info": "1",
                                                         "hole": "3"}
    for name, rule in sigma_rules().items():
        assert rule["logsource"] == {"product": "raqib"}, name
        for key, value in rule["detection"]["selection"].items():
            assert key.split("|")[0] in KEYS, (name, key)
            if key == "alarm":
                assert value is True, name   # the pipeline's value step reads alarm as true only


def test_e3_ids_are_unique_levels_are_set_and_attack_tags_are_only_the_catalogs():
    rules = sigma_rules()
    catalog = siem_content.catalog()
    ids = [r["id"] for r in rules.values()]
    assert len(set(ids)) == len(ids) == 8
    assert all(re.match(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z", i) for i in ids)
    assert len({r["title"] for r in rules.values()}) == 8
    classes = set()
    for name, rule in rules.items():
        assert rule["level"] in ("low", "medium", "high", "critical") and rule["status"] == "experimental"
        sel = rule["detection"]["selection"]
        matched = [c for c in catalog if sel.get("rule.class") in (None, c["class"])
                   and sel.get("rule.id") in (None, c["id"])] if ("rule.class" in sel or "rule.id" in sel) else []
        allowed = {"attack." + t.lower() for c in matched for t in c["attack"]}
        tags = set(rule.get("tags") or [])
        assert tags == allowed, (name, tags, allowed)   # exactly the techniques the catalog's rules hold
        if matched:
            order = ["low", "medium", "high"]
            assert rule["level"] == max((c["severity"] for c in matched), key=order.index), name
        classes.add(sel.get("rule.class") or sel.get("rule.id") or sel.get("kind") if not isinstance(
            sel.get("kind"), list) or "rule.class" in sel or "rule.id" in sel else "alarm")
    assert classes >= {"PERSIST", "NET", "DESTRUCT", "SECRET", "NEW-AGENT-UNKNOWN", "hole", "watch", "alarm"}


def test_e3_the_sigma_rules_match_the_examples_they_are_written_for():
    events = [json.loads(x) for x in EXAMPLES]
    count = {name: sum(1 for e in events if siem_run.sigma_match(r["detection"], e))
             for name, r in sigma_rules().items()}
    assert count["raqib_hole.yml"] == sum(1 for e in events if e["kind"] == "hole") >= 3
    assert count["raqib_alarm.yml"] >= 1
    assert count["raqib_watch_incomplete.yml"] == sum(1 for e in events if e["kind"] == "watch" and e.get(
        "result", {}).get("word") == "INCOMPLETE")


def test_e4_the_attack_table_and_layer_are_the_catalogs_and_a_new_rule_fails_the_check(tmp_path):
    assert siem_content.differences() == []
    done = subprocess.run([sys.executable, str(ROOT / "tools" / "siem_content.py"), "--check"],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    rules = siem_content.catalog()
    assert len(rules) == len(list((ROOT / "raqib" / "rules" / "catalog").glob("*.yaml")))
    table = (SIEM / "attack" / "rules.md").read_text(encoding="ascii")
    for rule in rules:
        row = "| %s | %s | %s | %s | %s | %s |" % (rule["id"], rule["title"], rule["class"], rule["kind"],
                                                  rule["severity"], ", ".join(rule["attack"]) or "none")
        assert row in table, rule["id"]
    layer = load(SIEM / "attack" / "raqib-layer.json")
    assert {t["techniqueID"] for t in layer["techniques"]} == {t for r in rules for t in r["attack"]}
    assert layer["domain"] == "enterprise-attack"
    more = rules + [{"id": "ZZ-NEW", "title": "A new rule", "class": "NET", "kind": "signature",
                     "severity": "high", "attack": ["T1095"]}]
    diffs = siem_content.differences(rules=more)
    assert any("rules.md" in d and "ZZ-NEW" in d for d in diffs)
    assert any("raqib-layer.json" in d and "T1095" in d for d in diffs)
    assert siem_content.main(["--nothing"]) == 2


def test_e5_siem_is_ascii_and_holds_no_address_host_or_persons_name():
    for path in (p for p in SIEM.rglob("*") if p.is_file()):
        text = path.read_bytes().decode("ascii")   # raises on anything but ASCII
        assert not re.search(r"(?<![\w.])\d{1,3}(\.\d{1,3}){3}(?![\w.])", text), path
        assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", text), path   # no address of mail
        assert not re.search(r"/home/|/Users/|\\Users\\|C:\\", text), path
        hosts = set(re.findall(r"\b[a-z0-9-]+\.(?:com|net|org|io|dev|local|lan|internal|corp)\b", text, re.I))
        assert hosts <= set(), (path, hosts)


def test_e5_nothing_under_raqib_imports_or_reads_siem():
    for path in (ROOT / "raqib").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\bsiem\b", text), path
    assert not (ROOT / "siem" / "__init__.py").exists()


def test_e6_the_rig_job_runs_both_engines_on_loopback_and_the_runner():
    text = (ROOT / ".github" / "workflows" / "rig.yml").read_text(encoding="ascii")
    job = text.split("\n  siem:\n", 1)[1]
    assert "elasticsearch:8.15.3" in job and "opensearch:2.17.1" in job
    assert job.count("-p 127.0.0.1:9200:9200") == 2 and "0.0.0.0" not in job
    assert "python tools/rig/siem_run.py docs/specs/EVENT.md" in job and "tools/siem_content.py" not in job
    assert "pip install --disable-pip-version-check -q sigma-cli pysigma-backend-elasticsearch" in job
    assert "curl" not in job   # nothing is sent off the machine


# ---------------------------------------------------------------- E6: the runner, against a stand-in engine

def flat_get(doc, field):
    value = siem_run.get(doc, field)
    return value


class StandIn:
    """A stand-in engine: its pipeline is the runner's own mapping (what the real engine is claimed to do), its
    searches are read from the runner's own requests. `spoil` changes a document; `miscount` a count."""

    def __init__(self, distribution="opensearch", spoil=None, miscount=0):
        self.distribution, self.spoil, self.miscount = distribution, spoil, miscount
        self.indices, self.clock = {}, 0

    def ingest(self, message):
        self.clock += 1
        arrived = "2026-11-20T10:00:%02d.%03d000000Z" % (self.clock // 1000, self.clock % 1000)
        if siem_run.event_of(message) is None:
            return {"event": {"kind": "pipeline_error", "original": message, "ingested": arrived},
                    "error": {"message": "not a raqib-event/1 event"}, "message": message}
        doc = siem_run.ecs_of(message)
        doc["event"]["ingested"] = arrived
        return self.spoil(doc) if self.spoil else doc

    def matches(self, doc, query):
        if "match_all" in query:
            return True
        if "term" in query:
            (field, value), = query["term"].items()
            have = siem_run.get(doc, field)
            return have is not None and str(have).lower() == str(value).lower()
        if "exists" in query:
            return siem_run.get(doc, query["exists"]["field"]) not in (None, [])
        if "query_string" in query:   # the stand-in sigma gives "SIGMA <rule file>"
            rule = yamlite.loads(Path(query["query_string"]["query"].split(" ", 1)[1]).read_text(encoding="utf-8"))
            return siem_run.sigma_match(rule["detection"], json.loads(doc["event"]["original"]))
        bool_ = query["bool"]
        return (all(self.matches(doc, q) for q in bool_.get("filter", []))
                and not any(self.matches(doc, q) for q in bool_.get("must_not", [])))

    def __call__(self, method, path, body=None, ndjson=False):
        if path == "/":
            return 200, {"version": {"distribution": self.distribution, "number": "0.0.0"}}
        if method == "PUT":
            return 200, {"acknowledged": True}
        index = path.split("/")[1]
        if method == "DELETE":
            self.indices.pop(index, None)
            return 200, {}
        if path.endswith("_bulk?refresh=true"):
            parts = body.decode("utf-8").splitlines()[1::2]
            docs = [self.ingest(json.loads(p)["message"]) for p in parts]
            self.indices.setdefault(index, []).extend(docs)
            return 200, {"items": [{"index": {"status": 201}} for _ in docs]}
        if path.endswith("/_search/template"):
            text = json.dumps(body["source"])
            for key, value in body["params"].items():
                text = text.replace("{{%s}}" % key, str(value))
            body = json.loads(text)
        docs = [d for d in self.indices.get(index, []) if self.matches(d, body.get("query", {"match_all": {}}))]
        got = {"hits": {"total": {"value": len(docs) + self.miscount}, "hits": [{"_source": d} for d in docs]}}
        if "aggs" in body:
            hosts = {}
            for d in docs:
                last, beat = siem_run.instant_ms(d["event"]["ingested"]), d["raqib"]["watch"]["beat"]
                was = hosts.get(d["host"]["name"], (last, beat))
                hosts[d["host"]["name"]] = (max(was[0], last), max(was[1], beat))
            now = int(body["aggs"]["hosts"]["aggs"]["silent"]["bucket_selector"]["script"]["params"]["now"])
            got["aggregations"] = {"hosts": {"buckets": [{"key": h} for h, (last, beat) in sorted(hosts.items())
                                                         if last + 2000.0 * beat < now]}}
        return 200, got


def stand_in_sigma(target, pipeline, rule):
    assert target in ("lucene", "opensearch_lucene") and pipeline.endswith("pipeline-ecs.yml")
    return "SIGMA " + rule


def run(tmp_path, engine, sigma=stand_in_sigma, extra=()):
    events = tmp_path / "events.jsonl"
    events.write_text("".join(x + "\n" for x in list(EXAMPLES[:6]) + list(extra)) + '{"torn', encoding="utf-8")
    said = []
    code = siem_run.main([str(ROOT / "docs" / "specs" / "EVENT.md"), str(events), "--wait", "1"],
                         ask=engine, sigma=sigma, out=said.append)
    return code, said


def rows(said):
    return {int(m.group(2)): m.group(1) for m in (re.match(r"(MET|MISSED|n/a) +X(\d+) ", x) for x in said) if m}


def test_e6_a_faithful_engine_meets_every_claim_with_its_numbers(tmp_path):
    code, said = run(tmp_path, StandIn())
    assert code == 0 and rows(said) == {39: "MET", 40: "MET", 41: "MET", 42: "MET"}, "\n".join(said)
    text = "\n".join(said)
    n = len(EXAMPLES) + 6
    assert "EVENTS events.jsonl: 6 line(s)" in text   # the torn last line is not whole and is not sent
    assert "%d line(s) sent, %d kept, 0 refused, 0 kept as an error" % (n, n) in text
    assert "2 line(s) that are not events: 2 kept with event.kind pipeline_error and a reason" in text
    assert "%d line(s), %d found in the engine, 0 difference(s)" % (n, n) in text
    assert "rule NO-SUCH-RULE 0/0" in text and "silent at " in text and "raqib_hole " in text
    assert "ENGINE opensearch 0.0.0 (the content of siem/opensearch; sigma target opensearch_lucene)" in text


def test_e6_a_field_the_engine_does_not_hold_as_the_event_does_is_missed_and_named(tmp_path):
    def spoil(doc):
        if "process" in doc:
            doc["process"]["pid"] = -1
        return doc
    code, said = run(tmp_path, StandIn(distribution="elasticsearch", spoil=spoil))
    assert code == 0 and rows(said)[40] == "MISSED" and rows(said)[39] == "MET"
    assert re.search(r"process\.pid: the event says \d+, the engine holds -1", "\n".join(said))
    assert "sigma target lucene" in "\n".join(said)


def test_e6_a_count_the_engine_gets_wrong_is_missed_with_both_numbers(tmp_path):
    code, said = run(tmp_path, StandIn(miscount=1))
    assert code == 0 and rows(said)[41] == "MISSED" and rows(said)[42] == "MISSED"
    assert re.search(r"alarm (\d+)/(\d+)", "\n".join(said))


def test_e6_a_line_kept_as_an_error_is_missed_for_x39(tmp_path):
    code, said = run(tmp_path, StandIn(), extra=['{"schema": "other/1"}'])
    assert rows(said)[39] == "MISSED" and "1 kept as an error (1 not events by the count here)" in "\n".join(said)


def test_e6_a_sigma_cli_that_is_not_there_or_fails_is_never_met(tmp_path, monkeypatch):
    monkeypatch.setattr(siem_run.shutil, "which", lambda name: None)
    code, said = run(tmp_path, StandIn(), sigma=None)
    assert code == 0 and rows(said)[42] == "n/a" and "sigma-cli is not installed here" in "\n".join(said)

    def broken(target, pipeline, rule):
        raise RuntimeError("sigma convert exit 1: no such target")
    code, said = run(tmp_path, StandIn(), sigma=broken)
    assert rows(said)[42] == "MISSED" and "not converted (sigma convert exit 1" in "\n".join(said)


def test_e6_an_engine_that_does_not_answer_is_said_as_such_and_never_as_met(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]   # closed when the block ends: nothing answers there
    events = tmp_path / "events.jsonl"
    events.write_text(EXAMPLES[0] + "\n", encoding="utf-8")
    said = []
    code = siem_run.main([str(events), "--url", "http://127.0.0.1:%d" % port, "--wait", "0.5"], out=said.append)
    assert code == 0 and rows(said) == {39: "n/a", 40: "n/a", 41: "n/a", 42: "n/a"}, said
    assert "ENGINE did not answer at http://127.0.0.1:%d" % port in "\n".join(said)


def test_e6_content_the_engine_refuses_is_missed_for_every_claim(tmp_path):
    engine = StandIn()

    def refusing(method, path, body=None, ndjson=False):
        if method == "PUT" and "_ingest" in path:
            return 400, {"error": {"type": "parse_exception", "reason": "a processor it does not know"}}
        return engine(method, path, body, ndjson)
    code, said = run(tmp_path, refusing)
    assert code == 0 and set(rows(said).values()) == {"MISSED"}
    assert "INSTALL the pipeline: http 400" in "\n".join(said)


def test_e6_the_runner_reads_instants_and_the_summary_file(tmp_path):
    assert siem_run.instant_ms("1970-01-01T00:00:01.500Z") == 1500
    assert siem_run.instant_ms("1970-01-01T00:00:01.123456789Z") == 1123
    assert siem_run.instant_ms("1970-01-01T01:00:00.000+01:00") == 0
    assert siem_run.instant_ms("boot+12") is None and siem_run.instant_ms(None) is None
    summary = tmp_path / "summary.md"
    events = tmp_path / "e.jsonl"
    events.write_text(EXAMPLES[0] + "\n", encoding="utf-8")
    siem_run.main([str(events), "--wait", "1", "--summary", str(summary)], ask=StandIn(), sigma=stand_in_sigma,
                  out=lambda line: None)
    assert summary.read_text(encoding="utf-8").count("X4") == 3


@pytest.mark.parametrize("path", ["tools/siem_content.py", "tools/rig/siem_run.py", "tests/test_siem_content.py"])
def test_e8_the_new_code_is_ascii_and_stdlib(path):
    text = (ROOT / path).read_bytes().decode("ascii")
    imports = set(re.findall(r"^(?:import|from) ([a-z_]+)", text, re.M))
    assert imports <= {"argparse", "calendar", "copy", "difflib", "json", "os", "re", "shutil", "socket",
                       "subprocess", "sys", "time", "urllib", "pathlib", "pytest", "raqib", "siem_content",
                       "siem_run"}, imports
