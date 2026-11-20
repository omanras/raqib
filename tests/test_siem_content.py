"""M16.1 and its REDO (ADR-0017 S-1 to S-5 and Amendment A): the ready content of siem/, held without an engine
(E5, R8), and the rig's runner tools/rig/siem_run.py held against a stand-in engine (E6, R6): its mapping, its
checks, its counts by the runner's own send times, its rows, and what it says when the engine does not answer.
No engine, no network: the stand-in is a function with a clock of its own, and the engine that does not answer is a
closed port of this machine's loopback."""
import copy
import json
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
SPEC = siem_run.spec_keys(EVENT_MD)
RULE_FILES = ["raqib_alarm.yml", "raqib_destruction.yml", "raqib_heartbeat_not_watching.yml", "raqib_hole.yml",
              "raqib_network.yml", "raqib_persist.yml", "raqib_secret.yml", "raqib_unnamed_agent.yml",
              "raqib_watch_incomplete.yml"]


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


def pipeline_text():
    return json.dumps(load(SIEM / "elastic" / "pipeline.json"))   # one line: the needles below are compact


def scripts():
    procs = load(SIEM / "elastic" / "pipeline.json")["processors"]
    return [p["script"]["source"] for p in procs if "script" in p]


# ---------------------------------------------------------------- the content, without an engine

def test_e5_every_json_and_yaml_file_of_siem_parses_with_the_standard_library_or_the_repos_reader():
    files = [p for p in SIEM.rglob("*") if p.is_file()]
    parsed = [p for p in files if p.suffix in (".json", ".yml", ".yaml")]
    assert len(parsed) == 2 + 2 + 12 + 1 + 9 + 1
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
    assert template["priority"] == 200 and template["index_patterns"] == ["raqib-events*"]
    mappings = template["template"]["mappings"]
    assert mappings["date_detection"] is False   # the trap of S-4: a string that looks like a date is not guessed
    assert mappings["dynamic_templates"][0]["strings"]["mapping"]["type"] == "keyword"
    raqib = mappings["properties"]["raqib"]["properties"]
    whole = {k for k, v in raqib.items() if v.get("type") == "flattened"}
    assert whole == {"subject", "evidence", "hole", "knocked", "result", "counts"}   # subject.started among them
    assert raqib["prev"] == raqib["unknown_keys"] == {"type": "keyword"}


def test_e1_every_ecs_field_the_mapping_names_is_set_by_the_pipelines_text():
    text = pipeline_text()
    sets = {"@timestamp": '"target_field": "@timestamp"', "event.id": "ev.id = r.remove('id')",
            "event.action": "ev.action = r.remove('kind')", "event.severity": "ev.severity = sev[",
            "event.kind": "ev.kind = r.remove('alarm') == true ? 'alert' : 'event'",
            "message": "ctx.message = r.remove('summary')", "host.name": "h.name = w.remove('host')",
            "observer.product": "ob.product = 'Raqib'", "observer.version": "ob.version = w.remove('version')",
            "rule.id": "rr.id = ru.remove('id')", "rule.category": "rc.category = ru.remove('class')",
            "threat.technique.id": "te.id = ru.remove('attack')", "process.pid": "pp.pid = su.remove('pid')",
            "process.name": "pn.name = su.remove('image')"}
    assert sorted(sets) == NAMED_ECS   # a named key added to the Mapping fails here until the pipeline sets it
    for field, needle in sets.items():
        assert needle in text, field
    for needle in ('"field": "event.original", "value": "{{{message}}}"', '"target_field": "raqib"',
                   '"field": "event.ingested", "value": "{{{_ingest.timestamp}}}"', "pipeline_error",
                   '"field": "error.message", "value": "{{{_ingest.on_failure_message}}}"'):
        assert needle in text, needle
    assert sorted(siem_run.NAMED) == NAMED_ECS


def test_r3_the_pipeline_names_every_reason_of_sa5_and_its_bounds():
    check, mapping = scripts()
    for reason in ("its schema is not raqib-event/1", "deeper than 10 levels", "a text longer than 8000 characters",
                   "more than 200 keys", "an empty key", "the base key ", "is not of its kind of value",
                   "its kind is not one of the spec", "the base key watch."):
        assert reason in pipeline_text(), reason
    assert (siem_run.MAX_DEPTH, siem_run.MAX_TEXT, siem_run.MAX_KEYS, siem_run.MAX_UNKNOWN) == (10, 8000, 200, 50)
    assert "def base = %s;" % str(list(siem_run.BASE)).replace('"', "'") in check
    assert "def kinds = %s;" % str(list(siem_run.KINDS)).replace('"', "'") in check
    assert "def wbase = ['run', 'host', 'beat'];" in check
    assert "r.unknown_keys = unknown.size() > 50 ? new ArrayList(unknown.subList(0, 50)) : unknown" in mapping
    assert check.index("void walk(") < check.index("def r = ctx.raqib;")   # every check runs before any write


def test_r3_the_pipelines_lists_of_known_keys_and_their_kinds_are_the_specs():
    check, mapping = scripts()
    top, parts, checked = siem_run.known(SPEC)
    assert "prev" in top and top["prev"] == "s" and top["alarm"] == "b" and top["n"] == "p"
    for key, code in top.items():
        assert "'%s': '%s'" % (key, code or "-") in check and "'%s': '%s'" % (key, code or "-") in mapping, key
    for parent, subs in parts.items():
        assert "'%s': [%s]" % (parent, ", ".join("'%s'" % s for s in subs)) in mapping, parent
    assert set(checked) == {"watch", "rule", "subject"} and set(checked["subject"]) == {"pid", "image"}
    for parent, subs in checked.items():
        assert "'%s': [%s]" % (parent, ", ".join("'%s': '%s'" % (k, c or "-") for k, c in subs.items())) in check
    assert len(top) + sum(len(s) for s in parts.values()) == len(SPEC)


def test_r3_no_field_a_shipper_set_is_removed_and_no_document_id_is_set():
    pipeline = load(SIEM / "elastic" / "pipeline.json")
    removes = [p["remove"] for p in pipeline["processors"] + pipeline["on_failure"] if "remove" in p]
    assert removes == [{"field": "raqib", "ignore_missing": True}]
    assert {"set": {"field": "@timestamp", "value": "{{{_ingest.timestamp}}}", "override": False}} in \
        pipeline["on_failure"]
    text = pipeline_text()
    assert not re.search(r"\b_id\b|ctx\._id", text) and "ctx.host = " not in text and "ctx.observer = " not in text
    assert "Map obj(Map m, String k) { if (!(m[k] instanceof Map)) { m[k] = [:]; } return m[k]; }" in text


def test_r3_the_runners_checks_keep_each_odd_line_as_the_ruling_says():
    maker = siem_run.Maker(EVENT_MD)
    want = {"an-unknown-key": None, "a-dotted-key": None, "sixty-unknown-keys": None,
            "an-empty-key": "an empty key", "run-an-object": "watch.run is not of its kind of value",
            "kind-unknown": "the kind is not one of the spec's eight", "n-missing": "the base key n is missing",
            "n-beyond-a-long": "n is not of its kind of value", "alarm-a-string": "alarm is not of its kind of value",
            "deep-unknown-key": "deeper than 10 levels", "deep-evidence": "deeper than 10 levels",
            "many-unknown-keys": "more than 200 keys", "a-long-word": "a text longer than 8000 characters",
            "not-json": "not JSON", "schema-2": "another schema",
            "fp-budget-a-text": "rule.fp_budget is not of its kind of value",
            "attack-objects": "rule.attack is not of its kind of value"}
    assert sorted(label for label, _ in siem_run.ODD) == sorted(want)
    for label, change in siem_run.ODD:
        line = siem_run.line_of(change(maker.make("heartbeat", "odd.example", "odd", 600)))
        assert siem_run.check_of(line, SPEC) == want[label], label
    sixty = dict(siem_run.ODD)["sixty-unknown-keys"](maker.make("heartbeat", "odd.example", "odd", 600))
    doc = siem_run.ecs_of(siem_run.line_of(sixty), SPEC)
    assert doc["raqib"]["unknown_keys"] == ["u%02d" % i for i in range(50)] and "u00" not in doc["raqib"]
    dotted = dict(siem_run.ODD)["a-dotted-key"](maker.make("heartbeat", "odd.example", "odd", 600))
    assert siem_run.ecs_of(siem_run.line_of(dotted), SPEC)["raqib"]["unknown_keys"] == ["watch.run"]


def test_e1_the_runners_mapping_names_exactly_the_mappings_fields_and_keeps_every_other_key_under_raqib():
    assert len(EXAMPLES) >= 18
    for line in EXAMPLES:
        ev = json.loads(line)
        assert siem_run.check_of(line, SPEC) is None, line
        doc = siem_run.ecs_of(line, SPEC)
        assert doc["event"]["original"] == line and doc["@timestamp"] == ev["time"]
        assert doc["event"]["kind"] == ("alert" if ev.get("alarm") is True else "event")
        assert doc["host"]["name"] == ev["watch"]["host"] and doc["observer"]["product"] == "Raqib"
        assert doc["event"]["severity"] == {"high": 4, "medium": 3, "low": 2, "info": 1, "hole": 3}[ev["severity"]]
        for key in ("time", "id", "kind", "severity", "alarm", "summary", "unknown_keys"):
            assert key not in doc["raqib"]
        assert "host" not in doc["raqib"]["watch"] and "version" not in doc["raqib"]["watch"]
        for part in ("rule", "subject"):
            for key in ("id", "class", "attack", "pid", "image"):
                assert key not in doc["raqib"].get(part, {})
        assert doc["raqib"].get("about") == ev["about"] and doc["raqib"]["n"] == ev["n"]
    chained = dict(json.loads(EXAMPLES[0]), prev="first")
    assert siem_run.ecs_of(siem_run.line_of(chained), SPEC)["raqib"]["prev"] == "first"   # ADR-0016: a known key


def test_e2_r1_r2_each_search_is_a_file_with_one_sentence_the_same_in_both_engines_and_no_time_given():
    names = sorted(p.name for p in (SIEM / "elastic" / "searches").iterdir())
    assert names == ["alarm.json", "hole.json", "rule.json", "runs-no-end.json", "silence.json", "watch-not-0.json"]
    for name in names:
        es, os_ = (SIEM / e / "searches" / name for e in ENGINES)
        assert es.read_bytes() == os_.read_bytes(), name
        search = load(es)
        assert set(search) == {"finds", "request", "body"}
        assert search["finds"].endswith(".") and search["finds"].count(". ") == 0, name
        assert search["request"] in ("POST raqib-events*/_search", "POST raqib-events*/_search/template")
        text = es.read_text(encoding="ascii")
        assert "now" not in json.dumps(search["body"].get("params", {})) and "{{now" not in text, name
        assert not re.search(r"\d{12,}", text), name   # no default time anywhere
    deadline = "doc['event.ingested'].value.toInstant().toEpochMilli() + (long)(2000 * doc['raqib.watch.beat'].value)"
    for name, agg, selector in (("silence.json", "hosts", "params.d < System.currentTimeMillis()"),
                                ("runs-no-end.json", "runs",
                                 "params.e == 0 && params.d < System.currentTimeMillis()")):
        body = load(SIEM / "elastic" / "searches" / name)["body"]
        text = json.dumps(body)
        assert "@timestamp" not in text and "heartbeat" not in text   # every line counts, by its arrival
        aggs = body["aggs"][agg]
        assert aggs["aggs"]["deadline"] == {"max": {"script": {"source": deadline}}}
        assert selector in text and "10000" in load(SIEM / "elastic" / "searches" / name)["finds"].replace(",", "")
    silence = load(SIEM / "elastic" / "searches" / "silence.json")["body"]["aggs"]["hosts"]["terms"]
    assert silence == {"field": "host.name", "size": 10000, "order": {"deadline": "asc"}}
    runs = load(SIEM / "elastic" / "searches" / "runs-no-end.json")["body"]["aggs"]["runs"]
    assert runs["aggs"]["ends"]["filter"]["bool"]["filter"] == [{"term": {"event.action": "watch"}},
                                                                {"term": {"raqib.state": "end"}}]


def test_e2_every_field_a_search_names_is_a_field_the_pipeline_writes():
    fields = set(NAMED_ECS) | {"event.ingested", "event.original"} | set(KEYS.values())
    for path in (SIEM / "elastic" / "searches").iterdir():
        body = json.dumps(load(path)["body"])
        named = re.findall(r'"field": "([^"]+)"', body) + re.findall(r'\{"term": \{"([^"]+)"', body)
        named += re.findall(r"doc\['([^']+)'\]", body)
        assert named, path.name
        for field in named:
            assert field in fields, (path.name, field)


def test_e3_r4_every_key_a_sigma_rule_or_its_pipeline_names_is_a_key_of_the_spec_and_none_names_alarm_false():
    pipeline = load(SIEM / "sigma" / "pipeline-ecs.yml")
    by_id = {t["id"]: t for t in pipeline["transformations"]}
    assert by_id["raqib_ecs_fields"]["mapping"] == KEYS   # every key to its ECS column, prev among them
    assert by_id["raqib_alarm_true_is_alert"]["field_name_conditions"][0]["fields"] == ["alarm"]
    assert by_id["raqib_severity_number"]["mapping"] == {"high": "4", "medium": "3", "low": "2", "info": "1",
                                                         "hole": "3"}
    assert sorted(sigma_rules()) == RULE_FILES
    for name, rule in sigma_rules().items():
        assert rule["logsource"] == {"product": "raqib"}, name
        blocks = [v for k, v in rule["detection"].items() if k != "condition"]
        for block in blocks:
            for key, value in block.items():
                assert key.split("|")[0] in KEYS, (name, key)
                assert key.split("|")[0] != "severity", name   # hole and medium are both 3
                if key == "alarm":
                    assert value is True, name   # the pipeline's value step turns any alarm into alert
    beat = sigma_rules()["raqib_heartbeat_not_watching.yml"]["detection"]
    assert beat == {"selection": {"kind": "heartbeat"}, "filter": {"state": "WATCHING"},
                    "condition": "selection and not filter"}


def test_e3_ids_are_unique_levels_are_set_and_attack_tags_are_only_the_rules():
    rules = sigma_rules()
    table = siem_content.catalog()
    ids = [r["id"] for r in rules.values()]
    assert len(set(ids)) == len(ids) == len(RULE_FILES)
    assert all(re.match(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z", i) for i in ids)
    assert len({r["title"] for r in rules.values()}) == len(RULE_FILES)
    tagged = {}
    for name, rule in rules.items():
        assert rule["level"] in ("low", "medium", "high", "critical") and rule["status"] == "experimental"
        sel = rule["detection"]["selection"]
        matched = [c for c in table if sel.get("rule.class") in (None, c["class"])
                   and sel.get("rule.id") in (None, c["id"])] if ("rule.class" in sel or "rule.id" in sel) else []
        allowed = {"attack." + t.lower() for c in matched for t in c["attack"]}
        assert set(rule.get("tags") or []) == allowed, name   # exactly the techniques the rules hold
        if matched:
            order = ["low", "medium", "high"]
            assert rule["level"] == max((c["severity"] for c in matched), key=order.index), name
        tagged[name] = sorted(allowed)
    assert tagged["raqib_persist.yml"] == ["attack.t1547.001"] and tagged["raqib_unnamed_agent.yml"] == ["attack.t1059"]
    assert tagged["raqib_network.yml"] == ["attack.t1021", "attack.t1048", "attack.t1105"]


def test_r6_each_sigma_rule_matches_its_made_up_event_and_passes_over_each_near_miss():
    maker = siem_run.Maker(EVENT_MD)
    made = {label: maker.make(base, "made.example", "made-run", **over) for label, base, over in siem_run.MADE}
    events = list(made.values()) + [json.loads(x) for x in EXAMPLES]
    assert set(siem_run.NEAR) == set(siem_run.POSITIVE) == set(RULE_FILES)
    for name, rule in sigma_rules().items():
        det = rule["detection"]
        assert sum(1 for e in events if siem_run.sigma_match(det, e)) >= 1, name
        positive = siem_run.POSITIVE[name]
        if positive:
            assert siem_run.sigma_match(det, made[positive]), name
        assert siem_run.NEAR[name], name
        for miss in siem_run.NEAR[name]:
            assert not siem_run.sigma_match(det, made[miss]), (name, miss)
    table = {r["id"]: r for r in siem_content.catalog()}
    for rid, (cls, kind, attack) in siem_run.RULE.items():   # the made-up rules are the rules' own
        assert (table[rid]["class"], table[rid]["kind"], table[rid]["attack"]) == (cls, kind, attack), rid
    for label, ev in made.items():
        assert siem_run.check_of(siem_run.line_of(ev), SPEC) is None, label


def test_r5_the_attack_table_and_layer_hold_every_rule_the_report_lists_and_a_change_fails_the_check():
    assert siem_content.differences() == []
    done = subprocess.run([sys.executable, str(ROOT / "tools" / "siem_content.py"), "--check"],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    rules = siem_content.catalog()
    ids = {r["id"] for r in rules}
    catalog_ids = {p.stem for p in (ROOT / "raqib" / "rules" / "catalog").glob("*.yaml")}
    assert catalog_ids < ids and {"SILENCE-GAP", "SILENCE-OPEN", "CROSS-SOURCE", "HEAD-UNMOVED",
                                  "INDEX-UNTOUCHED"} <= ids
    table = (SIEM / "attack" / "rules.md").read_text(encoding="ascii")
    for rule in rules:
        row = "| %s | %s | %s | %s | %s | %s |" % (rule["id"], rule["title"].replace("|", "/"), rule["class"],
                                                  rule["kind"], rule["severity"], ", ".join(rule["attack"]) or "none")
        assert row in table, rule["id"]
    layer = load(SIEM / "attack" / "raqib-layer.json")
    assert {t["techniqueID"] for t in layer["techniques"]} == {t for r in rules for t in r["attack"]}
    assert "T1562" in {t["techniqueID"] for t in layer["techniques"]} and layer["domain"] == "enterprise-attack"
    more = rules + [{"id": "ZZ-NEW", "title": "A new rule", "class": "NET", "kind": "signature",
                     "severity": "high", "attack": ["T1095"]}]
    diffs = siem_content.differences(rules=more)
    assert any("rules.md" in d and "ZZ-NEW" in d for d in diffs)
    assert any("raqib-layer.json" in d and "T1095" in d for d in diffs)
    changed = copy.deepcopy(rules)
    changed[0]["severity"] = "low" if changed[0]["severity"] != "low" else "high"
    assert any(changed[0]["id"] in d for d in siem_content.differences(rules=changed))
    assert siem_content.main(["--nothing"]) == 2


def test_e5_siem_is_ascii_and_holds_no_address_host_or_persons_name():
    for path in (p for p in SIEM.rglob("*") if p.is_file()):
        text = path.read_bytes().decode("ascii")   # raises on anything but ASCII
        assert not re.search(r"(?<![\w.])\d{1,3}(\.\d{1,3}){3}(?![\w.])", text), path
        assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", text), path   # no address of mail
        assert not re.search(r"/home/|/Users/|\\Users\\|C:\\", text), path
        hosts = set(re.findall(r"\b[a-z0-9-]+\.(?:com|net|org|io|dev|local|lan|internal|corp)\b", text, re.I))
        assert hosts == set(), (path, hosts)


def test_e5_nothing_under_raqib_imports_or_reads_siem():
    for path in (ROOT / "raqib").rglob("*.py"):
        assert not re.search(r"\bsiem\b", path.read_text(encoding="utf-8")), path
    assert not (ROOT / "siem" / "__init__.py").exists()


def test_r6_the_rig_job_runs_both_engines_on_loopback_a_watch_with_a_short_beat_and_pinned_tools():
    text = (ROOT / ".github" / "workflows" / "rig.yml").read_text(encoding="ascii")
    job = text.split("\n  siem:\n", 1)[1]
    assert "elasticsearch:8.15.3" in job and "opensearch:2.17.1" in job
    assert job.count("-p 127.0.0.1:9200:9200") == 2 and "0.0.0.0" not in job
    assert "raqib watch --host --rounds 4 --every 5 --beat 5 --no-open" in job
    assert ("pip install --disable-pip-version-check -q sigma-cli==3.1.0 pySigma==1.5.1 "
            "pysigma-backend-elasticsearch==2.1.1 pysigma-backend-opensearch==2.0.3") in job
    assert "python tools/rig/siem_run.py docs/specs/EVENT.md" in job and "curl" not in job


# ---------------------------------------------------------------- the runner, against a stand-in engine

class Clock:
    def __init__(self):
        self.t = 1795000000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += max(0.0, s)


def iso(ms):
    import time as _time
    return _time.strftime("%Y-%m-%dT%H:%M:%S", _time.gmtime(ms // 1000)) + ".%03dZ" % (ms % 1000)


class StandIn:
    """A stand-in engine with the runner's clock: its pipeline is the runner's own checks and mapping (what the real
    engine is claimed to do), its searches are read from the runner's requests. Each knob spoils one thing."""

    def __init__(self, clock, distribution="opensearch", spoil=None, miscount=0, by_time=False, late=0,
                 drop_shipper=False, refuse_deep=False):
        self.clock, self.distribution, self.spoil, self.miscount = clock, distribution, spoil, miscount
        self.by_time, self.late, self.drop_shipper, self.refuse_deep = by_time, late, drop_shipper, refuse_deep
        self.indices = {}

    def ingest(self, sent):
        line, extra = sent.pop("message"), sent
        now = int(self.clock() * 1000) + self.late
        why = siem_run.check_of(line, siem_run.spec_keys(EVENT_MD))
        if why:
            doc = copy.deepcopy(extra)
            doc.update(message=line, error={"message": why})
            doc.setdefault("event", {}).update(kind="pipeline_error", original=line, ingested=iso(now))
            doc.setdefault("@timestamp", iso(now))
            return doc
        doc = siem_run.ecs_of(line, siem_run.spec_keys(EVENT_MD))
        if not self.drop_shipper:
            for key, value in extra.items():
                doc[key] = dict(value, **doc[key]) if key in doc else copy.deepcopy(value)
        doc["event"]["ingested"] = iso(now)
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
        if "query_string" in query:   # the stand-in sigma gives "SIGMA <rule file>" or "MATCHALL"
            q = query["query_string"]["query"]
            if q == "MATCHALL":
                return True
            if siem_run.get(doc, "event.kind") == "pipeline_error":   # no event key of a rule is on it
                return False
            rule = yamlite.loads(Path(q.split(" ", 1)[1]).read_text(encoding="utf-8"))
            return siem_run.sigma_match(rule["detection"], json.loads(doc["event"]["original"]))
        bool_ = query["bool"]
        return (all(self.matches(doc, q) for q in bool_.get("filter", []))
                and not any(self.matches(doc, q) for q in bool_.get("must_not", [])))

    def deadline(self, doc):
        at = siem_run.instant_ms(doc["@timestamp"] if self.by_time else doc["event"]["ingested"])
        return at + int(2000 * doc["raqib"]["watch"]["beat"])

    def aggregate(self, aggs, docs):
        now = int(self.clock() * 1000)
        if "hosts" in aggs:
            groups = {}
            for d in docs:
                groups.setdefault(d["host"]["name"], []).append(d)
            rows = sorted((max(self.deadline(d) for d in ds), h) for h, ds in groups.items())
            return {"hosts": {"buckets": [{"key": h, "deadline": {"value": float(dl)}} for dl, h in rows
                                          if dl < now]}}
        groups = {}
        for d in docs:
            groups.setdefault((d["host"]["name"], d["raqib"]["watch"]["run"]), []).append(d)
        out = []
        for key, ds in sorted(groups.items()):
            ends = sum(1 for d in ds if d["event"]["action"] == "watch" and d["raqib"].get("state") == "end")
            dl = max(self.deadline(d) for d in ds)
            if ends == 0 and dl < now:
                out.append({"key": list(key), "deadline": {"value": float(dl)}})
        return {"runs": {"buckets": out}}

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
            items = []
            for part in body.decode("utf-8").splitlines()[1::2]:
                sent = json.loads(part)
                if self.refuse_deep and '"k":{"k":{"k":{"k":{"k":{"k":{"k":{"k":{"k":{"k":{"k"' in sent["message"]:
                    items.append({"index": {"status": 400, "error": {"type": "document_parsing_exception"}}})
                    continue
                self.indices.setdefault(index, []).append(self.ingest(sent))
                items.append({"index": {"status": 201}})
            return 200, {"items": items}
        if path.endswith("/_search/template"):
            text = json.dumps(body["source"])
            for key, value in body["params"].items():
                text = text.replace("{{%s}}" % key, str(value))
            body = json.loads(text)
        docs = [d for d in self.indices.get(index, []) if self.matches(d, body.get("query", {"match_all": {}}))]
        got = {"hits": {"total": {"value": len(docs) + self.miscount}, "hits": [{"_source": d} for d in docs]}}
        if "aggs" in body:
            got["aggregations"] = self.aggregate(body["aggs"], docs)
        return 200, got


def stand_in_sigma(target, pipeline, rule):
    assert target in ("lucene", "opensearch_lucene") and pipeline.endswith("pipeline-ecs.yml")
    return "SIGMA " + rule


def run(tmp_path, engine=None, sigma=stand_in_sigma, clock=None, **knobs):
    clock = clock or Clock()
    engine = engine or StandIn(clock, **knobs)
    events = tmp_path / "events.jsonl"
    events.write_text("".join(x + "\n" for x in EXAMPLES[:6]) + '{"torn', encoding="utf-8")
    said = []
    code = siem_run.main([str(ROOT / "docs" / "specs" / "EVENT.md"), str(events), "--wait", "1"],
                         ask=engine, sigma=sigma, out=said.append, clock=clock, sleep=clock.sleep)
    return code, said


def rows(said):
    return {int(m.group(2)): m.group(1) for m in (re.match(r"(MET|MISSED|n/a) +X(\d+) ", x) for x in said) if m}


def row(said, n):
    return next(x for x in said if re.match(r"\S+ +X%d " % n, x))


def test_r6_a_faithful_engine_meets_every_claim_and_each_row_names_what_was_fed(tmp_path):
    code, said = run(tmp_path)
    assert code == 0 and rows(said) == {39: "MET", 40: "MET", 41: "MET", 42: "MET"}, "\n".join(said)
    text = "\n".join(said)
    assert "EVENTS events.jsonl: 6 line(s)" in text   # the torn last line is not whole and is not sent
    for n in (39, 40, 41, 42):
        assert "[fed: engine opensearch 0.0.0, siem/opensearch; %d example(s) of EVENT.md; 6 line(s) of the events" \
               " file(s); 7 made-up event(s) of the rules' classes and 5 near miss(es); 17 odd line(s)" % len(
                   EXAMPLES) in row(said, n), n
    assert "sigma-cli" in row(said, 42) and "pySigma" in row(said, 42)
    x39 = row(said, 39)
    assert "0 refused" in x39 and "(0 wrong)" in x39 and "the line after each of 17 odd lines kept: 17" in x39
    assert "an-empty-key error" in x39 and "an-unknown-key event" in x39 and "not-json error" in x39
    assert "0 difference(s)" in row(said, 40) and "2 document(s) with a shipper's fields, 1 of them" in row(said, 40)
    x41 = row(said, 41)
    assert "rule NO-SUCH-RULE 0/0" in x41 and "rule PERSIST-RUN-KEY 1/1" in x41 and "watch-not-0 " in x41
    assert "silence -silence at +1.0 s: engine none; here none surely" in x41
    assert "silence -silence at +3.6 s: engine a.example,d.example,f.example,g.example; here a.example," \
           "d.example,f.example,g.example surely, 0 not sure" in x41
    assert "silence -silence at +8.0 s: engine a.example,d.example,f.example,g.example,c.example;" in x41   # the nearest deadline first
    assert "runs-no-end -silence at +3.6 s: engine a.example/a1,c.example/c2,d.example/d1,f.example/f1;" in x41
    assert "runs-no-end -silence at +8.0 s: engine a.example/a1,c.example/c1,c.example/c2,d.example/d1," \
           "f.example/f1;" in x41
    x42 = row(said, 42)
    assert "raqib_persist 1/1, its own persist 1, near miss drift 0,knock-persist 0" in x42
    assert "raqib_heartbeat_not_watching 1/1, its own not-watching 1, near miss heartbeat-incomplete 0" in x42


def test_r6_an_engine_that_judges_silence_by_the_events_time_is_missed(tmp_path):
    code, said = run(tmp_path, by_time=True)
    assert code == 0 and rows(said)[41] == "MISSED" and rows(said)[39] == "MET"
    assert "(MISSED)" in row(said, 41)


def test_r6_an_arrival_outside_the_runners_clock_or_a_shipper_field_lost_is_missed_and_named(tmp_path):
    code, said = run(tmp_path, late=3600 * 1000)
    assert rows(said)[40] == "MISSED" and "event.ingested: " in row(said, 40)
    code, said = run(tmp_path, drop_shipper=True)
    assert rows(said)[40] == "MISSED" and "host.hostname: the shipper sent" in row(said, 40)


def test_e6_a_field_the_engine_does_not_hold_as_the_event_does_is_missed_and_named(tmp_path):
    def spoil(doc):
        if "process" in doc:
            doc["process"]["pid"] = -1
        return doc
    code, said = run(tmp_path, distribution="elasticsearch", spoil=spoil)
    assert code == 0 and rows(said)[40] == "MISSED" and rows(said)[39] == "MET"
    assert re.search(r"process\.pid: the event says \d+, the engine holds -1", row(said, 40))
    assert "sigma target lucene" in "\n".join(said)


def test_r6_a_line_the_engine_refuses_is_missed_for_x39(tmp_path):
    code, said = run(tmp_path, refuse_deep=True)
    assert rows(said)[39] == "MISSED" and "2 refused" in row(said, 39) and "deep-unknown-key lost" in row(said, 39)


def test_e6_a_count_the_engine_gets_wrong_is_missed_with_both_numbers(tmp_path):
    code, said = run(tmp_path, miscount=1)
    assert code == 0 and rows(said)[41] == "MISSED" and rows(said)[42] == "MISSED"
    assert re.search(r"alarm (\d+)/(\d+)", row(said, 41))


def test_r6_a_rule_that_takes_its_near_miss_too_is_missed(tmp_path):
    def broad(target, pipeline, rule):
        return "MATCHALL" if rule.endswith("raqib_persist.yml") else "SIGMA " + rule
    code, said = run(tmp_path, sigma=broad)
    assert rows(said)[42] == "MISSED" and re.search(r"raqib_persist \d+/1, its own persist 1, near miss "
                                                    r"drift 1,knock-persist 1 \(MISSED\)", row(said, 42))


def test_e6_a_sigma_cli_that_is_not_there_or_fails_is_never_met(tmp_path, monkeypatch):
    monkeypatch.setattr(siem_run.shutil, "which", lambda name: None)
    code, said = run(tmp_path, sigma=None)
    assert code == 0 and rows(said)[42] == "n/a" and "sigma-cli is not installed here" in row(said, 42)

    def broken(target, pipeline, rule):
        raise RuntimeError("sigma convert exit 1: no such target")
    code, said = run(tmp_path, sigma=broken)
    assert rows(said)[42] == "MISSED" and "not converted (sigma convert exit 1" in row(said, 42)


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
    clock = Clock()
    engine = StandIn(clock)

    def refusing(method, path, body=None, ndjson=False):
        if method == "PUT" and "_ingest" in path:
            return 400, {"error": {"type": "parse_exception", "reason": "a processor it does not know"}}
        return engine(method, path, body, ndjson)
    code, said = run(tmp_path, engine=refusing, clock=clock)
    assert code == 0 and set(rows(said).values()) == {"MISSED"}
    assert "INSTALL the pipeline: http 400" in "\n".join(said)


def test_e6_the_runner_reads_instants_deadlines_and_the_summary_file(tmp_path):
    assert siem_run.instant_ms("1970-01-01T00:00:01.500Z") == 1500
    assert siem_run.instant_ms("1970-01-01T00:00:01.123456789Z") == 1123
    assert siem_run.instant_ms("1970-01-01T01:00:00.000+01:00") == 0
    assert siem_run.instant_ms("boot+12") is None and siem_run.instant_ms(None) is None
    groups = {"x": (10, 20, False), "y": (100, 200, False), "z": (10, 20, True)}
    assert siem_run.judge_deadlines(groups, (50, 60), [("x", 20.0), ("z", 20.0)], False)[0] is True
    assert siem_run.judge_deadlines(groups, (50, 60), [("x", 20.0), ("y", 150.0)], False)[0] is False
    assert siem_run.judge_deadlines(groups, (50, 60), [("x", 20.0)], True)[0] is True   # z said its end
    assert siem_run.judge_deadlines(groups, (50, 60), [("x", 20.0), ("z", 20.0)], True)[0] is False
    assert siem_run.judge_deadlines(groups, (15, 16), [], False) == (True, "engine none; here none surely, 2 not sure")
    summary = tmp_path / "summary.md"
    events = tmp_path / "e.jsonl"
    events.write_text(EXAMPLES[0] + "\n", encoding="utf-8")
    clock = Clock()
    siem_run.main([str(events), "--wait", "1", "--summary", str(summary)], ask=StandIn(clock), sigma=stand_in_sigma,
                  out=lambda line: None, clock=clock, sleep=clock.sleep)
    assert summary.read_text(encoding="utf-8").count(" X4") == 3


@pytest.mark.parametrize("path", ["tools/siem_content.py", "tools/rig/siem_run.py", "tests/test_siem_content.py"])
def test_e8_the_new_code_is_ascii_and_stdlib(path):
    text = (ROOT / path).read_bytes().decode("ascii")
    imports = set(re.findall(r"^(?:import|from) ([a-z_]+)", text, re.M))
    assert imports <= {"argparse", "calendar", "copy", "difflib", "json", "os", "re", "shutil", "socket",
                       "subprocess", "sys", "time", "urllib", "pathlib", "pytest", "raqib", "siem_content",
                       "siem_run"}, imports
