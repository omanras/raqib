"""M8.2 (ADR-0009 decisions 4-5): a rule made from a form, without Tk.

A person answers, in words: the rule's id and title, what to watch for
(a program is run, a file under a place is touched, a network host is
reached, a tool is used), the names or places, the severity, one example
that must fire and one that must not. From the answers this module writes
the rule's YAML text (kind signature, with the evasions that form always
has, ADR-0002) and its positive and negative fixture files - or a refusal
that names the field and says why.

It never judges the rule itself (A6): the files are written to a staging
directory Raqib owns (~/.raqib/rules.staging/form-*), judged there by
overlay.validate_rule - the engine's loader and the fixture runner, as any
person's rule is judged (ADR-0008 A-1's path checks, class HOST refused,
an id already taken refused) - and they reach ~/.raqib/rules.d/<ID>/ only
through overlay.add_rule, the path `raqib rules --add FILE` takes. The
staging directory is removed after every Test and Add; nothing is written
in rules.d when anything is refused.

Nothing a person types becomes part of a file path except the id, after
its check (engine.RULE_ID). Program names follow the capture's own name
rule (raqib/hooks/common.py HEAD_NAME), lower-cased as discover.image_name
does; hosts are host names; places are whole paths.

"On your records" (E3): the rule, once accepted in staging, is run over
the traces under ~/.raqib/traces and the host source files under
~/.raqib/host/sources - the newest RECORD_FILES files, at most
RECORD_BYTES of each (its end) and RECORD_LINES lines in all, read-only -
and the result is said: information for the person, never a gate.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile

from raqib import discover, overlay
from raqib.hooks import common
from raqib.rules import engine, trace, yamlite

FORMS = ("program", "path", "host", "tool")
FORM_WORDS = {"program": "a program is run", "path": "a file under a place is touched",
              "host": "a network host is reached", "tool": "a tool is used"}
VALUE_WORDS = {"program": "program names", "path": "places", "host": "host names", "tool": "tool names"}
VALUE_HINTS = {
    "program": "Program names, separated by commas (terraform, tofu): the name capture records, no .exe",
    "path": "Whole places, separated by commas (~/.aws, /srv/data, C:\\Users\\me\\keys); * or ? make a pattern",
    "host": "Host names, separated by commas (paste.example.com): each name whole",
    "tool": "Tool names, separated by commas (WebSearch, mcp__server__tool): matched exactly",
}
FIELDS = ("id", "title", "when", "values", "severity", "fires", "quiet")
FIELD_WORDS = {"id": "Id", "title": "Title", "when": "Watch for", "values": "Names or places",
               "severity": "Severity", "fires": "Must fire on", "quiet": "Must stay quiet on", "rule": "The rule"}
SEVERITIES = engine.SEVERITIES
# Q-1 (docs/review/2026-11-11-M8.2-questions.md): the Table proposed one class word for a person's rules
# (USER); engine.CLASSES refuses a class it does not list (compile_rule and check_finding), and
# raqib/rules/engine.py is outside this task's scope. Until the Table rules, each form takes the
# nearest class the engine knows; never HOST (ADR-0008 A-6), never CROSS (M5.3 D-11).
CLASS_OF = {"program": "SCOPE", "path": "SCOPE", "host": "NET", "tool": "SCOPE"}
FP_BUDGET = 0.1
ID_MAX = 48
TITLE_MAX = 80
VALUES_MAX = 32
VALUE_MAX = 64
PLACE_MAX = 260
TOOL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
FILE_TOOLS = ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "NotebookRead", "Glob", "Grep", "LS")
GLOB_CHARS = "*?"
STAGING_NAME = "rules.staging"
TS = "2026-11-11T09:00:00.000Z"
POSIX_CWD = "/work/example"
WINDOWS_CWD = "C:\\work\\example"
RECORD_FILES = 20          # E3: the newest files read
RECORD_LINES = 20000       # E3: the lines read, in all
RECORD_BYTES = 4000000     # E3: the bytes read of one file (its end: the newest lines)
CITED_MAX = 3
QUIET_PROGRAMS = ("ls", "git", "make")
QUIET_HOSTS = ("example.org", "example.net", "example.com")
QUIET_TOOLS = ("Read", "Grep", "LS")
QUIET_PATHS = {"posix": ("/work/example/notes.txt", "/srv/example/notes.txt"),
               "windows": ("C:\\work\\example\\notes.txt", "D:\\example\\notes.txt")}
HEADER = ("# A person's rule, written by Raqib's rule form (M8.2, ADR-0009 decision 4) and judged by the\n"
          "# engine's loader and fixture runner as any rule is (A6). Remove it with: raqib rules --remove %s\n")

EVASIONS = {
    "program": (
        "a renamed copy of a program (curl copied as x) is matched by its new name only",
        "a program run inside another one (python -c, node -e, a library call, a PowerShell cmdlet) starts no"
        " program of that name",
        "a wrapper in front (sudo, env, xargs, timeout, nohup, exec, find -exec) or a shell other than bash or sh:"
        " the program it runs is an argument, and capture never records arguments",
        "a Bash command capture cannot read in full is matched by its first program only (command_unread: true)",
        "code given to a shell on stdin or in a script file (bash x.sh, ./x.sh) records the shell or the script only",
        "on a Bash line a program is matched as written: Curl or curl.exe is another name there (an os line's"
        " image is lower case with no .exe)",
        "host source (raqib watch --host): a child that lives only between two rounds is never seen",
        "os source: a process line written before M7.8 has no image and is not judged; a program run inside WSL"
        " or by a multicall binary (busybox x) is another image",
    ),
    "path": (
        "a place is compared as written: ~/.aws matches only paths written with ~, never /home/me/.aws; no link,"
        " junction or subst drive is followed",
        "a Bash command that touches the place (cat, cp, a script) records its program, never its arguments",
        "a tool whose path is in a field other than file_path, notebook_path or path",
        "the os source's file lines and the host source's lines are not read by this rule",
        "a POSIX path is case-sensitive (/Data is not /data); a Windows path is folded A-Z only",
        "a place with * or ? is a pattern matched case-sensitively on the path as written, with no folding",
    ),
    "host": (
        "a host reached by a Bash program (curl https://example.com) is an argument: capture never records it",
        "a sub-domain, another name of the same server, or its IP address is another host",
        "a URL in a field not named url, or a redirect the tool followed, is not read",
        "the os source's net lines carry an address and a port, not a host name; the host source's connection"
        " lines are not read",
    ),
    "tool": (
        "the same act done by another tool (a file read by Bash cat instead of Read) is another tool",
        "a tool name is matched exactly and case-sensitively: an MCP tool renamed by its server is another name",
        "a tool the hook never sees (a tool of another agent, or one run with no hook) is never recorded",
    ),
}
READS = {
    "program": "It reads three kinds of line: a Bash line, by its first program (command_head) and, when capture"
               " could read the whole command, every program in it (command_programs); a host source line of tool"
               " HostChild, by the image names of a tree's new children (command_programs); and an os source"
               " process line (Sysmon event 1), by its image name (input_meta.image). It reads no other line.",
    "path": "It reads the file tools' lines (%s) by their path (input_meta.path, from file_path, notebook_path or"
            " path). It reads no other line." % ", ".join(FILE_TOOLS),
    "host": "It reads every tool line that carries a URL host (input_meta.url_host, from the url field of the tool"
            " input: WebFetch, and any tool with a url). It reads no other line.",
    "tool": "It reads every tool line (pre), by its tool name. It reads no other field.",
}


class Refused(ValueError):
    """The answers refused: refusals is [(field, why)], each in a person's words."""

    def __init__(self, refusals):
        self.refusals = list(refusals)
        super().__init__("; ".join("%s: %s" % (FIELD_WORDS.get(f, f), why) for f, why in self.refusals))


def split_values(text):
    """A person's list: a list as given, or text split on commas and new lines; blanks dropped, order kept."""
    if isinstance(text, (list, tuple)):
        items = [str(v) for v in text]
    else:
        items = re.split(r"[,\n]", str(text or ""))
    out = []
    for item in items:
        item = item.strip()
        if item and item not in out:
            out.append(item)
    return out


def _printable(text):
    return all(c.isprintable() and c not in "\t\r\n" for c in text)


def check_program(value):
    """(name, None) or (None, why): a program as capture names it (HEAD_NAME, lower case, no .exe)."""
    value = value.strip()
    if "/" in value or "\\" in value:
        return None, "%r is a path: write the program's name only (curl), capture records names, never paths" % value
    name = discover.image_name(value)
    if not name or not common.HEAD_NAME.match(name):
        return None, ("%r is not a program name capture records: letters, digits and _ . + [ - only, up to %d"
                      % (value, common.COMMAND_HEAD_MAX))
    return name, None


def check_host(value):
    value = value.strip().lower()
    if "://" in value or "/" in value:
        return None, "%r is a URL: write the host name only (example.com)" % value
    if "*" in value:
        return None, "%r: a host is named whole; a sub-domain is another host, name each one" % value
    labels = value.split(".")
    if not value or len(value) > 253 or not all(HOST_LABEL.match(x) for x in labels):
        return None, ("%r is not a host name: letters, digits and - in parts joined by dots (example.com)"
                      % value)
    return value, None


def check_tool(value):
    value = value.strip()
    if not TOOL_NAME.match(value):
        return None, ("%r is not a tool name: a letter, then letters, digits, _ . or - (Bash, WebFetch,"
                      " mcp__server__tool)" % value)
    return value, None


def path_system(place):
    """"windows" for a drive or UNC place, else "posix" (engine.norm_path's own reading)."""
    placed = engine.norm_path(place)
    return placed[0] if placed else "posix"


def check_place(value, example=False):
    """(place, None) or (None, why): a whole path (/, ~, a drive or a UNC share), one line of printable
    characters with no .. part; a place (not an example) may hold * or ? as a pattern."""
    value = value.strip()
    if not value:
        return None, "empty"
    if len(value) > PLACE_MAX:
        return None, "%r is longer than %d characters" % (value[:40] + "...", PLACE_MAX)
    if not _printable(value):
        return None, "%r holds a tab, a new line or a control character" % value
    if not (value.startswith(("/", "~")) or engine.WINDOWS_PATH.match(value)):
        return None, ("%r is not a whole path: start it at / or ~ or a drive (/srv/data, ~/.aws,"
                      " C:\\Users\\me\\secrets)" % value)
    if ".." in re.split(r"[\\/]", value):
        return None, "%r has a .. part: write the place itself" % value
    if "[" in value or "]" in value:
        return None, "%r: [ ] sets are not supported; use * or ?" % value
    if example and any(c in value for c in GLOB_CHARS):
        return None, "%r: an example is one file, with no * or ?" % value
    return value, None


CHECKERS = {"program": check_program, "host": check_host, "tool": check_tool,
            "path": lambda v: check_place(v)}
EXAMPLE_CHECKERS = {"program": check_program, "host": check_host, "tool": check_tool,
                    "path": lambda v: check_place(v, example=True)}


def taken_ids(home=None, catalog=None):
    return overlay.taken_ids(home, catalog)


def check(answers, taken=()):
    """(clean answers, refusals): every field checked, every refusal named with its field."""
    a = dict(answers or {})
    out, refusals = {}, []
    rid = str(a.get("id") or "").strip()
    if not rid:
        refusals.append(("id", "empty: give the rule an id such as MY-RULE"))
    elif len(rid) > ID_MAX or not engine.RULE_ID.match(rid):
        refusals.append(("id", "%r: an id is upper-case letters and digits in parts joined by dashes, such as"
                               " MY-RULE (at most %d characters; it names the rule's folder)" % (rid, ID_MAX)))
    elif rid in set(taken):
        refusals.append(("id", "%s is taken: a rule of the package or of rules.d has it" % rid))
    out["id"] = rid
    when = str(a.get("when") or "").strip()
    if when not in FORMS:
        refusals.append(("when", "choose one: %s" % "; ".join(FORM_WORDS[f] for f in FORMS)))
    out["when"] = when
    severity = str(a.get("severity") or "").strip()
    if severity not in SEVERITIES:
        refusals.append(("severity", "choose one of %s" % ", ".join(SEVERITIES)))
    out["severity"] = severity
    values = split_values(a.get("values"))
    names = []
    if when in FORMS:
        if not values:
            refusals.append(("values", "empty: name at least one (%s)" % VALUE_WORDS[when]))
        elif len(values) > VALUES_MAX:
            refusals.append(("values", "%d given: at most %d" % (len(values), VALUES_MAX)))
        else:
            for v in values:
                name, why = CHECKERS[when](v)
                if why:
                    refusals.append(("values", why))
                    break
                if name not in names:
                    names.append(name)
    out["values"] = names
    for field in ("fires", "quiet"):
        text = str(a.get(field) or "").strip()
        value = None
        if not text:
            refusals.append((field, "empty: give one example"))
        elif when in FORMS:
            value, why = EXAMPLE_CHECKERS[when](text)
            if why:
                refusals.append((field, why))
        out[field] = value
    title = str(a.get("title") or "").strip()
    if not title and when in FORMS and names:
        title = "%s: %s" % (FORM_WORDS[when][0].upper() + FORM_WORDS[when][1:], ", ".join(names))
        if len(title) > TITLE_MAX:
            title = title[:TITLE_MAX - 3].rstrip(", ") + "..."
    if title and (len(title) > TITLE_MAX or not _printable(title) or "{" in title or "}" in title):
        refusals.append(("title", "one line of at most %d printable characters, with no { or }" % TITLE_MAX))
    out["title"] = title
    return out, refusals


def examples(when, values):
    """The two examples prefilled from the first name: (fires, quiet), or ("", "") when nothing to go on."""
    names = []
    for v in split_values(values):
        name, why = CHECKERS[when](v) if when in CHECKERS else (None, "")
        if name:
            names.append(name)
    if not names:
        return "", ""
    first = names[0]
    if when == "program":
        return first, next((q for q in QUIET_PROGRAMS if q not in names), "")
    if when == "host":
        return first, next((q for q in QUIET_HOSTS if q not in names), "")
    if when == "tool":
        return first, next((q for q in QUIET_TOOLS if q not in names), "")
    system = path_system(first.replace("*", "x").replace("?", "x"))
    if any(c in first for c in GLOB_CHARS):
        fires = first.replace("**", "example").replace("*", "example").replace("?", "x")
    else:
        fires = first.rstrip("/\\") + ("\\" if system == "windows" else "/") + "example.txt"
    placed = [engine.norm_path(n) for n in names if not any(c in n for c in GLOB_CHARS)]
    for q in QUIET_PATHS[system]:
        pq = engine.norm_path(q)
        if not any(p and engine._under(pq, p) for p in placed):   # a suggestion only: the engine judges it
            return fires, q
    return fires, ""


# --- the rule's text --------------------------------------------------------------------------------------

def _match(when, names):
    pre = {"field": "phase", "eq": "pre"}
    if when == "program":
        return {"all": [pre, {"any": [
            {"all": [{"field": "source", "eq": "os"}, {"field": "tool", "eq": "process"},
                     {"field": "input_meta.image", "in": list(names)}]},
            {"all": [{"any": [{"field": "source", "exists": False}, {"field": "source", "ne": "os"}]},
                     {"any": [
                         {"all": [{"field": "source", "eq": "host"}, {"field": "tool", "eq": "HostChild"},
                                  {"field": "input_meta.command_programs", "exists": True},
                                  {"field": "input_meta.command_programs", "has_any": list(names)}]},
                         {"all": [{"field": "tool", "eq": "Bash"},
                                  {"any": [{"field": "input_meta.command_head", "in": list(names)},
                                           {"all": [{"field": "input_meta.command_programs", "exists": True},
                                                    {"field": "input_meta.command_programs",
                                                     "has_any": list(names)}]}]}]}]}]}]}]}
    if when == "path":
        under = [n for n in names if not any(c in n for c in GLOB_CHARS)]
        globs = [n for n in names if any(c in n for c in GLOB_CHARS)]
        parts = ([{"field": "input_meta.path", "under_any": under}] if under else []) + \
                [{"field": "input_meta.path", "glob": g} for g in globs]
        return {"all": [pre, {"field": "tool", "in": list(FILE_TOOLS)},
                        {"field": "input_meta.path", "exists": True}, {"any": parts}]}
    if when == "host":
        return {"all": [pre, {"field": "input_meta.url_host", "exists": True},
                        {"field": "input_meta.url_host", "in": list(names)}]}
    return {"all": [pre, {"field": "tool", "in": list(names)}]}


SUMMARIES = {
    "program": "{tool} runs a watched program at seq {seq} (program {input_meta.command_head}, programs"
               " {input_meta.command_programs}, image {input_meta.image})",
    "path": "{tool} touches {input_meta.path} at seq {seq}",
    "host": "{tool} reaches {input_meta.url_host} at seq {seq}",
    "tool": "{tool} is used at seq {seq}",
}


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _lines(when, value, rid, n):
    """The fixture lines of one example (in the shape capture writes, trace.strict_problem): {file stem: lines}."""
    sid = "form-%s-%d" % (rid.lower(), n)
    base = {"ts": TS, "seq": 1, "phase": "pre", "input_sha256": _sha("%s %s %s" % (rid, when, value))}
    if when == "program":
        return {
            "bash": [dict(base, session_id=sid, tool="Bash", tool_use_id="toolu_form_%d" % n, cwd=POSIX_CWD,
                          input_meta={"command_head": value, "command_programs": [value]})],
            "host": [dict(base, session_id="host-%d" % (4200 + n), source="host", tool="HostChild", cwd="host",
                          input_meta={"command_programs": [value], "pid": 4200 + n, "round": 1, "run": "form",
                                      "children": [{"image": value, "pid": 4300 + n, "started": None}]})],
            "os": [dict(base, session_id="os-%d" % (4400 + n), source="os", tool="process", cwd=WINDOWS_CWD,
                        input_meta={"image": value, "parent_image": "explorer", "depth": 1,
                                    "command_head": value + ".exe", "command_programs": [value + ".exe"]})],
        }
    if when == "path":
        cwd = WINDOWS_CWD if path_system(value) == "windows" else POSIX_CWD
        return {"read": [dict(base, session_id=sid, tool="Read", tool_use_id="toolu_form_%d" % n, cwd=cwd,
                              input_meta={"path": value})]}
    if when == "host":
        return {"fetch": [dict(base, session_id=sid, tool="WebFetch", tool_use_id="toolu_form_%d" % n,
                               cwd=POSIX_CWD, input_meta={"url_host": value})]}
    return {"tool": [dict(base, session_id=sid, tool=value, tool_use_id="toolu_form_%d" % n, cwd=POSIX_CWD,
                          input_meta={})]}


def _scalar(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return repr(v)
    return json.dumps(str(v), ensure_ascii=True)


def _emit(value, indent, out):
    pad = " " * indent
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, (dict, list)):
                out.append("%s%s:" % (pad, k))
                _emit(v, indent + 2, out)
            else:
                out.append("%s%s: %s" % (pad, k, _scalar(v)))
        return
    for item in value:
        if isinstance(item, dict):
            first = True
            for k, v in item.items():
                lead = pad + ("- " if first else "  ")
                if isinstance(v, (dict, list)):
                    out.append("%s%s:" % (lead, k))
                    _emit(v, indent + 4, out)
                else:
                    out.append("%s%s: %s" % (lead, k, _scalar(v)))
                first = False
        else:
            out.append("%s- %s" % (pad, _scalar(item)))


def dumps(doc, rid):
    """The YAML text of doc in the subset raqib/rules/yamlite.py reads; read back and compared before it is
    used (what is written is what the loader reads)."""
    out = []
    _emit(doc, 0, out)
    text = HEADER % rid + "\n".join(out) + "\n"
    if yamlite.loads(text) != doc:   # never a silent misread
        raise Refused([("rule", "the rule's text did not read back as written (a bug of the form: said, never"
                                " written)")])
    return text


class Built:
    """The files of a rule made from answers: rid, when, answers, doc, yaml (text), files {rel: text}."""

    def __init__(self, answers, doc, yaml_text, files):
        self.answers, self.doc, self.yaml, self.files = answers, doc, yaml_text, files
        self.rid, self.when = answers["id"], answers["when"]


def build(answers, taken=()):
    """The rule's YAML text and its fixture files from the answers (Built), or Refused naming each field."""
    a, refusals = check(answers, taken)
    if refusals:
        raise Refused(refusals)
    when, names, rid = a["when"], a["values"], a["id"]
    files, positive, negative = {}, [], []
    for kind, value, n, into in (("positive", a["fires"], 1, positive), ("negative", a["quiet"], 2, negative)):
        for stem, lines in _lines(when, value, rid, n).items():
            rel = "%s-%s.json" % (kind, stem)
            body = {"lines": lines}
            if kind == "positive":
                body["expect_seq"] = [1]
            files[rel] = json.dumps(body, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
            into.append(rel)
    what = ", ".join(names)
    doc = {
        "id": rid, "title": a["title"], "class": CLASS_OF[when], "kind": "signature",
        "evasion": list(EVASIONS[when]), "severity": a["severity"], "fp_budget": FP_BUDGET,
        "description": "A person's rule, made from the rule form (M8.2): fires when %s (%s: %s). %s The two"
                       " examples given (must fire on %s, must stay quiet on %s) are its fixtures."
                       % (FORM_WORDS[when], VALUE_WORDS[when], what, READS[when], a["fires"], a["quiet"]),
        "summary": SUMMARIES[when], "match": _match(when, names),
        "fixtures": {"positive": positive, "negative": negative},
    }
    return Built(a, doc, dumps(doc, rid), files)


def fingerprint(answers):
    """The answers as checked, one string: Add is enabled only after a passing Test of the same answers."""
    a, _ = check(answers)
    return json.dumps(a, sort_keys=True, ensure_ascii=True)


# --- the staging place, the engine's judgement -------------------------------------------------------------

def staging_dir(home=None):
    return os.path.join(overlay.raqib_dir(home), STAGING_NAME)


def _stage(built, home=None):
    """Write built's files into a new directory under staging_dir(home) (realpath under ~/.raqib, no link on
    the way); the YAML's path. Only the id (checked) and the form's own file names are path parts."""
    base = staging_dir(home)
    overlay.fixture_file(overlay.raqib_dir(home), STAGING_NAME)   # no link: the staging place is Raqib's own
    os.makedirs(base, exist_ok=True)
    stage = tempfile.mkdtemp(prefix="form-", dir=base)
    for rel, text in list(built.files.items()) + [(built.rid + ".yaml", built.yaml)]:
        path = overlay.fixture_file(stage, rel)
        with open(path, "w", encoding="ascii", newline="\n") as f:
            f.write(text)
    return os.path.join(stage, built.rid + ".yaml")


def _unstage(yaml_path, home=None):
    """Remove the staging directory of yaml_path (only one under staging_dir(home), by realpath), then the
    staging place itself when it is empty: it is emptied after every Test and Add."""
    base = os.path.realpath(staging_dir(home))
    stage = os.path.realpath(os.path.dirname(yaml_path))
    if os.path.dirname(stage) == base and os.path.basename(stage).startswith("form-"):
        shutil.rmtree(stage, ignore_errors=True)
    try:
        os.rmdir(base)
    except OSError:
        pass


def _words(exc, yaml_path, rid):
    """The overlay's refusal with the staging path said as the rule's file name."""
    text = str(exc)
    return text.replace(yaml_path, rid + ".yaml") if yaml_path else text


def _engine_refusal(text):
    """The engine's refusal, said beside the field it is about (the engine's words kept)."""
    if "positives missed" in text or "positive-missed" in text:
        return "fires", "the engine says it did not fire on this example: %s" % text
    if "over-budget" in text:
        return "quiet", "the engine says it fired on this example, which must stay quiet: %s" % text
    if "already in the catalog" in text:
        return "id", text
    return "rule", text


class Result:
    """What Test or Add said: ok, refusals [(field, why)], yaml, files, records (on_records), said, rule."""

    def __init__(self):
        self.ok, self.refusals, self.yaml, self.files, self.records, self.said, self.rule = \
            False, [], None, {}, None, None, None
        self.answers = None

    def text(self):
        lines = []
        for field, why in self.refusals:
            lines.append("refused: %s: %s" % (FIELD_WORDS.get(field, field), why))
        if self.said:
            lines.append(self.said)
        if self.records is not None:
            lines.append(records_text(self.records))
            lines += ["  %s" % c for c in cited_text(self.records)]
        return lines


def test(answers, home=None, catalog=None, records=True):
    """E1-E3 without writing in rules.d: build, stage, judge by overlay.validate_rule, run on the records
    (read-only, bounded; never a gate), unstage. Result."""
    res = Result()
    taken = taken_ids(home, catalog)
    try:
        built = build(answers, taken)
    except Refused as exc:
        res.refusals = exc.refusals
        return res
    res.answers, res.yaml, res.files = built.answers, built.yaml, built.files
    yaml_path = None
    try:
        yaml_path = _stage(built, home)
        rule = overlay.validate_rule(yaml_path, os.path.dirname(yaml_path), taken, user=True)
    except overlay.OverlayError as exc:
        res.refusals = [_engine_refusal(_words(exc, yaml_path, built.rid))]
        return res
    except OSError as exc:
        res.refusals = [("rule", "the staging place %s cannot be written: %s" % (staging_dir(home),
                                                                                 exc.strerror or exc))]
        return res
    finally:
        if yaml_path is not None:
            _unstage(yaml_path, home)
    res.ok, res.rule = True, rule
    res.said = ("test passed: the loader and the fixture runner accept %s (fires on its example, quiet on the"
                " other); nothing is written yet" % built.rid)
    if records:
        res.records = on_records(rule, home)
    return res


def add(answers, home=None, catalog=None):
    """Build and stage the rule and add it through overlay.add_rule (the --add path: validated again there,
    copied under rules.d/<ID>/ by fixture_file); the staging place emptied; Result (said: add_rule's line)."""
    res = Result()
    taken = taken_ids(home, catalog)
    try:
        built = build(answers, taken)
    except Refused as exc:
        res.refusals = exc.refusals
        return res
    res.answers, res.yaml, res.files = built.answers, built.yaml, built.files
    yaml_path = None
    try:
        yaml_path = _stage(built, home)
        res.said = overlay.add_rule(yaml_path, home, catalog)
        res.ok = True
    except overlay.OverlayError as exc:
        res.refusals = [_engine_refusal(_words(exc, yaml_path, built.rid))]
    except OSError as exc:
        res.refusals = [("rule", "the staging place %s cannot be written: %s" % (staging_dir(home),
                                                                                 exc.strerror or exc))]
    finally:
        if yaml_path is not None:
            _unstage(yaml_path, home)
    return res


# --- on your records (E3): read-only, bounded, never a gate ----------------------------------------------

def record_files(home=None):
    """The trace and host source files under ~/.raqib, newest first: [(path, name)]; links never followed."""
    root = overlay.raqib_dir(home)
    found = []
    for top in (os.path.join(root, "traces"), os.path.join(root, "host", "sources")):
        if not os.path.isdir(top) or os.path.islink(top):
            continue
        for here, dirs, names in os.walk(top, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(here, d))]
            for name in names:
                path = os.path.join(here, name)
                if name.endswith(".jsonl") and not os.path.islink(path):
                    try:
                        found.append((os.path.getmtime(path), path))
                    except OSError:
                        continue
    found.sort(key=lambda x: (-x[0], x[1]))
    return [(p, os.path.relpath(p, root).replace("\\", "/")) for _, p in found]


def _tail(path, limit):
    """(text, cut): the last `limit` bytes of path, from its first whole line; read-only."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - limit))
        data = f.read(limit)
    cut = size > limit
    if cut:
        data = data.split(b"\n", 1)[1] if b"\n" in data else b""
    return data.decode("utf-8", "replace"), cut


def on_records(rule, home=None, max_files=RECORD_FILES, max_lines=RECORD_LINES, max_bytes=RECORD_BYTES):
    """The rule run over the newest records under ~/.raqib: {files, lines, fired, fired_files, cited:
    [(name, seq)], cut, more_files, unreadable, bounds}. Read-only; information, never a gate."""
    files = record_files(home)
    out = {"files": 0, "lines": 0, "fired": 0, "fired_files": 0, "cited": [], "cut": False,
           "more_files": max(0, len(files) - max_files), "unreadable": [],
           "bounds": (max_files, max_lines, max_bytes)}
    left = max_lines
    for path, name in files[:max_files]:
        if left <= 0:
            out["cut"] = True
            break
        try:
            text, cut = _tail(path, max_bytes)
        except OSError as exc:
            out["unreadable"].append("%s: %s" % (name, exc.strerror or exc))
            continue
        numbered, _ = trace.parse_numbered(text)
        if len(numbered) > left:
            numbered, cut = numbered[-left:], True
        out["cut"] = out["cut"] or cut
        left -= len(numbered)
        out["files"] += 1
        out["lines"] += len(numbered)
        found, _ = engine.judge(rule, [rec for _, rec in numbered], {})
        hits = sorted({(f.get("session_id"), s) for f in found for s in f.get("cited_seq", ())},
                      key=lambda x: (str(x[0]), x[1]))
        if hits:
            out["fired"] += len(hits)
            out["fired_files"] += 1
            for _, seq in hits:
                if len(out["cited"]) < CITED_MAX:
                    out["cited"].append((name, seq))
    return out


def records_text(r):
    """E3's line, in a person's words; no records is said, never hidden."""
    nf, nl, nb = r["bounds"]
    bounds = "the newest %d files, at most %s lines in all and %s MB of each" % (nf, "{:,}".format(nl),
                                                                                 "%g" % (nb / 1e6))
    if not r["files"]:
        tail = "; %d could not be read" % len(r["unreadable"]) if r["unreadable"] else ""
        return ("on your records: no trace or host source file under ~/.raqib yet, nothing to run it on%s"
                " (it would read %s)" % (tail, bounds))
    text = "on your records: would have fired on %s of %s lines in %d files" % (
        "{:,}".format(r["fired"]), "{:,}".format(r["lines"]), r["files"])
    if r["fired"]:
        text += " (%d of them with a line)" % r["fired_files"]
    extra = []
    if r["cut"] or r["more_files"]:
        extra.append("read: %s%s" % (bounds, "; %d older files not read" % r["more_files"] if r["more_files"]
                                     else ""))
    else:
        extra.append("read: every file (%s)" % bounds)
    if r["unreadable"]:
        extra.append("%d could not be read" % len(r["unreadable"]))
    return text + "; " + "; ".join(extra) + "; information only, never a gate"


def cited_text(r):
    return ["%s, seq %s" % (name, seq) for name, seq in r["cited"]]
