"""Probe only (never merged): the eighteenth measurement - what Raqib's host watch keeps of the processes it samples.
It runs `raqib watch --host` for three rounds in a home of its own and counts, in every file the watch wrote, how
many processes are named, by which keys, and how large the files are. It prints numbers and the names of keys
only: no path, no command, no user's name. It changes nothing outside its own temporary folder."""
import collections
import json
import os
import re
import subprocess
import sys
import tempfile

PID_KEYS = ("pid", "ppid", "parent", "ProcessId", "ParentProcessId")
TEXT_KEYS = re.compile(r"(?i)cmd|command|argv|args|cwd|exe|image|path|user|env")


def walk(obj, pids, keys, texts, pre=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys[pre + k] += 1
            if k in PID_KEYS and isinstance(v, int):
                pids.add(v)
            if TEXT_KEYS.search(k) and isinstance(v, (str, list)) and v:
                texts[k] += 1
            walk(v, pids, keys, texts, pre + k + ".")
    elif isinstance(obj, list):
        for v in obj:
            walk(v, pids, keys, texts, pre + "[].")


def read(path):
    raw = open(path, encoding="utf-8", errors="replace").read()
    if path.endswith(".jsonl"):
        out = []
        for line in raw.splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"not-json": 1})
        return out
    try:
        return [json.loads(raw)]
    except ValueError:
        return []


def main():
    home = tempfile.mkdtemp(prefix="raqib-record-")
    env = dict(os.environ, HOME=home, USERPROFILE=home)
    proc = subprocess.run([sys.executable, "-m", "raqib", "watch", "--host", "--every", "2", "--rounds", "3",
                           "--no-notify"], env=env, capture_output=True, text=True, errors="replace", timeout=600)
    rep = proc.stdout
    print("watch: exit %d; %s" % (proc.returncode, (re.search(r"^RESULT: .*$", rep, re.M) or [None])[0] and
                                    re.search(r"^RESULT: ([A-Z-]+)", rep, re.M).group(1)))
    rounds = [int(n) for n in re.findall(r"round \d+(?: \(late[^)]*\))?: (\d+) records read", rep)]
    seen = re.search(r"^TREES SEEN: (\d+)", rep, re.M)
    print("records read a round: %s; trees seen: %s" % (rounds[:3], seen.group(1) if seen else "not said"))
    root = os.path.join(home, ".raqib")
    every = set()
    for folder, _, names in sorted(os.walk(root)):
        for name in sorted(names):
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            rel = re.sub(r"sources/.*", "sources/<one a tree>", rel)
            if not name.endswith((".json", ".jsonl")):
                print("%-28s %7d bytes (not read)" % (rel, os.path.getsize(path)))
                continue
            pids, keys, texts = set(), collections.Counter(), collections.Counter()
            lines = read(path)
            for line in lines:
                walk(line, pids, keys, texts)
            every |= pids
            kinds = collections.Counter(x.get("kind") for x in lines if isinstance(x, dict) and "kind" in x)
            print("%-28s %7d bytes, %3d line(s), %3d distinct process ids named; keys holding text of a process:"
                  " %s%s" % (rel, os.path.getsize(path), len(lines), len(pids), dict(sorted(texts.items())) or "none",
                             "; kinds %s" % dict(kinds) if kinds else ""))
            if name == "inventory.json" and lines:
                inv = lines[0]
                print("    inventory: processes %s (keys of one: %s), candidates %d, act_roots %d, records %s" % (
                    len(inv.get("processes", [])), sorted((inv.get("processes") or [{}])[0].keys()),
                    len(inv.get("candidates", [])), len(inv.get("act_roots", [])), inv.get("records")))
                tree = set()
                for c in inv.get("candidates", []) + inv.get("act_roots", []):
                    walk(c, tree, collections.Counter(), collections.Counter())
                named = {p.get("pid") for p in inv.get("processes", []) if isinstance(p, dict)}
                print("    of the processes it lists, in no candidate's or act-root's entry: %d" % len(named - tree))
            if name == "events.jsonl":
                subj = {x["subject"].get("pid") for x in lines if isinstance(x.get("subject"), dict)}
                print("    events: distinct subjects %d; the longest event %d bytes" % (
                    len(subj - {None}), max((len(json.dumps(x)) for x in lines), default=0)))
    print("distinct process ids named in all the files together: %d, of about %s sampled a round" % (
        len(every), max(rounds) if rounds else "?"))


if __name__ == "__main__":
    main()
