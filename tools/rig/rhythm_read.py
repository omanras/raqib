"""Probe only: what the rounds' record says of each tree's rhythm (cycles, their rounds, the destination, the
talks and acts each line counted). Reads ~/.raqib/host/rounds.jsonl; prints one line per HostTree line that has a
talk, an act or a cycle, and the HOST-RHYTHM findings. Usage: python tools/rig/rhythm_read.py [IMAGE ...]"""
import json
import os
import sys


def walk(x, out):
    if isinstance(x, dict):
        if x.get("tool") == "HostTree" and isinstance(x.get("input_meta"), dict):
            out.append(x)
        if x.get("rule_id") == "HOST-RHYTHM":
            out.append(x)
        for v in x.values():
            walk(v, out)
    elif isinstance(x, list):
        for v in x:
            walk(v, out)


def main(argv):
    want = [a.lower() for a in argv[1:]]
    path = os.path.join(os.path.expanduser("~"), ".raqib", "host", "rounds.jsonl")
    seen = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        found = []
        walk(rec, found)
        for x in found:
            if x.get("rule_id") == "HOST-RHYTHM":
                key = ("f", x.get("run"), x.get("round"), x.get("tree"))
                if key not in seen:
                    seen.add(key)
                    print("FINDING HOST-RHYTHM run %s round %s tree %s rounds %s" % (
                        x.get("run"), x.get("round"), x.get("tree"), x.get("cycle_rounds")))
                continue
            m = x["input_meta"]
            rh = m.get("rhythm") if isinstance(m.get("rhythm"), dict) else {}
            image = str(m.get("image") or "").lower()
            if want and not any(w in image for w in want):
                continue
            key = (m.get("run"), m.get("round"), m.get("pid"))
            if key in seen:
                continue
            seen.add(key)
            talks = rh.get("talks")
            print("run %s round %s pid %s %s class %s named %s: cycles %s rounds %s dest %s talks %s acts %s"
                  " read_talks %s read_acts %s fires %s endpoints %s" % (
                      str(m.get("run"))[-9:], m.get("round"), m.get("pid"), m.get("image"), m.get("class"),
                      m.get("named"), rh.get("cycles"), rh.get("rounds"), rh.get("destination"),
                      len(talks) if isinstance(talks, list) else talks, rh.get("acts"), rh.get("read_talks"),
                      rh.get("read_acts"), rh.get("fires"), m.get("endpoints")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
