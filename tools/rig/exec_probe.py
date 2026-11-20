"""Probe only (never merged): what real agents and common shell idioms do with their processes, read from an
strace of their own tree (strace -f -ttt -e trace=execve,clone,clone3,fork,vfork,exit_group), before M14.1d is
ruled (ADR-0007 BZ-3). It counts, for the processes of the traced tree:
  - how many ran more than one program in one pid (an exec after an exec), and how far apart in time;
  - how many programs are named differently by their file (the target of the link that was run) and by the name
    they were called by (argv[0]) - what a list of names would miss;
  - how many children began while their parent had been alive for more than a round and saw that parent end
    within a round after (a child whose parent is gone by the next sample).
It reads a file and prints counts and a few examples by program name only; it runs nothing."""
import collections
import os
import re
import sys

LINE = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(.*)$")
EXEC = re.compile(r'^execve\("([^"]*)", \["([^"]*)"')
FORK = re.compile(r"^(clone3?|fork|vfork)\((.*)\)\s+=\s+(\d+)\s*$")
ROUND = float(os.environ.get("ROUND_SECONDS", "5"))


def base(path):
    return os.path.basename(path.rstrip("/")) or path


def main(path, label):
    execs, parent, born, gone = collections.defaultdict(list), {}, {}, {}
    pending = {}
    for raw in open(path, encoding="utf-8", errors="replace"):
        m = LINE.match(raw.rstrip("\n"))
        if not m:
            continue
        pid, at, rest = int(m.group(1)), float(m.group(2)), m.group(3)
        if rest.endswith("<unfinished ...>"):
            pending[pid] = rest[:-len("<unfinished ...>")]
            continue
        resumed = re.match(r"^<\.\.\. \w+ resumed>\s*(.*)$", rest)
        if resumed:
            rest = pending.pop(pid, "") + resumed.group(1)
        born.setdefault(pid, at)
        e = EXEC.match(rest)
        if e and rest.rstrip().endswith("= 0"):
            execs[pid].append((at, e.group(1), e.group(2)))
            continue
        f = FORK.match(rest)
        if f and "CLONE_THREAD" not in f.group(2):
            child = int(f.group(3))
            parent[child] = (pid, at)
            born[child] = at
            continue
        if rest.startswith("exit_group(") or rest.startswith("+++ exited") or rest.startswith("+++ killed"):
            gone.setdefault(pid, at)
    pids = set(born)
    several = {p: v for p, v in execs.items() if len(v) > 1}
    late = {p: v for p, v in several.items() if v[-1][0] - v[0][0] > ROUND}
    print("EXEC %s: %d process(es) traced, %d ran a program, %d ran more than one program in one pid, %d of them"
          " with more than %.0f s between the first and the last" % (label, len(pids), len(execs), len(several),
                                                                   len(late), ROUND))
    chains = collections.Counter(" -> ".join(base(x[1]) for x in v) for v in several.values())
    for chain, n in chains.most_common(8):
        print("   %d x %s" % (n, chain))
    for p, v in list(late.items())[:5]:
        print("   late: %s after %.1f s" % (" -> ".join(base(x[1]) for x in v), v[-1][0] - v[0][0]))
    named = collections.Counter()
    for v in execs.values():
        for _, file_, argv0 in v:
            real = base(os.path.realpath(file_)) if os.path.exists(file_) else base(file_)
            if real != base(argv0):
                named[(base(argv0), base(file_), real)] += 1
    print("NAMES %s: %d program run(s) whose file's own name is not the name it was called by" % (
        label, sum(named.values())))
    for (called, ran, real), n in named.most_common(12):
        print("   %d x called %s, the path's name %s, its file %s" % (n, called, ran, real))
    orphans = []
    for child, (p, at) in parent.items():
        p_born, p_gone = born.get(p), gone.get(p)
        if p_born is None or p_gone is None:
            continue
        if at - p_born > ROUND and 0 <= p_gone - at < ROUND and gone.get(child, 1e18) > p_gone:
            orphans.append((child, p))
    print("PARENTS %s: %d child(ren) of %d began under a parent older than a round that ended within a round after,"
          " the child still alive" % (label, len(orphans), len(parent)))
    for child, p in orphans[:6]:
        print("   child %s under %s" % (base(execs[child][-1][1]) if execs.get(child) else "(no program)",
                                        base(execs[p][-1][1]) if execs.get(p) else "(no program)"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "trace"))
