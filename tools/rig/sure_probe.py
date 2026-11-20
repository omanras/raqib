"""Probe only (never merged): how M15.3b's `sure` (ADR-0014 AJ-3, AK-3) labels the texts a real Windows machine holds,
before the Table rules the third review's S3 - the module's own function over every service's ImagePath, the Run
values and Winlogon's two values; and how many users' hives are loaded (the review's Q3). It reads the registry and
changes nothing. usage: sure_probe.py FOLDER_OF_THE_MODULE"""
import collections
import re
import sys
import winreg

sys.path.insert(0, sys.argv[1])
import autostart   # the file of claude/M15.3b, fetched beside this probe


def why(text):
    if any(c.isspace() and c not in " \t" for c in text):
        return "a blank other than space or tab"
    first = re.split(r"[ \t]", text, maxsplit=1)[0]
    if text.startswith('"'):
        return "a quoted first word that holds %"
    if "%" in first:
        return "an unquoted first word that holds %"
    runs = {text[:m.start()].rstrip(" \t") for m in re.finditer(r"[ \t]", text)} | {text}
    if sum(1 for r in runs if r and r.lower().endswith(autostart.PROGRAM_EXTENSIONS)) > 1:
        return "more than one run ends in a program's extension"
    return "a separator, a blank after it, no program's extension"


def texts_of(root, path, names=None, view=0):
    out = []
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
            i = 0
            while True:
                try:
                    name, data, kind = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if isinstance(data, str) and (names is None or name.lower() in names):
                    out.append(data)
    except OSError as exc:
        print("  could not read %s: %s" % (path, exc))
    return out


def say(place, texts):
    count = collections.Counter()
    shown = collections.defaultdict(list)
    for t in texts:
        if autostart._sure(t):
            count["sure"] += 1
        else:
            w = why(t)
            count[w] += 1
            if len(shown[w]) < 4:
                shown[w].append(t[:110])
    print("%s: %d text(s); %s" % (place, len(texts), "; ".join("%s %d" % kv for kv in sorted(count.items()))))
    for w, some in sorted(shown.items()):
        for t in some:
            print("    not sure (%s): %s" % (w, t))


def main():
    services = []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as key:
        n = winreg.QueryInfoKey(key)[0]
        for i in range(n):
            name = winreg.EnumKey(key, i)
            services += texts_of(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services" + "\\" + name,
                                 names=("imagepath",))
    say("services' ImagePath", services)
    run = []
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        for leaf in ("Run", "RunOnce"):
            run += texts_of(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion" + "\\" + leaf,
                            view=view)
    hives = []
    with winreg.OpenKey(winreg.HKEY_USERS, "") as key:
        for i in range(winreg.QueryInfoKey(key)[0]):
            hives.append(winreg.EnumKey(key, i))
    users = [h for h in hives if not h.lower().endswith("_classes")]
    for sid in users:
        for leaf in ("Run", "RunOnce"):
            run += texts_of(winreg.HKEY_USERS, sid + r"\Software\Microsoft\Windows\CurrentVersion" + "\\" + leaf)
    say("Run and RunOnce values (the machine's, both views, and every loaded hive's)", run)
    say("Winlogon's Shell and Userinit", texts_of(winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", names=("shell", "userinit")))
    print("hives under HKEY_USERS: %d key(s), %d of them not a _Classes key (by their SID's shape: %s)" % (
        len(hives), len(users), ", ".join(sorted(collections.Counter(
            re.sub(r"S-1-5-21-.*", "S-1-5-21-...", re.sub(r"^\.DEFAULT$", ".DEFAULT", h)) for h in users)))))
    got = autostart.read()
    labels = collections.Counter((e["place"], e["sure"]) for e in got["entries"])
    print("the module's own read: %s" % "; ".join("%s sure=%s %d" % (p, s, c) for (p, s), c in sorted(
        labels.items(), key=lambda kv: (kv[0][0], str(kv[0][1])))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
