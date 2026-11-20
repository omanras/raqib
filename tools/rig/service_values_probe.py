"""Probe only (never merged): which values of a service's key Windows itself changes (M15.3c, before it is ruled).
Ten quiet minutes under main's Watcher said `changed service "BITS"` three times and no other service. This reads
the values of that service's key, and of every service's, every two seconds for some minutes and says which value
names changed, with a number's old and new value (a text's and a binary's only as changed). It changes nothing.
usage: service_values_probe.py SECONDS"""
import sys
import time
import winreg

SERVICES = r"SYSTEM\CurrentControlSet\Services"


def values(path):
    out = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            i = 0
            while True:
                try:
                    name, data, kind = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                out[name] = (kind, data)
    except OSError:
        return None
    return out


def names():
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES) as key:
        return [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]


def main(seconds):
    held = {n: values(SERVICES + "\\" + n) for n in names()}
    print("services read: %d; BITS holds the values: %s" % (len(held), sorted((held.get("BITS") or {}))))
    end, rounds, said = time.monotonic() + seconds, 0, 0
    while time.monotonic() < end:
        time.sleep(2)
        rounds += 1
        for n in names():
            now = values(SERVICES + "\\" + n)
            old = held.get(n)
            if now == old:
                continue
            held[n] = now
            if old is None or now is None:
                print("round %d: service %s %s" % (rounds, n, "appeared" if old is None else "gone or unreadable"))
                said += 1
                continue
            for v in sorted(set(old) | set(now)):
                a, b = old.get(v), now.get(v)
                if a == b:
                    continue
                said += 1
                if a is None or b is None:
                    print("round %d: service %s: value %s %s" % (rounds, n, v, "added" if a is None else "removed"))
                elif isinstance(a[1], int) and isinstance(b[1], int):
                    print("round %d: service %s: value %s: %d -> %d" % (rounds, n, v, a[1], b[1]))
                else:
                    print("round %d: service %s: value %s changed (kind %s)" % (rounds, n, v, b[0]))
    print("rounds: %d; changes said: %d" % (rounds, said))
    return 0


if __name__ == "__main__":
    sys.exit(main(float(sys.argv[1])))
