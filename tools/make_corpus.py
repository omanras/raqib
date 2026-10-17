#!/usr/bin/env python3
"""Generate the synthetic benign corpora of the example rule set.

    python3 tools/make_corpus.py [--out corpus/]

Writes, from a fixed seed, three JSON Lines files of 1,000 benign events
each, headed by the Mizan logsource declaration (ADR-0001 section 7):

    corpus/windows-process_creation.jsonl
    corpus/linux-auth.jsonl
    corpus/webserver.jsonl

Everything is invented: hosts live under ``.corp.example`` or
``.example.test``, users are ``user01``..``user40`` / ``adm01``..``adm03``,
IP addresses come from the documentation ranges 192.0.2.0/24 (office),
198.51.100.0/24 (partner) and 203.0.113.0/24 (internet) (RFC 5737).
A handful of benign events are placed on purpose so that the example rules
have a measurable, non-zero false-positive rate: an administrator running
an encoded PowerShell script, ``whoami`` from a help-desk session, an
installer creating a scheduled task from ``Temp``, ``sudo -i`` by an
administrator, one SSH login from the internet, and a partner integration
that uses ``python-requests``.  Their positions are fixed so that
``tests/test_examples.py`` can regenerate the files and compare bytes.

Only ``random.Random.random``, ``randrange`` and ``choice`` are used; their
output for a given seed is stable across Python 3 versions.
"""

import argparse
import json
import os
import random
import sys

SEED = 20261017
EVENTS_PER_FILE = 1000
GENERATOR = "tools/make_corpus.py"

OFFICE_NET = "192.0.2."
PARTNER_NET = "198.51.100."
INTERNET_NET = "203.0.113."
BASTION_IP = INTERNET_NET + "10"


def _dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _write(path, logsource, events):
    header = {"_mizan": {"logsource": logsource, "generator": GENERATOR, "seed": SEED,
                         "events": len(events)}}
    with open(path, "w", encoding="ascii", newline="\n") as handle:
        handle.write(_dumps(header) + "\n")
        for event in events:
            handle.write(_dumps(event) + "\n")


def _clock(base_hour, index, step_seconds):
    """A deterministic timestamp on 2026-10-17 for event ``index``."""
    seconds = base_hour * 3600 + index * step_seconds
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return "2026-10-17T%02d:%02d:%02dZ" % (hours % 24, minutes, secs)


# --- windows / process_creation ---------------------------------------------------------------

_WIN_USERS = ["EXAMPLE\\user%02d" % n for n in range(1, 41)]
_WIN_ADMINS = ["EXAMPLE\\adm%02d" % n for n in range(1, 4)]
_SYSTEM = "NT AUTHORITY\\SYSTEM"

_WIN_PROFILES = [
    # (weight, Image, [CommandLine...], ParentImage, user kind, IntegrityLevel)
    (18, "C:\\Windows\\System32\\svchost.exe",
     ["C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule",
      "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
      "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s Dnscache"],
     "C:\\Windows\\System32\\services.exe", "system", "System"),
    (10, "C:\\Windows\\System32\\conhost.exe",
     ["\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1"],
     "C:\\Windows\\System32\\cmd.exe", "user", "Medium"),
    (12, "C:\\Program Files\\Example Browser\\browser.exe",
     ["\"C:\\Program Files\\Example Browser\\browser.exe\" --type=renderer --lang=en-US",
      "\"C:\\Program Files\\Example Browser\\browser.exe\" --type=utility --utility-sub-type=network"],
     "C:\\Program Files\\Example Browser\\browser.exe", "user", "Low"),
    (8, "C:\\Program Files\\Example Office\\mail.exe",
     ["\"C:\\Program Files\\Example Office\\mail.exe\"", "\"C:\\Program Files\\Example Office\\mail.exe\" /recycle"],
     "C:\\Windows\\explorer.exe", "user", "Medium"),
    (8, "C:\\Windows\\System32\\cmd.exe",
     ["C:\\Windows\\system32\\cmd.exe /c dir /s C:\\Projects\\build",
      "cmd.exe /c copy \\\\fs01.corp.example\\share\\report.xlsx C:\\Users\\Public\\Documents\\",
      "C:\\Windows\\system32\\cmd.exe /c \"C:\\Program Files\\Example Tools\\build.cmd\" release",
      "cmd.exe /c ping -n 2 fs01.corp.example"],
     "C:\\Windows\\explorer.exe", "user", "Medium"),
    (7, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     ["powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Program Files\\Example Tools\\inventory.ps1",
      "powershell.exe -NoLogo -Command \"Get-Service | Where-Object Status -eq Running\"",
      "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -File C:\\Scripts\\backup.ps1 -Verbose",
      "powershell.exe -Command Get-ChildItem C:\\Users\\Public\\Downloads"],
     "C:\\Windows\\explorer.exe", "mixed", "Medium"),
    (6, "C:\\Windows\\System32\\taskhostw.exe",
     ["taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}", "taskhostw.exe KEYROAMING"],
     "C:\\Windows\\System32\\svchost.exe", "user", "Medium"),
    (5, "C:\\Windows\\System32\\rundll32.exe",
     ["C:\\Windows\\system32\\rundll32.exe C:\\Windows\\system32\\inetcpl.cpl,ClearMyTracksByProcess 8",
      "rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL desk.cpl",
      "rundll32.exe printui.dll,PrintUIEntry /in /n \\\\print01.corp.example\\Floor2"],
     "C:\\Windows\\explorer.exe", "user", "Medium"),
    (4, "C:\\Windows\\System32\\schtasks.exe",
     ["schtasks.exe /Query /TN \"Example Updater\" /FO LIST",
      "schtasks.exe /Create /TN \"Example Inventory\" /TR \"C:\\Program Files\\Example Tools\\inventory.exe\" /SC DAILY /ST 02:00 /F",
      "schtasks.exe /Run /TN \"Example Updater\"",
      "schtasks.exe /Change /TN \"Example Updater\" /ENABLE"],
     "C:\\Windows\\System32\\cmd.exe", "admin", "High"),
    (5, "C:\\Windows\\System32\\msiexec.exe",
     ["msiexec.exe /i \"C:\\Users\\user12\\Downloads\\ExampleClient-4.2.msi\" /qn",
      "C:\\Windows\\System32\\msiexec.exe /V"],
     "C:\\Windows\\System32\\services.exe", "system", "System"),
    (4, "C:\\Windows\\System32\\WerFault.exe",
     ["C:\\Windows\\system32\\WerFault.exe -u -p 4812 -s 1840"],
     "C:\\Program Files\\Example Browser\\browser.exe", "user", "Medium"),
    (3, "C:\\Windows\\System32\\whoami.exe",
     ["whoami.exe", "whoami /groups"],
     "C:\\Windows\\System32\\svchost.exe", "system", "System"),
    (4, "C:\\Windows\\System32\\net.exe",
     ["net use Z: \\\\fs01.corp.example\\projects /persistent:yes", "net view \\\\fs01.corp.example"],
     "C:\\Windows\\System32\\cmd.exe", "user", "Medium"),
    (3, "C:\\Windows\\System32\\wscript.exe",
     ["\"C:\\Windows\\System32\\wscript.exe\" \\\\dc01.corp.example\\netlogon\\mapdrives.vbs"],
     "C:\\Windows\\explorer.exe", "user", "Medium"),
    (3, "C:\\Windows\\explorer.exe",
     ["C:\\Windows\\Explorer.EXE", "explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding"],
     "C:\\Windows\\System32\\userinit.exe", "user", "Medium"),
]

_WIN_PLANTED = {
    # index -> event: the deliberate benign matches of the example rules
    137: {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "CommandLine": "powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBEAGEAdABlAA==",
          "ParentImage": "C:\\Windows\\System32\\svchost.exe", "User": "EXAMPLE\\adm02",
          "IntegrityLevel": "High"},
    412: {"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /all",
          "ParentImage": "C:\\Windows\\System32\\cmd.exe", "User": "EXAMPLE\\adm01",
          "IntegrityLevel": "High"},
    655: {"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami.exe",
          "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "User": "EXAMPLE\\user17", "IntegrityLevel": "Medium"},
    803: {"Image": "C:\\Windows\\System32\\schtasks.exe",
          "CommandLine": "schtasks.exe /Create /TN \"ExampleClient Update\" /TR "
                         "\"C:\\Users\\user12\\AppData\\Local\\Temp\\ExampleClient\\updater.exe\" /SC HOURLY /F",
          "ParentImage": "C:\\Windows\\System32\\msiexec.exe", "User": "EXAMPLE\\user12",
          "IntegrityLevel": "High"},
}


def _weighted(rnd, profiles):
    total = sum(p[0] for p in profiles)
    pick = rnd.randrange(total)
    for profile in profiles:
        pick -= profile[0]
        if pick < 0:
            return profile
    return profiles[-1]


def windows_events(rnd):
    events = []
    for index in range(EVENTS_PER_FILE):
        _weight, image, commands, parent, kind, integrity = _weighted(rnd, _WIN_PROFILES)
        if kind == "system":
            user = _SYSTEM
        elif kind == "admin":
            user = rnd.choice(_WIN_ADMINS)
        elif kind == "mixed":
            user = rnd.choice(_WIN_ADMINS) if rnd.random() < 0.3 else rnd.choice(_WIN_USERS)
        else:
            user = rnd.choice(_WIN_USERS)
        event = {
            "EventID": 1,
            "UtcTime": _clock(6, index, 41),
            "Computer": "ws%02d.corp.example" % (rnd.randrange(40) + 1),
            "User": user,
            "Image": image,
            "CommandLine": rnd.choice(commands),
            "ParentImage": parent,
            "ProcessId": 1000 + rnd.randrange(60000),
            "ParentProcessId": 500 + rnd.randrange(900),
            "IntegrityLevel": integrity,
        }
        planted = _WIN_PLANTED.get(index)
        if planted is not None:
            event.update(planted)
        events.append(event)
    return events


# --- linux / auth -----------------------------------------------------------------------------

_LINUX_USERS = ["user%02d" % n for n in range(1, 25)]
_LINUX_ADMINS = ["adm01", "adm02", "adm03", "deploy"]
_LINUX_HOSTS = ["srv%02d.corp.example" % n for n in range(1, 13)]

_LINUX_PLANTED = {
    211: {"process": "sshd", "user": "adm03", "src_ip": INTERNET_NET + "77",
          "message": "Accepted publickey for adm03 from 203.0.113.77 port 51022 ssh2: ED25519 SHA256:3xample0000000000000000000000000000000000000"},
    488: {"process": "sudo", "user": "adm01", "src_ip": None,
          "message": "    adm01 : TTY=pts/2 ; PWD=/home/adm01 ; USER=root ; COMMAND=/bin/bash"},
    914: {"process": "sudo", "user": "deploy", "src_ip": None,
          "message": "   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/sh -c systemctl restart example-app"},
}


def linux_events(rnd):
    events = []
    sudo_commands = ["/usr/bin/apt-get update", "/usr/bin/systemctl restart example-app",
                     "/usr/bin/journalctl -u example-app -n 200", "/usr/bin/tail -n 100 /var/log/example/app.log",
                     "/usr/sbin/service nginx reload", "/usr/bin/docker ps", "/usr/bin/vim /etc/example/app.conf"]
    for index in range(EVENTS_PER_FILE):
        roll = rnd.random()
        host = rnd.choice(_LINUX_HOSTS)
        src_ip = None
        user = None
        if roll < 0.30:
            process = "sshd"
            user = rnd.choice(_LINUX_USERS + _LINUX_ADMINS)
            from_bastion = rnd.random() < 0.15
            src_ip = BASTION_IP if from_bastion else OFFICE_NET + str(rnd.randrange(20, 240))
            port = 30000 + rnd.randrange(30000)
            kind = rnd.random()
            if kind < 0.55:
                message = "Accepted publickey for %s from %s port %d ssh2: ED25519 SHA256:%s" % (
                    user, src_ip, port, "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(43)))
            elif kind < 0.70:
                message = "Accepted password for %s from %s port %d ssh2" % (user, src_ip, port)
            elif kind < 0.85:
                message = "Failed password for %s from %s port %d ssh2" % (user, src_ip, port)
            else:
                message = "Disconnected from user %s %s port %d" % (user, src_ip, port)
        elif roll < 0.50:
            process = "sshd"
            user = rnd.choice(_LINUX_USERS + _LINUX_ADMINS)
            message = "pam_unix(sshd:session): session %s for user %s" % (
                rnd.choice(["opened", "closed"]), user)
        elif roll < 0.65:
            process = "sudo"
            user = rnd.choice(_LINUX_ADMINS)
            message = "%8s : TTY=pts/%d ; PWD=/home/%s ; USER=root ; COMMAND=%s" % (
                user, rnd.randrange(4), user, rnd.choice(sudo_commands))
        elif roll < 0.72:
            process = "sudo"
            user = rnd.choice(_LINUX_ADMINS)
            message = "pam_unix(sudo:session): session %s for user root by %s(uid=0)" % (
                rnd.choice(["opened", "closed"]), user)
        elif roll < 0.85:
            process = "CRON"
            message = "pam_unix(cron:session): session %s for user %s by (uid=0)" % (
                rnd.choice(["opened", "closed"]), rnd.choice(["root", "backup", "www-data"]))
        elif roll < 0.95:
            process = "systemd-logind"
            user = rnd.choice(_LINUX_USERS + _LINUX_ADMINS)
            message = rnd.choice(["New session %d of user %s." % (rnd.randrange(900) + 100, user),
                                  "Removed session %d." % (rnd.randrange(900) + 100),
                                  "Session %d logged out. Waiting for processes to exit." % (rnd.randrange(900) + 100)])
        else:
            process = "su"
            user = rnd.choice(_LINUX_ADMINS)
            message = "(to postgres) %s on pts/%d" % (user, rnd.randrange(4))
        event = {
            "timestamp": _clock(0, index, 86),
            "host": host,
            "process": process,
            "pid": 400 + rnd.randrange(60000),
            "message": message,
        }
        if user is not None:
            event["user"] = user
        if src_ip is not None:
            event["src_ip"] = src_ip
        planted = _LINUX_PLANTED.get(index)
        if planted is not None:
            for key, value in planted.items():
                if value is None:
                    event.pop(key, None)
                else:
                    event[key] = value
        events.append(event)
    return events


# --- webserver ----------------------------------------------------------------------------------

_BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ExampleBrowser/118.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) ExampleBrowser/118.0",
    "Mozilla/5.0 (X11; Linux x86_64) ExampleBrowser/117.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) ExampleMobile/17.0",
    "Mozilla/5.0 (Linux; Android 14) ExampleMobile/118.0",
    "ExampleBot/1.0 (+https://www.example.test/bot)",
]
_MONITOR_UA = "python-requests/2.31.0"
_PAGES = ["/", "/index.html", "/about", "/products", "/products/42", "/products/7", "/blog/2026/10/release-notes",
          "/static/css/site.css", "/static/js/app.js", "/static/img/logo.svg", "/favicon.ico", "/robots.txt",
          "/api/v1/items", "/api/v1/items/42", "/api/v1/session", "/login", "/account", "/search", "/contact",
          "/docs/getting-started", "/downloads/example-client-4.2.msi", "/health"]
_QUERIES = ["-", "-", "-", "page=2", "page=3&sort=name", "id=42", "q=release+notes", "q=example+client",
            "lang=en", "ref=newsletter", "utm_source=partner&utm_medium=email", "format=json", "limit=50&offset=100"]

_WEB_PLANTED = {
    # partner integration without a browser user agent, from the partner range
    96: {"c-ip": PARTNER_NET + "23", "cs-useragent": _MONITOR_UA, "cs-method": "GET",
         "cs-uri-stem": "/api/v1/items", "cs-uri-query": "format=json&limit=50", "sc-status": 200},
    541: {"c-ip": PARTNER_NET + "23", "cs-useragent": _MONITOR_UA, "cs-method": "POST",
          "cs-uri-stem": "/api/v1/session", "cs-uri-query": "-", "sc-status": 201},
    877: {"c-ip": PARTNER_NET + "24", "cs-useragent": _MONITOR_UA, "cs-method": "GET",
          "cs-uri-stem": "/api/v1/items/42", "cs-uri-query": "format=json", "sc-status": 200},
}


def web_events(rnd):
    events = []
    for index in range(EVENTS_PER_FILE):
        roll = rnd.random()
        if roll < 0.04:
            # internal monitoring: health checks from the office range
            client, agent, method, stem, query = (OFFICE_NET + str(rnd.randrange(2, 9)), _MONITOR_UA,
                                                  "GET", "/health", "-")
            status = 200
        else:
            client = rnd.choice([INTERNET_NET + str(rnd.randrange(1, 255)), PARTNER_NET + str(rnd.randrange(1, 255)),
                                 OFFICE_NET + str(rnd.randrange(20, 240))])
            agent = rnd.choice(_BROWSER_UAS)
            stem = rnd.choice(_PAGES)
            method = "POST" if stem in ("/login", "/api/v1/session", "/contact") and rnd.random() < 0.7 else "GET"
            query = rnd.choice(_QUERIES) if stem in ("/products", "/search", "/api/v1/items", "/blog/2026/10/release-notes") else "-"
            status_roll = rnd.random()
            if status_roll < 0.86:
                status = 200
            elif status_roll < 0.91:
                status = 304
            elif status_roll < 0.95:
                status = 404
            elif status_roll < 0.98:
                status = 302
            else:
                status = 500
        event = {
            "date": "2026-10-17",
            "time": _clock(8, index, 29)[11:19],
            "c-ip": client,
            "cs-method": method,
            "cs-uri-stem": stem,
            "cs-uri-query": query,
            "sc-status": status,
            "sc-bytes": 200 + rnd.randrange(60000),
            "cs-useragent": agent,
            "cs-host": "www.example.test",
            "cs-referer": rnd.choice(["-", "-", "https://www.example.test/", "https://search.example.test/?q=example"]),
        }
        planted = _WEB_PLANTED.get(index)
        if planted is not None:
            event.update(planted)
        events.append(event)
    return events


# --- entry -----------------------------------------------------------------------------------------

FILES = (
    ("windows-process_creation.jsonl", {"product": "windows", "category": "process_creation"}, windows_events),
    ("linux-auth.jsonl", {"product": "linux", "service": "auth"}, linux_events),
    ("webserver.jsonl", {"category": "webserver"}, web_events),
)


def generate(out_dir):
    """Write the three corpus files into ``out_dir``; returns their paths."""
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for name, logsource, maker in FILES:
        rnd = random.Random(SEED)
        events = maker(rnd)
        assert len(events) == EVENTS_PER_FILE
        path = os.path.join(out_dir, name)
        _write(path, logsource, events)
        paths.append(path)
    return paths


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="corpus", help="output directory (default: corpus/)")
    args = parser.parse_args(argv)
    for path in generate(args.out):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
