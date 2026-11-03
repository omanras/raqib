"""Generate the SYNTHETIC M5.0b discover fixtures (HANDOFF M5.0b, E4 and E5).

Run from the repository root: python3 tests/fixtures/discover/synthetic.py

Nothing here was captured from a machine. Every file says so in its first
line (run.json, which has no comments, in its "note"), with the redaction
note of ADR-0004 Amendment B (B-9): no line of a real export is copied; the
user is `user`, the host `host`; addresses are loopback, unspecified, or in
the documentation ranges of RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24); host names are example names, or a catalog host.

- kimi/one-sample, kimi/two-samples: the shape of the commander's Kimi export
  (docs/review/2026-11-02-field-note-kimi-discover.md; the export itself
  stays off the tree): explorer talks; cmd -> kimi.exe under .kimi-code\\bin
  -> bash -> bash -> bash -> ping; kimi.exe owns no connection in sample 1,
  where a TIME-WAIT row with owner 0 and a DNS cache row point at the
  catalog's api.moonshot.ai; in sample 2 kimi.exe holds an ESTABLISHED one.
  The README loop with N = 1 and with N = 2: sample 1 is the same file in both.
- benign/windows-desktop: explorer, OneDrive, VS Code (user install under
  AppData\\Local\\Programs, with its extension host running git and an idle
  integrated terminal) and Edge; two samples of the README loop.
- benign/linux-desktop: GNOME, a terminal running vim, VS Code from its
  package (/usr/share/code) with a terminal running make -> cc, Firefox,
  JetBrains Toolbox under ~/.local; two snapshots of `raqib discover
  --window 1 --save` as a user who is not root.
"""
import ipaddress
import json
import os

OUT = os.path.join("tests", "fixtures", "discover")
REDACTION = ("Redaction (ADR-0004 B-9): no line of a real export; user `user`, host `host`; addresses loopback,"
             " unspecified or RFC 5737 documentation ranges only")
WIN_PROCESS = ("ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine", "CreationDate")
WIN_TCP = ("LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "State", "OwningProcess", "CreationTime")
WIN_DNS = ("Entry", "RecordName", "RecordType", "Status", "Section", "TimeToLive", "DataLength", "Data")
SHAPE = {"win-process": "Get-CimInstance Win32_Process", "win-tcp": "Get-NetTCPConnection",
         "win-dns": "Get-DnsClientCache"}


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="ascii", newline="\n") as f:
        f.write(text)


def csv_line(values):
    return ",".join("" if v is None else '"%s"' % str(v).replace('"', '""') for v in values)


def win_csv(kind, scenario, header, rows):
    head = ("# M5.0b fixture SYNTHETIC (not captured from a machine) - %s; in the shape of: %s | ConvertTo-Csv"
            " -NoTypeInformation, columns %s. %s" % (scenario, SHAPE[kind], "; ".join(header), REDACTION))
    return "\n".join([head, csv_line(header)] + [csv_line(r) for r in rows]) + "\n"


def loop_run_json(scenario, samples):
    """run.json as the README loop writes it (PowerShell 5.1 ConvertTo-Json of an [ordered] table), with a note."""
    keys = [("note", "M5.0b fixture SYNTHETIC (not captured from a machine) - %s. %s" % (scenario, REDACTION)),
            ("raqib", "discover-run"), ("version", 1), ("export", "windows"), ("samples", samples),
            ("seconds_apart", 10)]
    return "{\n" + ",\n".join("    %s:  %s" % (json.dumps(k), json.dumps(v)) for k, v in keys) + "\n}\n"


def footprints(scenario, shape, paths):
    return "\n".join(["# M5.0b fixture SYNTHETIC (not captured from a machine) - %s; in the shape of: %s. %s"
                      % (scenario, shape, REDACTION)] + paths) + "\n"


# --- Windows: the Kimi shape (E5) ----------------------------------------------------

KIMI = "the shape of the Kimi field test (docs/review/2026-11-02-field-note-kimi-discover.md), invented lines"
GIT_BASH = "C:\\Program Files\\Git\\bin\\bash.exe"
MSYS_BASH = "C:\\Program Files\\Git\\usr\\bin\\bash.exe"
PIPE = 'ping -n 90 127.0.0.1 | tee -a work/ping.log'
KIMI_PROCS = [
    ("0", "0", "System Idle Process", None, None, "11/2/2026 8:01:02 AM"),
    ("4", "0", "System", None, None, "11/2/2026 8:01:02 AM"),
    ("700", "604", "wininit.exe", "C:\\Windows\\System32\\wininit.exe", "wininit.exe", "11/2/2026 8:01:09 AM"),
    ("760", "700", "services.exe", "C:\\Windows\\System32\\services.exe", "C:\\Windows\\system32\\services.exe",
     "11/2/2026 8:01:09 AM"),
    ("912", "760", "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k RPCSS -p",
     "11/2/2026 8:01:10 AM"),
    ("1300", "760", "svchost.exe", "C:\\Windows\\System32\\svchost.exe",
     "C:\\Windows\\system32\\svchost.exe -k NetworkService -p -s Dnscache", "11/2/2026 8:01:11 AM"),
    ("6636", "6600", "explorer.exe", "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", "11/2/2026 8:02:30 AM"),
    ("13236", "6636", "cmd.exe", "C:\\Windows\\System32\\cmd.exe", '"C:\\Windows\\system32\\cmd.exe" ',
     "11/2/2026 10:20:41 AM"),
    ("13244", "13236", "conhost.exe", "C:\\Windows\\System32\\conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0x4",
     "11/2/2026 10:20:41 AM"),
    ("10728", "13236", "kimi.exe", "C:\\Users\\user\\.kimi-code\\bin\\kimi.exe", "kimi  -r", "11/2/2026 10:21:05 AM"),
    ("7768", "10728", "bash.exe", GIT_BASH, '"%s" -c "%s"' % (GIT_BASH, PIPE), "11/2/2026 10:29:11 AM"),
    ("10476", "7768", "bash.exe", MSYS_BASH, '%s -c "%s"' % (MSYS_BASH, PIPE), "11/2/2026 10:29:11 AM"),
    ("5796", "10476", "bash.exe", MSYS_BASH, '%s -c "%s"' % (MSYS_BASH, PIPE), "11/2/2026 10:29:11 AM"),
    ("8496", "5796", "PING.EXE", "C:\\Windows\\System32\\PING.EXE", "ping  -n 90 127.0.0.1", "11/2/2026 10:29:11 AM"),
    ("8500", "10476", "tee.exe", "C:\\Program Files\\Git\\usr\\bin\\tee.exe", "tee -a work/ping.log",
     "11/2/2026 10:29:11 AM"),
]
LISTEN = [("0.0.0.0", "135", "0.0.0.0", "0", "Listen", "912", "11/2/2026 8:01:10 AM"),
          ("0.0.0.0", "445", "0.0.0.0", "0", "Listen", "4", "11/2/2026 8:01:12 AM"),
          ("::", "135", "::", "0", "Listen", "912", "11/2/2026 8:01:10 AM")]
KIMI_TCP_1 = LISTEN + [
    ("192.0.2.10", "49812", "198.51.100.23", "443", "Established", "6636", "11/2/2026 10:12:40 AM"),
    ("192.0.2.10", "50420", "203.0.113.40", "443", "TimeWait", "0", None),
    ("192.0.2.10", "50101", "198.51.100.99", "443", "TimeWait", "0", None),
]
KIMI_TCP_2 = LISTEN + [
    ("192.0.2.10", "49812", "198.51.100.23", "443", "Established", "6636", "11/2/2026 10:12:40 AM"),
    ("192.0.2.10", "50431", "203.0.113.40", "443", "Established", "10728", "11/2/2026 10:29:24 AM"),
    ("192.0.2.10", "50420", "203.0.113.40", "443", "TimeWait", "0", None),
]


def kimi_dns(ttl):
    return [("api.moonshot.ai", "api.moonshot.ai", "A", "0", "1", str(ttl), "4", "203.0.113.40"),
            ("update.example.com", "update.example.com", "CNAME", "0", "1", "1800", "8", "edge.example.net"),
            ("update.example.com", "edge.example.net", "A", "0", "1", "1800", "4", "198.51.100.23"),
            ("www.example.org", "www.example.org", "A", "0", "1", "3000", "4", "198.51.100.99")]


KIMI_HOME = ["C:\\Users\\user\\.kimi", "C:\\Users\\user\\.kimi-code", "C:\\Users\\user\\AppData",
             "C:\\Users\\user\\Desktop", "C:\\Users\\user\\Documents", "C:\\Users\\user\\NTUSER.DAT"]
HOME_SHAPE = ("Get-ChildItem -Force C:\\Users\\*\\, C:\\Users\\*\\AppData\\Roaming\\Claude\\ | ForEach-Object"
              " FullName (every entry of every home; discover keeps the catalog matches)")


def kimi(directory, samples):
    scenario = "%s; host `host`, sample %%d of the README loop (10 s apart)" % KIMI
    files = {"run.json": loop_run_json("%s; host `host`, the README loop with N = %d" % (KIMI, samples), samples),
             "footprints.txt": footprints("%s; host `host`" % KIMI, HOME_SHAPE, KIMI_HOME)}
    for k in range(1, samples + 1):
        tcp, ttl = (KIMI_TCP_1, 562) if k == 1 else (KIMI_TCP_2, 552)
        files["win-process-%d.csv" % k] = win_csv("win-process", scenario % k, WIN_PROCESS, KIMI_PROCS)
        files["win-tcp-%d.csv" % k] = win_csv("win-tcp", scenario % k, WIN_TCP, tcp)
        files["win-dns-%d.csv" % k] = win_csv("win-dns", scenario % k, WIN_DNS, kimi_dns(ttl))
    return directory, files


# --- Windows: a benign desktop (E4) ----------------------------------------------------

DESK = "a benign Windows desktop: explorer, OneDrive, VS Code (user install), Edge"
CODE = "C:\\Users\\user\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"
EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
NODE_SVC = "--type=utility --utility-sub-type=node.mojom.NodeService --lang=en-US --service-sandbox-type=none"


def code(extra):
    return '"%s" %s' % (CODE, extra)


def edge(extra):
    return '"%s" %s' % (EDGE, extra)


DESK_PROCS = [
    ("0", "0", "System Idle Process", None, None, "11/3/2026 7:40:02 AM"),
    ("4", "0", "System", None, None, "11/3/2026 7:40:02 AM"),
    ("700", "604", "wininit.exe", "C:\\Windows\\System32\\wininit.exe", "wininit.exe", "11/3/2026 7:40:09 AM"),
    ("760", "700", "services.exe", "C:\\Windows\\System32\\services.exe", "C:\\Windows\\system32\\services.exe",
     "11/3/2026 7:40:09 AM"),
    ("912", "760", "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k RPCSS -p",
     "11/3/2026 7:40:10 AM"),
    ("1300", "760", "svchost.exe", "C:\\Windows\\System32\\svchost.exe",
     "C:\\Windows\\system32\\svchost.exe -k NetworkService -p -s Dnscache", "11/3/2026 7:40:11 AM"),
    ("5100", "5060", "explorer.exe", "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", "11/3/2026 7:41:30 AM"),
    ("5320", "5100", "OneDrive.exe", "C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
     '"C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background', "11/3/2026 7:41:44 AM"),
    ("5400", "5100", "SecurityHealthSystray.exe", "C:\\Windows\\System32\\SecurityHealthSystray.exe",
     '"C:\\Windows\\System32\\SecurityHealthSystray.exe" ', "11/3/2026 7:41:45 AM"),
    ("6000", "5100", "Code.exe", CODE, code(""), "11/3/2026 8:02:10 AM"),
    ("6010", "6000", "Code.exe", CODE, code("--type=gpu-process --gpu-preferences=UAAAAAAAAADgAAAEAAAAAAAAAAAAAAAAAAB"),
     "11/3/2026 8:02:10 AM"),
    ("6020", "6000", "Code.exe", CODE, code("--type=utility --utility-sub-type=network.mojom.NetworkService"
                                            " --lang=en-US --service-sandbox-type=none"), "11/3/2026 8:02:10 AM"),
    ("6030", "6000", "Code.exe", CODE, code("--type=renderer --lang=en-US --app-path=\"C:\\Users\\user\\AppData\\"
                                            "Local\\Programs\\Microsoft VS Code\\resources\\app\""),
     "11/3/2026 8:02:11 AM"),
    ("6040", "6000", "Code.exe", CODE, code(NODE_SVC + " --vscode-utility-kind=shared-process"),
     "11/3/2026 8:02:12 AM"),
    ("6050", "6000", "Code.exe", CODE, code(NODE_SVC + " --vscode-utility-kind=extensionHost"),
     "11/3/2026 8:02:13 AM"),
    ("6055", "6050", "git.exe", "C:\\Program Files\\Git\\cmd\\git.exe",
     '"C:\\Program Files\\Git\\cmd\\git.exe" status -z -uall', "11/3/2026 9:10:41 AM"),
    ("6056", "6055", "git.exe", "C:\\Program Files\\Git\\mingw64\\bin\\git.exe", "git.exe status -z -uall",
     "11/3/2026 9:10:41 AM"),
    ("6060", "6000", "Code.exe", CODE, code(NODE_SVC + " --vscode-utility-kind=ptyHost"), "11/3/2026 8:02:13 AM"),
    ("6065", "6060", "OpenConsole.exe", "C:\\Users\\user\\AppData\\Local\\Programs\\Microsoft VS Code\\resources\\app"
     "\\node_modules\\node-pty\\build\\Release\\conpty\\OpenConsole.exe",
     '"C:\\Users\\user\\AppData\\Local\\Programs\\Microsoft VS Code\\resources\\app\\node_modules\\node-pty\\build'
     '\\Release\\conpty\\OpenConsole.exe" --headless --inheritcursor --width 120 --height 30', "11/3/2026 8:05:30 AM"),
    ("6070", "6060", "powershell.exe", PS, '"%s" ' % PS, "11/3/2026 8:05:30 AM"),
    ("7000", "5100", "msedge.exe", EDGE, edge("--profile-directory=Default"), "11/3/2026 7:55:02 AM"),
    ("7010", "7000", "msedge.exe", EDGE, edge("--type=crashpad-handler --database=C:\\Users\\user\\AppData\\Local\\"
                                              "Microsoft\\Edge\\User Data\\Crashpad"), "11/3/2026 7:55:02 AM"),
    ("7020", "7000", "msedge.exe", EDGE, edge("--type=gpu-process --gpu-preferences=UAAAAAAAAADgAAAEAAAAAAAAAAAAAAAA"),
     "11/3/2026 7:55:03 AM"),
    ("7030", "7000", "msedge.exe", EDGE, edge("--type=utility --utility-sub-type=network.mojom.NetworkService"
                                              " --lang=en-US --service-sandbox-type=none"), "11/3/2026 7:55:03 AM"),
    ("7040", "7000", "msedge.exe", EDGE, edge("--type=renderer --lang=en-US --renderer-client-id=7"),
     "11/3/2026 7:55:04 AM"),
    ("7050", "7000", "msedge.exe", EDGE, edge("--type=renderer --lang=en-US --renderer-client-id=9"),
     "11/3/2026 8:40:15 AM"),
]
DESK_PROCS_2 = DESK_PROCS + [
    ("7060", "7000", "msedge.exe", EDGE, edge("--type=renderer --lang=en-US --renderer-client-id=12"),
     "11/3/2026 9:10:50 AM")]
DESK_TCP_1 = LISTEN + [
    ("192.0.2.30", "50001", "198.51.100.23", "443", "Established", "5100", "11/3/2026 7:41:40 AM"),
    ("192.0.2.30", "50010", "198.51.100.77", "443", "Established", "5320", "11/3/2026 7:41:50 AM"),
    ("192.0.2.30", "50020", "198.51.100.50", "443", "Established", "6020", "11/3/2026 8:02:20 AM"),
    ("192.0.2.30", "50021", "198.51.100.51", "443", "Established", "6050", "11/3/2026 8:02:25 AM"),
    ("192.0.2.30", "50030", "198.51.100.80", "443", "Established", "7030", "11/3/2026 9:01:02 AM"),
    ("192.0.2.30", "50031", "198.51.100.81", "443", "Established", "7030", "11/3/2026 9:10:30 AM"),
    ("192.0.2.30", "49990", "198.51.100.80", "443", "TimeWait", "0", None),
]
DESK_TCP_2 = [r for r in DESK_TCP_1 if r[1] != "50031"] + [
    ("192.0.2.30", "50031", "198.51.100.81", "443", "TimeWait", "0", None)]


def desk_dns(drop):
    rows = [("update.example.com", "update.example.com", "A", "0", "1", "1700", "4", "198.51.100.23"),
            ("sync.example.net", "sync.example.net", "A", "0", "1", "240", "4", "198.51.100.77"),
            ("marketplace.example.com", "marketplace.example.com", "A", "0", "1", "50", "4", "198.51.100.50"),
            ("telemetry.example.com", "telemetry.example.com", "A", "0", "1", "3200", "4", "198.51.100.51"),
            ("www.example.org", "www.example.org", "A", "0", "1", "280", "4", "198.51.100.80"),
            ("cdn.example.org", "cdn.example.org", "A", "0", "1", "90", "4", "198.51.100.81")]
    return [r for r in rows if r[0] not in drop]


DESK_HOME = ["C:\\Users\\user\\.vscode", "C:\\Users\\user\\AppData", "C:\\Users\\user\\Desktop",
             "C:\\Users\\user\\Documents", "C:\\Users\\user\\OneDrive", "C:\\Users\\user\\NTUSER.DAT"]


def windows_desktop(directory):
    files = {"run.json": loop_run_json("%s; host `host`, the README loop with N = 2" % DESK, 2),
             "footprints.txt": footprints("%s; host `host`" % DESK, HOME_SHAPE, DESK_HOME)}
    for k, procs, tcp, drop in ((1, DESK_PROCS, DESK_TCP_1, ()), (2, DESK_PROCS_2, DESK_TCP_2, ("marketplace.example.com",))):
        scenario = "%s; host `host`, sample %d of 2 of the README loop" % (DESK, k)
        files["win-process-%d.csv" % k] = win_csv("win-process", scenario, WIN_PROCESS, procs)
        files["win-tcp-%d.csv" % k] = win_csv("win-tcp", scenario, WIN_TCP, tcp)
        files["win-dns-%d.csv" % k] = win_csv("win-dns", scenario, WIN_DNS, desk_dns(drop))
    return directory, files


# --- Linux: a benign desktop (E4) -----------------------------------------------------

LINUX = "a benign Linux desktop: GNOME, a terminal, VS Code from its package with a terminal running make, Firefox"
T1, T2 = "2026-11-03T09:00:00.000Z", "2026-11-03T09:00:01.000Z"
ENV = ["DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "HOME", "LANG", "PATH", "SHELL", "USER", "XDG_RUNTIME_DIR"]
CODE_BIN = "/usr/share/code/code"
FIREFOX = "/usr/lib/firefox/firefox"
TOOLBOX = "/home/user/.local/share/JetBrains/Toolbox/bin/jetbrains-toolbox"
NOT_OURS = {"cwd": None, "env_keys": None, "sockets": None, "unread": ["cwd", "environ", "fd"]}


def proc(pid, ppid, name, argv, cwd="/home/user", sockets=(), env=ENV, hidden=False):
    rec = {"pid": pid, "ppid": ppid, "name": name, "argv": argv, "cwd": cwd, "env_keys": sorted(env),
           "sockets": sorted(sockets), "unread": []}
    if hidden:
        rec.update(NOT_OURS)
    return rec


LINUX_PROCS = [
    proc(1, 0, "systemd", ["/sbin/init", "splash"], hidden=True),
    proc(610, 1, "systemd-resolve", ["/usr/lib/systemd/systemd-resolved"], hidden=True),
    proc(980, 1, "systemd", ["/usr/lib/systemd/systemd", "--user"]),
    proc(1210, 980, "gnome-shell", ["/usr/bin/gnome-shell"]),
    proc(1500, 980, "gnome-terminal-", ["/usr/libexec/gnome-terminal-server"]),
    proc(1510, 1500, "bash", ["bash"], cwd="/home/user/notes"),
    proc(1520, 1510, "vim", ["vim", "todo.md"], cwd="/home/user/notes"),
    proc(1530, 1500, "bash", ["bash"], cwd="/home/user/src/raqib"),
    proc(1540, 1530, "python3", ["python3", "-m", "raqib", "discover", "--window", "1", "--save",
                                 "/home/user/runs/desktop"], cwd="/home/user/src/raqib"),
    proc(1700, 980, "jetbrains-toolb", [TOOLBOX, "--minimize"], sockets=[43001]),
    proc(2000, 1210, "code", [CODE_BIN, "--unity-launch"]),
    proc(2010, 2000, "code", [CODE_BIN, "--type=zygote", "--no-zygote-sandbox"]),
    proc(2020, 2000, "code", [CODE_BIN, "--type=utility", "--utility-sub-type=network.mojom.NetworkService",
                              "--lang=en-US", "--service-sandbox-type=none"], sockets=[41001]),
    proc(2030, 2010, "code", [CODE_BIN, "--type=renderer", "--lang=en-US"]),
    proc(2040, 2000, "code", [CODE_BIN, "--type=utility", "--utility-sub-type=node.mojom.NodeService",
                              "--lang=en-US", "--service-sandbox-type=none"], sockets=[41002]),
    proc(2045, 2040, "git", ["/usr/bin/git", "status", "-z", "-uall"], cwd="/home/user/src/app"),
    proc(2050, 2000, "code", [CODE_BIN, "--type=utility", "--utility-sub-type=node.mojom.NodeService",
                              "--lang=en-US", "--service-sandbox-type=none"]),
    proc(2060, 2050, "bash", ["/usr/bin/bash"], cwd="/home/user/src/app"),
    proc(2070, 2060, "make", ["make", "test"], cwd="/home/user/src/app"),
    proc(2080, 2070, "cc", ["cc", "-c", "-o", "build/util.o", "src/util.c"], cwd="/home/user/src/app"),
    proc(3000, 1210, "firefox", [FIREFOX], sockets=[42001, 42002]),
    proc(3010, 3000, "Isolated Web Co", [FIREFOX, "-contentproc", "-childID", "1", "-isForBrowser", "tab"]),
    proc(3020, 3000, "Web Content", [FIREFOX, "-contentproc", "-childID", "2", "-isForBrowser", "tab"]),
    proc(3030, 3000, "RDD Process", [FIREFOX, "-contentproc", "-parentBuildID", "20261030", "rdd"]),
]


def linux_procs_2():
    out = []
    for p in LINUX_PROCS:
        if p["pid"] == 2080:   # cc ended; the next one compiles another file
            out.append(proc(2081, 2070, "cc", ["cc", "-c", "-o", "build/main.o", "src/main.c"], cwd="/home/user/src/app"))
        elif p["pid"] == 3000:
            out.append(dict(p, sockets=[42001]))
        else:
            out.append(p)
    return out


def hexaddr(ip, port):
    raw = ipaddress.ip_address(ip).packed
    return "%s:%04X" % ("".join(raw[i:i + 4][::-1].hex().upper() for i in range(0, len(raw), 4)), port)


NET_HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"


def net_rows(rows):
    out = [NET_HEAD]
    for n, (local, remote, state, uid, inode) in enumerate(rows):
        out.append("%4d: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 20 4 30"
                   " 10 -1" % (n, hexaddr(*local), hexaddr(*remote), state, uid, inode))
    return out


LAN = "192.0.2.20"
NET_1 = [(("127.0.0.53", 53), ("0.0.0.0", 0), "0A", 991, 30001),
         ((LAN, 51000), ("198.51.100.50", 443), "01", 1000, 41001),
         ((LAN, 51002), ("198.51.100.51", 443), "01", 1000, 41002),
         ((LAN, 51010), ("198.51.100.90", 443), "01", 1000, 42001),
         ((LAN, 51012), ("198.51.100.91", 443), "01", 1000, 42002),
         ((LAN, 51020), ("198.51.100.60", 443), "01", 1000, 43001)]
NET_2 = [r if r[4] != 42002 else ((LAN, 51012), ("198.51.100.91", 443), "06", 0, 0) for r in NET_1]


def linux_desktop(directory):
    head = "# M5.0b fixture SYNTHETIC (not captured from a machine) - %s; host `host`; %s. %s"
    proc_lines = [head % (LINUX, "in the shape of snapshot_proc() as `raqib discover --window 1 --save` writes it,"
                          " as user `user` (uid 1000, not root: root's processes show unread cwd, environ and fd)",
                          REDACTION),
                  "# environ: variable NAMES only; values are never read into this text."]
    net_lines = [head % (LINUX, "/proc/net/tcp and /proc/net/tcp6 as the kernel prints them, as read_proc_net()"
                         " writes them", REDACTION)]
    for at, procs, net in ((T1, LINUX_PROCS, NET_1), (T2, linux_procs_2(), NET_2)):
        meta = {"snapshot": at, "self": 1540, "processes": len(procs), "kernel_threads": 143, "kernel_parent": 2,
                "gone_while_read": 0, "unreadable": 0}
        proc_lines.append(json.dumps(meta, sort_keys=True))
        proc_lines += [json.dumps(dict(p, at=at), sort_keys=True) for p in procs]
        net_lines += ["# at %s (/proc/net/tcp)" % at] + net_rows(net) + ["# at %s (/proc/net/tcp6)" % at, NET_HEAD]
    sources = {"proc": {"error": None, "file": "proc.txt", "label": "live /proc"},
               "proc-net": {"error": None, "file": "proc-net.txt", "label": "live /proc/net/tcp, /proc/net/tcp6"},
               "footprints": {"error": None, "file": "footprints.txt", "label": "live: homes /home/user"}}
    run = {"note": "M5.0b fixture SYNTHETIC (not captured from a machine) - %s; host `host`; in the shape of the run.json"
                   " that --save writes. %s" % (LINUX, REDACTION),
           "raqib": "discover-run", "version": 1, "sources": sources, "holes": [], "samples": 2,
           "connections_from": ["live /proc/net/tcp, /proc/net/tcp6"]}
    files = {"proc.txt": "\n".join(proc_lines) + "\n", "proc-net.txt": "\n".join(net_lines) + "\n",
             "footprints.txt": "\n".join([head % (LINUX, "the footprint listing scan_footprints() writes", REDACTION),
                                          "# raqib discover: footprint listing (paths only; nothing opened)",
                                          "# home /home/user: 31 entries"]) + "\n",
             "run.json": json.dumps(run, indent=2, sort_keys=True) + "\n"}
    return directory, files


def main():
    made = [kimi(os.path.join(OUT, "kimi", "one-sample"), 1), kimi(os.path.join(OUT, "kimi", "two-samples"), 2),
            windows_desktop(os.path.join(OUT, "benign", "windows-desktop")),
            linux_desktop(os.path.join(OUT, "benign", "linux-desktop"))]
    for directory, files in made:
        for name, text in sorted(files.items()):
            write(os.path.join(directory, name), text)
    return made


if __name__ == "__main__":
    main()
