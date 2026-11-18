#!/bin/bash
# Probe only (never merged): the service as M12.1 builds it, and what its review asked to be measured.
set -u
P=/usr/local/lib/raqib-probe
echo "=================== the machine"
systemd --version | head -1
ls -ld / /usr /usr/local /usr/local/lib /etc /etc/systemd /etc/systemd/system /var/lib | awk '{print $1, $3, $4, $9}'
sudo mkdir -m 0755 $P
sudo cp -r "$PWD" $P/src
sudo rm -rf $P/src/.git
sudo chown -R root:root $P/src
sudo /usr/bin/python3 -m venv $P/venv
sudo $P/venv/bin/pip install --disable-pip-version-check -q $P/src 2>&1 | tail -1
PY="$P/venv/bin/python"
sudo useradd -m agentuser
IP=$(hostname -I | awk '{print $1}')
python3 tools/rig/model.py --port 8790 --log "$RUNNER_TEMP/model-service.log" &
sleep 2

echo "=================== A. the install, and systemd's own word on the unit"
sudo $PY -I -m raqib service install; echo "install exit $?"
echo "--- systemd-analyze verify:"; sudo systemd-analyze verify /etc/systemd/system/raqib-watch.service 2>&1 | head -12
echo "--- the manager's words on the unit's file:"
sudo journalctl -b --no-pager -o cat | grep -i "raqib-watch.service" | grep -iE "unknown|ignor|parse|invalid|not supported" | head -8
echo "(end)"
echo "--- as loaded:"
systemctl show raqib-watch -p NoNewPrivileges -p ProtectSystem -p ProtectHome -p PrivateTmp -p PrivateDevices \
  -p ProtectKernelTunables -p ProtectKernelModules -p ProtectControlGroups -p ProtectClock -p ProtectHostname \
  -p LockPersonality -p MemoryDenyWriteExecute -p RestrictRealtime -p RestrictSUIDSGID -p RestrictNamespaces \
  -p RestrictAddressFamilies -p IPAddressDeny -p IPAddressAllow -p CapabilityBoundingSet -p SystemCallArchitectures \
  -p UMask -p FragmentPath -p DropInPaths -p NRestarts | tr '\n' ' ' | fold -w 200; echo
echo "SystemCallFilter holds $(systemctl show raqib-watch -p SystemCallFilter --value | wc -w) names"
systemd-analyze security raqib-watch --no-pager 2>/dev/null | tail -1

echo "=================== B. the page, read by another user"
sleep 8
sudo ss -ltnp | grep -E "python|8765" | cut -c1-200
sudo -u agentuser curl -s -o /tmp/page.html -w "another user's read of the page: http %{http_code}, %{size_download} bytes\n" http://127.0.0.1:8765/

echo "=================== C. an agent of another user whose program and folder are in /tmp (PrivateTmp)"
sudo -u agentuser mkdir -p /tmp/agentbin /tmp/agentwork
sudo -u agentuser cp /usr/bin/python3 /tmp/agentbin/agentpy
sudo -u agentuser cp tools/rig/workload.py /tmp/agentwork/workload.py 2>/dev/null || { cp tools/rig/workload.py /tmp/wl.py; chmod 644 /tmp/wl.py; sudo -u agentuser cp /tmp/wl.py /tmp/agentwork/workload.py; }
sudo systemd-run --uid=agentuser --collect --unit=rig-agent-tmp --quiet -p WorkingDirectory=/tmp/agentwork /tmp/agentbin/agentpy /tmp/agentwork/workload.py
sleep 3
APID=$(systemctl show rig-agent-tmp -p MainPID --value); echo "the agent's pid $APID; its exe and cwd as root reads them outside the unit:"
sudo readlink /proc/$APID/exe /proc/$APID/cwd
sleep 65
systemctl show rig-agent-tmp -p Result -p ActiveState 2>/dev/null | tr '\n' ' '; echo
sudo -u agentuser curl -s -o /tmp/page2.html -w "another user's read of the page after the agent: http %{http_code}, %{size_download} bytes\n" http://127.0.0.1:8765/
echo "the page names the agent's finding $(grep -c 'NEW-AGENT' /tmp/page2.html) time(s); names /home/runner $(grep -c '/home/runner' /tmp/page2.html) time(s)"
sudo python3 - "$APID" <<'PY'
import json, sys
pid = sys.argv[1]
n = 0
for line in open("/var/lib/raqib/.raqib/host/events.jsonl", encoding="utf-8", errors="replace"):
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    n += 1
    if ev.get("kind") == "finding":
        s = json.dumps(ev, sort_keys=True)
        if pid in s:
            print("finding:", s[:1500])
print("events:", n)
try:
    inv = json.load(open("/var/lib/raqib/.raqib/host/inventory.json"))
    for g in ("candidates", "act_roots"):
        for t in inv.get(g) or ():
            if str(t.get("pid")) == pid or pid in json.dumps(t)[:400]:
                print(g, json.dumps(t, sort_keys=True)[:1200])
except Exception as exc:
    print("inventory:", type(exc).__name__, exc)
PY

echo "=================== D. the stop"
sudo systemctl stop raqib-watch; echo "stop exit $?"
systemctl show raqib-watch -p ActiveState -p SubState -p Result -p ExecMainStatus -p ExecMainCode -p NRestarts | tr '\n' ' '; echo
sudo journalctl -u raqib-watch --no-pager -o cat | tail -4 | cut -c1-220
sudo tail -n 2 /var/lib/raqib/.raqib/host/events.jsonl | cut -c1-260
sudo $PY -I -m raqib service status; echo "status exit $?"

cat > /tmp/talker.py <<'PY'
import http.client, subprocess, sys, time
host, port = sys.argv[1], int(sys.argv[2])
conn = http.client.HTTPConnection(host, port, timeout=10)   # one connection kept, a request each turn
for i in range(9):
    try:
        conn.request("GET", "/v1/models")
        conn.getresponse().read()
    except Exception as exc:
        print("talk failed", exc)
    subprocess.run(["id", "-un"], stdout=subprocess.DEVNULL)
    time.sleep(5)
PY
chmod 644 /tmp/talker.py
HARD="-p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=read-only -p PrivateTmp=yes -p PrivateDevices=yes -p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectControlGroups=yes -p ProtectClock=yes -p ProtectHostname=yes -p LockPersonality=yes -p MemoryDenyWriteExecute=yes -p RestrictRealtime=yes -p RestrictSUIDSGID=yes -p RestrictNamespaces=yes -p SystemCallFilter=@system-service -p SystemCallArchitectures=native -p UMask=0077"

echo "=================== E1. ss alone, by the families the unit may open (a kept connection of another user's)"
sudo systemd-run --uid=agentuser --collect --unit=rig-talker-ss --quiet python3 /tmp/talker.py "$IP" 8790
sleep 4
for fam in "AF_UNIX AF_NETLINK AF_INET AF_INET6" "AF_UNIX AF_NETLINK" "AF_NETLINK"; do
  sudo systemd-run --wait --pipe --quiet $HARD -p "RestrictAddressFamilies=$fam" -p IPAddressDeny=any \
    -p "CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN" /usr/bin/ss -tinp > /tmp/ss.out 2> /tmp/ss.err; code=$?
  echo "families [$fam]: ss exit $code, $(wc -l < /tmp/ss.out) lines, $(grep -c 'users:' /tmp/ss.out) with users, $(grep -c 'bytes_acked' /tmp/ss.out) with bytes_acked; the talker's: $(grep -A1 ':8790' /tmp/ss.out | grep -c 'python3')/$(grep -A1 ':8790' /tmp/ss.out | grep -c bytes_acked); stderr: $(head -c 200 /tmp/ss.err | tr '\n' ' ')"
done
echo "--- and by the capabilities it keeps (families AF_UNIX AF_NETLINK):"
for caps in "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN" "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH" "CAP_SYS_PTRACE" "CAP_DAC_READ_SEARCH" ""; do
  sudo systemd-run --wait --pipe --quiet $HARD -p "RestrictAddressFamilies=AF_UNIX AF_NETLINK" -p IPAddressDeny=any \
    -p "CapabilityBoundingSet=$caps" /usr/bin/ss -tinp > /tmp/ss.out 2> /tmp/ss.err; code=$?
  echo "caps [$caps]: ss exit $code, $(wc -l < /tmp/ss.out) lines, $(grep -c 'users:' /tmp/ss.out) with users, $(grep -c 'bytes_acked' /tmp/ss.out) with bytes_acked; the talker's line names its process: $(grep ':8790' /tmp/ss.out | grep -c 'python3'); stderr: $(head -c 200 /tmp/ss.err | tr '\n' ' ')"
done
sleep 45

echo "=================== E2. the watch itself, by the capabilities it keeps (the page still served)"
n=0
for caps in "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN" "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH" "CAP_SYS_PTRACE" "CAP_DAC_READ_SEARCH"; do
  n=$((n+1)); u=raqib-v$n
  echo "------- $u caps [$caps]"
  ( sleep 6; sudo systemd-run --uid=agentuser --collect --unit=rig-talker-$n --quiet python3 /tmp/talker.py "$IP" 8790 ) &
  sudo systemd-run --wait --quiet --unit=$u $HARD -p "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6" \
    -p IPAddressDeny=any -p IPAddressAllow=localhost -p "CapabilityBoundingSet=$caps" -p StateDirectory=$u -p StateDirectoryMode=0700 \
    -E HOME=/var/lib/$u $PY -I -m raqib watch --host --rounds 10 --every 5 --no-open --no-notify; echo "exit $?"
  sudo journalctl -u $u --no-pager -o cat | grep -E "^RESULT|BLIND|HOLES|FINDING|could not|Permission|denied|Traceback|Error" | cut -c1-240 | head -12
  echo "--- the report's trees:"
  sudo journalctl -u $u --no-pager -o cat | sed -n '/^TREES SEEN/,/^FINDINGS/p' | grep -v 'source:' | cut -c1-240 | head -10
  wait
  sleep 3
done
