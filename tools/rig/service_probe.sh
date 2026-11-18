#!/bin/bash
# Probe only (never merged): the watch as a unit of the system's, with another user's agent-like process.
set -u
sudo python3 -m venv /opt/raqib
sudo /opt/raqib/bin/pip install --disable-pip-version-check -q . 2>&1 | tail -1
ls -ld /opt/raqib /opt/raqib/bin/python /opt/raqib/lib/python3*/site-packages/raqib | cut -c1-120
IP=$(hostname -I | awk '{print $1}')
python3 tools/rig/model.py --port 8790 --log "$RUNNER_TEMP/model-service.log" &
sleep 2
sudo useradd -m agentuser
cat > /tmp/talker.py <<'PY'
import http.client, subprocess, sys, time
host, port = sys.argv[1], int(sys.argv[2])
conn = http.client.HTTPConnection(host, port, timeout=10)   # one connection kept, a request each turn
for i in range(10):
    try:
        conn.request("GET", "/v1/models")
        conn.getresponse().read()
    except Exception as exc:
        print("talk failed", exc)
    subprocess.run(["id", "-un"], stdout=subprocess.DEVNULL)
    time.sleep(5)
PY
unit() {  # name, hardening lines
cat <<UNIT | sudo tee /etc/systemd/system/$1.service >/dev/null
[Unit]
Description=Raqib probe $1
[Service]
Type=simple
Environment=HOME=/var/lib/$1
StateDirectory=$1
StateDirectoryMode=0700
ExecStart=/opt/raqib/bin/python -I -m raqib watch --host --rounds 15 --every 5 --no-open --no-notify
$2
UNIT
}
unit raqib-plain ""
unit raqib-hard "NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077"
sudo systemctl daemon-reload
for u in raqib-hard; do
  echo "=================== $u"
  sudo systemctl start $u
  sleep 6
  cp tools/rig/workload.py /tmp/workload.py; chmod 644 /tmp/workload.py
  sudo systemd-run --uid=agentuser --collect --unit=rig-agent-$u --quiet python3 /tmp/workload.py
  sleep 62
  echo "--- the other user's process:"; systemctl show rig-agent-$u -p MainPID -p User -p Result 2>/dev/null | tr '\n' ' '; echo
  systemctl is-active $u; systemctl show $u -p ExecMainStatus -p Result -p User | tr '\n' ' '; echo
  sudo journalctl -u $u --no-pager -o cat | grep -E "FINDING|TREES SEEN|RESULT|BLIND|HOLES|could not|Permission|denied|Traceback|Error|error" | cut -c1-260 | head -30
  echo "--- the report's trees:"
  sudo journalctl -u $u --no-pager -o cat | sed -n '/^TREES SEEN/,/^FINDINGS/p' | grep -v 'source:' | cut -c1-260 | head -14
  echo "--- uid of the talker's tree in the inventory:"
  sudo python3 -c "
import json,sys
inv=json.load(open('/var/lib/$u/.raqib/host/inventory.json'))
for g in ('candidates','act_roots'):
    for t in inv.get(g) or ():
        print(g, t.get('pid'), t.get('image'), {k: t.get(k) for k in ('user','uid','owner') if k in t}, [x.get('remote') for x in t.get('talks') or ()][:3])
print('conn_bytes hole:', (inv.get('conn_bytes') or {}).get('hole'))
"
  echo "--- files:"; sudo find /var/lib/$u -maxdepth 3 | head -12; sudo stat -c '%U %a %n' /var/lib/$u
  sudo head -c 600 /var/lib/$u/.raqib/host/events.jsonl 2>/dev/null | cut -c1-400; echo
  echo "--- security:"; systemd-analyze security $u --no-pager 2>/dev/null | tail -1
done
echo "=================== as the runner's own user, for comparison (does it see agentuser's tree?)"
( timeout 90 /opt/raqib/bin/python -I -m raqib watch --host --rounds 15 --every 5 --no-open --no-notify > "$RUNNER_TEMP/user-watch.out" 2>&1 & )
sleep 6
sudo systemd-run --uid=agentuser --collect --unit=rig-agent-user --quiet python3 /tmp/workload.py
sleep 80
sed -n '/^TREES SEEN/,/^FINDINGS/p' "$RUNNER_TEMP/user-watch.out" | grep -v "source:" | cut -c1-240 | head -10
grep -E "FINDING|RESULT|BLIND" "$RUNNER_TEMP/user-watch.out" | cut -c1-260 | head -12
