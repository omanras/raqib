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
import subprocess, sys, time, urllib.request
for i in range(10):
    try:
        urllib.request.urlopen(sys.argv[1], timeout=5).read()
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
ExecStart=/opt/raqib/bin/python -I -m raqib watch --host --rounds 11 --every 5 --no-open --no-notify
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
for u in raqib-plain raqib-hard; do
  echo "=================== $u"
  sudo systemctl start $u
  sleep 6
  sudo -u agentuser python3 /tmp/talker.py "http://$IP:8790/v1/models" &
  T=$!
  wait $T
  sleep 12
  systemctl is-active $u; systemctl show $u -p ExecMainStatus -p Result -p User | tr '\n' ' '; echo
  sudo journalctl -u $u --no-pager -o cat | grep -E "FINDING|TREES SEEN|RESULT|BLIND|HOLES|could not|Permission|denied|Traceback|Error|error" | cut -c1-260 | head -30
  echo "--- trees of agentuser's pids in the report:"
  sudo journalctl -u $u --no-pager -o cat | grep -E "python3|talker" | cut -c1-220 | head -8
  echo "--- files:"; sudo find /var/lib/$u -maxdepth 3 | head -12; sudo stat -c '%U %a %n' /var/lib/$u
  sudo head -c 600 /var/lib/$u/.raqib/host/events.jsonl 2>/dev/null | cut -c1-400; echo
  echo "--- security:"; systemd-analyze security $u --no-pager 2>/dev/null | tail -1
done
echo "=================== as the runner's own user, for comparison (sees agentuser?)"
( timeout 70 /opt/raqib/bin/python -I -m raqib watch --host --rounds 11 --every 5 --no-open --no-notify > "$RUNNER_TEMP/user-watch.out" 2>&1 & )
sleep 6
sudo -u agentuser python3 /tmp/talker.py "http://$IP:8790/v1/models"
sleep 12
grep -E "FINDING|TREES SEEN|RESULT|BLIND" "$RUNNER_TEMP/user-watch.out" | cut -c1-260 | head -12
