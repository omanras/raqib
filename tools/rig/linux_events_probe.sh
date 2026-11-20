#!/bin/bash
# Probe only (never merged): Linux's own word on what happens between two samples, and what else is there to ask.
set -u
echo "=================== the ground"
uname -r; grep -E "^(NAME|VERSION)=" /etc/os-release
echo "auditctl: $(command -v auditctl || echo none); auditd: $(systemctl is-active auditd 2>/dev/null); bpftool: $(command -v bpftool || echo none); bpftrace: $(command -v bpftrace || echo none)"
echo "BTF: $(ls /sys/kernel/btf/vmlinux 2>/dev/null || echo none); unprivileged_bpf_disabled: $(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)"
echo "=================== as a plain user (expected: refused)"
python3 tools/rig/linux_events_probe.py --listen 3
echo "=================== as root: the acts and what was heard"
sudo python3 tools/rig/linux_events_probe.py
HARD="-p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=read-only -p PrivateTmp=yes -p PrivateDevices=yes -p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectControlGroups=yes -p ProtectClock=yes -p ProtectHostname=yes -p LockPersonality=yes -p MemoryDenyWriteExecute=yes -p RestrictRealtime=yes -p RestrictSUIDSGID=yes -p RestrictNamespaces=yes -p SystemCallFilter=@system-service -p SystemCallArchitectures=native -p UMask=0077 -p IPAddressDeny=any"
sudo cp tools/rig/linux_events_probe.py /usr/local/lib/raqib-events-probe.py
echo "=================== under the unit's limits, with the unit's two capabilities (expected: refused)"
sudo systemd-run --wait --pipe --quiet $HARD -p "RestrictAddressFamilies=AF_UNIX AF_NETLINK" -p "CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH" /usr/bin/python3 /usr/local/lib/raqib-events-probe.py --listen 4
echo "=================== under the unit's limits, with CAP_NET_ADMIN beside them"
sudo systemd-run --wait --pipe --quiet $HARD -p "RestrictAddressFamilies=AF_UNIX AF_NETLINK" -p "CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN" /usr/bin/python3 /usr/local/lib/raqib-events-probe.py --listen 4
