#!/bin/bash
# Probe only (never merged): the ways an agent's shell tool commonly runs a network tool, each harmless (a fetch of
# example.com thrown away), for tools/rig/exec_probe.py to read from an strace of this script.
u=https://example.com/
bash -c "curl -s -o /dev/null --max-time 5 $u"
sh -c "sleep 6; wget -q -O /dev/null --tries=1 --timeout=5 $u"
bash -lc "git --version > /dev/null"
python3 -c "import subprocess; subprocess.run(['curl', '-s', '-o', '/dev/null', '--max-time', '5', '$u'])"
timeout 5 curl -s -o /dev/null $u
env A=1 curl -s -o /dev/null --max-time 5 $u
echo $u | xargs curl -s -o /dev/null --max-time 5
sh -c "sleep 7; sh -c 'sleep 3; curl -s -o /dev/null --max-time 5 $u' & sleep 1"
command -v nc > /dev/null && nc -z -w 2 example.com 80
command -v busybox > /dev/null && busybox wget -q -O /dev/null $u
sleep 5
true
