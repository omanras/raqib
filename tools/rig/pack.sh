#!/bin/sh
# The rig's packer (ADR-0007 Amendment CG-3, M17.2a): the Raqib installed in a Python, packed into one folder with
# its own runtime by PyInstaller 6.11.1 (a tool of the rig's job, installed by the job, never a dependency of
# Raqib), with no window toolkit. It prints the packed program's path on its output, and nothing else there.
#
#     tools/rig/pack.sh WORKDIR
#
# PYTHON: the interpreter whose Raqib and PyInstaller are packed and run (default python3). WORKDIR: a folder of
# the run's own (made where it is not there); the packed program is WORKDIR/dist/raqib/raqib. The packer runs in
# WORKDIR, so a checkout's own raqib folder is never packed in place of the installed one. Exit 2 where the
# PyInstaller found is not the pinned one, 1 where no packed program was made.
set -eu

PINNED=6.11.1
NAME=raqib            # tools/rig/check.py's PACKED_NAME: the packed program's name, so its image

work=${1:?usage: tools/rig/pack.sh WORKDIR}
py=${PYTHON:-python3}
have=$("$py" -m PyInstaller --version 2>/dev/null || true)
if [ "$have" != "$PINNED" ]; then
    echo "pack.sh: PyInstaller $PINNED is wanted; this Python has ${have:-none}" >&2
    exit 2
fi
mkdir -p "$work"
work=$(cd "$work" && pwd)
cd "$work"
printf 'import sys\nfrom raqib.cli import main\nsys.exit(main())\n' > entry.py
"$py" -m PyInstaller --noconfirm --onedir --name "$NAME" --collect-all raqib --exclude-module tkinter \
    --log-level WARN --distpath "$work/dist" --workpath "$work/build" --specpath "$work" entry.py >&2
exe="$work/dist/$NAME/$NAME"
if [ ! -x "$exe" ]; then
    echo "pack.sh: no packed program at $exe" >&2
    exit 1
fi
echo "$exe"
