#!/usr/bin/env bash
# The constitutional gate. Green = exit 0. Every landed: commit must pass it.
# The checks live in tools/gate.py (M5.1 E4), which also runs on Windows.
exec python3 -I "$(dirname "$0")/gate.py" "$@"
