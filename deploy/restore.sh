#!/usr/bin/env bash
# Restores a copy made by deploy/backup.sh.
#
#   deploy/restore.sh backups/dawr-2026-10-17T031700Z.sqlite        # Docker Compose install
#   DAWR_DB=/srv/dawr/data/dawr.sqlite deploy/restore.sh <backup>   # without Docker; stop the server first
#   deploy/restore.sh --check <backup>                              # only check the copy; change nothing
#
# The copy is checked first (integrity and every circle's chain); a copy that
# fails is not restored. Then the service stops, the current database and
# its -wal/-shm files are moved aside as before-restore-<UTC time>.sqlite in
# the same directory (never deleted: remove them yourself once satisfied),
# the copy takes its place and the service starts again. Restore into the
# same or a newer Dawr version; migrations run forward on start.
set -euo pipefail
umask 077

here="$(cd "$(dirname "$0")" && pwd)"
check_only=0
if [ "${1:-}" = "--check" ]; then check_only=1; shift; fi
backup="${1:?usage: deploy/restore.sh [--check] <backup file>}"
if [ ! -f "$backup" ]; then echo "restore: no file $backup" >&2; exit 1; fi
stamp="$(date -u +%Y-%m-%dT%H%M%SZ)"

if [ -n "${DAWR_DB:-}" ]; then
  if ! node "$here/dbtool.mjs" verify "$backup"; then
    echo "restore: $backup failed its check; nothing was changed" >&2
    exit 1
  fi
  if [ "$check_only" -eq 1 ]; then echo "restore: $backup is good (checked only)"; exit 0; fi
  dir="$(dirname "$DAWR_DB")"
  for suffix in "" -wal -shm; do
    if [ -e "$DAWR_DB$suffix" ]; then mv -- "$DAWR_DB$suffix" "$dir/before-restore-$stamp.sqlite$suffix"; fi
  done
  cp -- "$backup" "$DAWR_DB"
  chmod 600 "$DAWR_DB"
  echo "restore: $DAWR_DB now holds $backup; the previous files are $dir/before-restore-$stamp.sqlite*"
  echo "restore: start the server, then open a circle's Ledger and press Verify chain"
  exit 0
fi

compose=(docker compose -f "$here/compose.yml")
run=("${compose[@]}" run --rm --no-deps -T -e STAMP="$stamp" dawr)
staged="/data/.restore-$stamp.sqlite"
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

# Stage the copy inside the volume (streamed, so the backup's owner and mode
# on the host do not matter), compare it byte for byte, and check it there.
"${run[@]}" sh -c 'cat > "/data/.restore-$STAMP.sqlite"' < "$backup"
want="$(sha "$backup" | cut -d' ' -f1)"
got="$("${run[@]}" sha256sum "$staged" | cut -d' ' -f1)"
if [ "$want" != "$got" ] || ! "${run[@]}" node /app/deploy/dbtool.mjs verify "$staged"; then
  "${run[@]}" rm -f "$staged"
  echo "restore: the copy did not arrive intact or failed its check; nothing was changed" >&2
  exit 1
fi
if [ "$check_only" -eq 1 ]; then
  "${run[@]}" rm -f "$staged"
  echo "restore: $backup is good (checked only; nothing was changed)"
  exit 0
fi

"${compose[@]}" stop dawr
"${run[@]}" sh -c '
  set -e
  for suffix in "" -wal -shm; do
    if [ -e "/data/dawr.sqlite$suffix" ]; then mv "/data/dawr.sqlite$suffix" "/data/before-restore-$STAMP.sqlite$suffix"; fi
  done
  mv "/data/.restore-$STAMP.sqlite" /data/dawr.sqlite
  chmod 600 /data/dawr.sqlite'
"${compose[@]}" up -d --no-build --wait dawr
echo "restore: the service runs on $backup; the previous files are /data/before-restore-$stamp.sqlite* in the volume"
echo "restore: open a circle's Ledger and press Verify chain"
