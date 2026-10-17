#!/usr/bin/env bash
# Online backup of the Dawr database to a dated file; keeps the newest KEEP.
# Safe while Dawr runs. Every copy is integrity-checked and has every
# circle's hash chain recomputed before it is kept (deploy/dbtool.mjs).
#
#   deploy/backup.sh                                     # Docker Compose install
#   DAWR_DB=/srv/dawr/data/dawr.sqlite deploy/backup.sh  # install without Docker
#
# BACKUP_DIR  where the copies go (default: ./backups). Copies are mode 0600:
#             they hold password hashes and every circle's records.
# KEEP        how many dated copies to keep (default: 30).
# Files are named dawr-YYYY-MM-DDTHHMMSSZ.sqlite (UTC), so the names sort by age.
#
# Exit 0: a good copy was kept. Exit 2: the check failed; the copy is kept as
# evidence as dawr-<time>.sqlite.broken, is never rotated away, and no older
# copy is removed (docs/OPERATIONS.md, "If the ledger check is red").
set -euo pipefail
umask 077

here="$(cd "$(dirname "$0")" && pwd)"
backup_dir="${BACKUP_DIR:-./backups}"
keep="${KEEP:-30}"
case "$keep" in '' | *[!0-9]* | 0) echo "backup: KEEP must be a whole number >= 1" >&2; exit 1 ;; esac

stamp="$(date -u +%Y-%m-%dT%H%M%SZ)"
mkdir -p "$backup_dir"
target="$backup_dir/dawr-$stamp.sqlite"
if [ -e "$target" ]; then echo "backup: $target already exists" >&2; exit 1; fi

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

status=0
if [ -n "${DAWR_DB:-}" ]; then
  # Without Docker: run the tool from the built checkout next to this script.
  node "$here/dbtool.mjs" backup "$DAWR_DB" "$target" || status=$?
  if [ "$status" -eq 2 ]; then target="$target.broken"; fi
  [ "$status" -eq 0 ] || [ "$status" -eq 2 ] || exit "$status"
else
  compose=(docker compose -f "$here/compose.yml")
  inside="/data/.backup-$stamp.sqlite"
  # The copy is made inside the container (where the database is), then
  # streamed out and compared byte for byte before the inside copy is removed.
  "${compose[@]}" exec -T dawr node /app/deploy/dbtool.mjs backup /data/dawr.sqlite "$inside" || status=$?
  if [ "$status" -eq 2 ]; then inside="$inside.broken"; target="$target.broken"; fi
  [ "$status" -eq 0 ] || [ "$status" -eq 2 ] || exit "$status"
  "${compose[@]}" exec -T dawr cat "$inside" > "$target.partial"
  want="$("${compose[@]}" exec -T dawr sha256sum "$inside" | cut -d' ' -f1)"
  got="$(sha "$target.partial" | cut -d' ' -f1)"
  "${compose[@]}" exec -T dawr rm -f "$inside"
  if [ "$want" != "$got" ]; then
    rm -f "$target.partial"
    echo "backup: the copy changed on its way out of the container; nothing kept" >&2
    exit 1
  fi
  mv "$target.partial" "$target"
fi
chmod 600 "$target"

if [ "$status" -eq 2 ]; then
  echo "backup: THE CHECK FAILED. Evidence kept at $target; no older copy was removed." >&2
  echo "backup: follow docs/OPERATIONS.md, \"If the ledger check is red\"." >&2
  exit 2
fi
echo "backup: kept $target"

# Retention: the newest $keep dated copies stay, older ones go. Only names
# this script writes for good copies match; .broken evidence is never removed.
expired="$(ls -1 "$backup_dir" | grep -E '^dawr-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}Z\.sqlite$' | sort -r | tail -n +"$((keep + 1))" || true)"
while IFS= read -r old; do
  [ -n "$old" ] || continue
  rm -f -- "${backup_dir:?}/$old"
  echo "backup: removed $backup_dir/$old (older than the newest $keep)"
done <<< "$expired"
