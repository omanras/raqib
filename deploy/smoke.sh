#!/usr/bin/env bash
# Container smoke test: CI runs it on every push; run it by hand wherever
# Docker runs (it needs nothing but Docker, Node and this checkout).
#
#   deploy/smoke.sh                            # docker build, then the checks
#   DAWR_IMAGE=dawr:ci deploy/smoke.sh --no-build
#
# Under a throwaway Compose project it checks that the image becomes healthy,
# runs as a non-root user with a read-only root filesystem and only /data
# writable, answers with the production headers, and that a circle created
# through the API survives deploy/backup.sh then deploy/restore.sh with its
# hash chain intact (a circle created after the backup is gone again).
set -euo pipefail
cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME="dawr-smoke-$$"
export DAWR_IMAGE="${DAWR_IMAGE:-dawr:smoke}"
export DAWR_PORT="${DAWR_PORT:-3299}"
export BASE_URL="https://dawr.invalid"
SESSION_SECRET="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
export SESSION_SECRET
export SMOKE_URL="http://127.0.0.1:$DAWR_PORT"

work="$(mktemp -d)"
compose=(docker compose -f deploy/compose.yml)
cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "${work:?}"
}
trap cleanup EXIT
step() { echo "[smoke] $*"; }
die() { echo "[smoke] FAILED: $*" >&2; exit 1; }

if [ "${1:-}" != "--no-build" ]; then
  step "docker build -f deploy/Dockerfile -t $DAWR_IMAGE ."
  docker build -f deploy/Dockerfile -t "$DAWR_IMAGE" ${NODE_IMAGE:+--build-arg NODE_IMAGE="$NODE_IMAGE"} .
fi

step "compose file is valid (with and without the caddy profile)"
"${compose[@]}" config --quiet
"${compose[@]}" --profile caddy config --quiet

step "start and wait for the health check"
"${compose[@]}" up -d --no-build --wait --wait-timeout 120 dawr
cid="$("${compose[@]}" ps -q dawr)"
[ -n "$cid" ] || die "no container"

step "non-root user, read-only root filesystem, /data writable"
uid="$(docker exec "$cid" id -u)"
[ "$uid" != "0" ] || die "the container runs as root"
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$cid")" = "true" ] || die "root filesystem is writable"
if docker exec "$cid" sh -c 'echo x > /app/probe' 2>/dev/null; then die "/app is writable"; fi
docker exec "$cid" sh -c 'echo x > /data/.probe && rm /data/.probe' || die "/data is not writable"
docker inspect -f '{{json .Config.Volumes}}' "$cid" | grep -q '"/data"' || die "/data is not a volume"

api() { node --input-type=module - "$@" <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
const [mode, stateFile] = process.argv.slice(2);
const base = process.env.SMOKE_URL;
const state = mode === 'seed' ? { cookies: {} } : JSON.parse(readFileSync(stateFile, 'utf8'));
const fail = (m) => { console.error(`[smoke] FAILED: ${m}`); process.exit(1); };
async function call(method, path, body, csrf) {
  const headers = { accept: 'application/json', 'user-agent': 'dawr-smoke' };
  const jar = Object.entries(state.cookies);
  if (jar.length) headers.cookie = jar.map(([k, v]) => `${k}=${v}`).join('; ');
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (csrf) headers['x-csrf-token'] = csrf;
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(';');
    const i = pair.indexOf('=');
    const value = pair.slice(i + 1);
    if (value === '' || /max-age=0/i.test(c)) delete state.cookies[pair.slice(0, i)];
    else state.cookies[pair.slice(0, i)] = value;
  }
  const text = await res.text();
  return { status: res.status, headers: res.headers, json: text ? JSON.parse(text) : null };
}
const csrf = async () => (await call('GET', '/api/auth/csrf')).json.csrfToken;
const circle = async (name) => {
  const r = await call('POST', '/api/circles', { name, currency: 'OMR', contribution: 50000, period: 'monthly', dueDay: 5, rulesText: 'Smoke test.' }, await csrf());
  if (r.status !== 201) fail(`create circle: ${r.status} ${JSON.stringify(r.json)}`);
  return r.json.circle.id;
};
const verified = async (id) => (await call('GET', `/api/circles/${id}/ledger?verify=1`)).json?.verification?.ok === true;

if (mode === 'seed') {
  const h = await call('GET', '/api/health');
  if (h.status !== 200 || h.json.ok !== true || h.json.db !== 'ok') fail(`health: ${h.status} ${JSON.stringify(h.json)}`);
  for (const name of ['strict-transport-security', 'content-security-policy', 'x-request-id']) {
    if (!h.headers.get(name)) fail(`missing header ${name}`);
  }
  const s = await call('POST', '/api/auth/signup', { login: 'smoke', displayName: 'Smoke', password: 'a quiet smoke test passphrase' }, await csrf());
  if (s.status !== 201) fail(`signup: ${s.status} ${JSON.stringify(s.json)}`);
  state.kept = await circle('Kept by the backup');
  if (!(await verified(state.kept))) fail('chain of the new circle does not verify');
  console.log(`[smoke] version ${h.json.version}, ${h.json.migrations} migration(s), circle ${state.kept} created`);
} else if (mode === 'after-backup') {
  state.lost = await circle('Made after the backup');
} else if (mode === 'after-restore') {
  const r = await call('GET', '/api/circles');
  if (r.status !== 200) fail(`list circles after restore: ${r.status}`);
  const ids = r.json.circles.map((c) => c.id);
  if (!ids.includes(state.kept)) fail('the backed-up circle is missing after restore');
  if (ids.includes(state.lost)) fail('a circle made after the backup is still there after restore');
  if (!(await verified(state.kept))) fail('chain does not verify after restore');
  console.log('[smoke] restored: the backed-up circle is back, its chain verifies, the later one is gone');
}
writeFileSync(stateFile, JSON.stringify(state));
JS
}

step "health, production headers, sign up, create a circle"
api seed "$work/state.json"

step "deploy/backup.sh"
BACKUP_DIR="$work/backups" deploy/backup.sh
backup="$(ls -1 "$work"/backups/dawr-*.sqlite | head -n 1)"
[ -n "$backup" ] || die "no backup written"
[ "$(stat -c %a "$backup")" = "600" ] || die "backup is not mode 0600"

step "a change after the backup"
api after-backup "$work/state.json"

step "deploy/restore.sh --check, then deploy/restore.sh"
deploy/restore.sh --check "$backup"
deploy/restore.sh "$backup"
docker run --rm -v "${COMPOSE_PROJECT_NAME}_dawr-data:/data:ro" --entrypoint ls "$DAWR_IMAGE" /data | grep -q '^before-restore-' \
  || die "the replaced database was not kept"
api after-restore "$work/state.json"

step "a ledger row changed underneath the app: backup.sh exits 2, keeps the evidence, removes nothing"
# As someone with write access to the file could: recreate the table without
# its append-only triggers, edit one payload, put the triggers back.
"${compose[@]}" exec -T dawr node --input-type=module - <<'JS'
import Database from 'better-sqlite3';
const db = new Database('/data/dawr.sqlite');
db.pragma('busy_timeout = 10000');
const table = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'ledger'").get().sql;
const triggers = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'ledger'").pluck().all();
db.transaction(() => {
  db.exec('ALTER TABLE ledger RENAME TO ledger_old');
  db.exec(table);
  db.exec('INSERT INTO ledger SELECT * FROM ledger_old');
  db.exec('DROP TABLE ledger_old');
  db.prepare("UPDATE ledger SET payload = replace(payload, '50000', '90000') WHERE seq = 1").run();
  for (const sql of triggers) db.exec(sql);
})();
db.close();
JS
status=0
BACKUP_DIR="$work/backups" KEEP=1 deploy/backup.sh || status=$?
[ "$status" -eq 2 ] || die "backup.sh exited $status on a broken chain, not 2"
ls "$work"/backups/dawr-*.sqlite.broken >/dev/null 2>&1 || die "no .broken evidence copy"
[ -f "$backup" ] || die "an older good copy was removed after a failed check"
if deploy/restore.sh --check "$(ls "$work"/backups/dawr-*.sqlite.broken | head -n 1)"; then die "restore --check accepted a broken copy"; fi

step "GREEN"
