# Operating Dawr

For whoever runs a Dawr instance for a circle or a community. Dawr is one
process, one SQLite file and one directory (`/data`), behind a reverse
proxy that terminates TLS. It never makes an outbound connection, so it
needs no API keys, no mail server and no internet access of its own.

Contents: [First run](#first-run) · [Configuration](#configuration) ·
[Without Docker](#without-docker) · [Upgrade](#upgrade) ·
[Backup and restore](#backup-and-restore) ·
[Rotating the session secret](#rotating-the-session-secret) ·
[Reading logs](#reading-logs) · [Retention](#retention) ·
[Resources](#resources) · [Health](#health) ·
[If the ledger check is red](#if-the-ledger-check-is-red)

## First run

You need a Linux host with Docker Engine and the Compose plugin, a DNS name
that points at the host (for example `dawr.example.org`), and ports 80 and
443 reachable from the internet for the certificate.

```sh
git clone https://github.com/omanras/raqib.git dawr && cd dawr
git checkout dawr                     # the Dawr branch of this repository
cp deploy/env.example deploy/.env
openssl rand -hex 32                  # paste the output as SESSION_SECRET in deploy/.env
${EDITOR:-nano} deploy/.env           # set BASE_URL=https://dawr.example.org
docker compose -f deploy/compose.yml --profile caddy up -d --build
docker compose -f deploy/compose.yml ps     # dawr should say "healthy"
```

Open `BASE_URL` in a browser and create the first account. That person
creates a circle and invites the others (README, "How a circle runs").

The three settings that matter, and why the server refuses to start in
production without them:

- **SESSION_SECRET**: at least 32 characters, random, kept secret. It keys
  the CSRF tokens and the hashes that let the log and the audit trail
  correlate a user or a browser without storing who they are. Keep a copy
  with your other secrets; `deploy/.env` is never committed (the gate and
  `.gitignore` make sure).
- **BASE_URL**: the origin members open, `https://` and no path. It is the
  origin of invitation links; with the bundled Caddy it is also the site
  Caddy obtains and renews a certificate for.
- **TRUST_PROXY=1**: set by `deploy/compose.yml`. Dawr only runs behind a
  proxy, and trusts exactly one hop: the address the proxy saw becomes the
  client address used for rate limits and the audit trail; anything a
  client writes into `X-Forwarded-For` itself is ignored.

Sign-up is open to anyone who can reach `BASE_URL`. An account on its own
sees nothing: circles are visible only to the members an organizer invited
(by a one-time link) and who accepted.

### With your own reverse proxy instead of Caddy

Leave out `--profile caddy`. The app is published on the host's loopback
only (`127.0.0.1:3000`, or `DAWR_PORT`), never on a public interface.
Point your proxy at it, terminate TLS there, and set `X-Forwarded-For` to
the client address. For nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    client_max_body_size 1m;
}
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `NODE_ENV` | `development` | `production` in the image. Production enforces the three rules above, sets `Secure` `__Host-` cookies and HSTS. |
| `SESSION_SECRET` | generated in development | Required in production, 32+ characters. In development a secret is written once to `DATA_DIR/session-secret` (mode 0600). |
| `BASE_URL` | `http://127.0.0.1:PORT` | Origin of the site; https in production. |
| `TRUST_PROXY` | unset | `1` behind a reverse proxy (required in production). |
| `DATA_DIR` | `./data` (`/data` in the image) | Holds `dawr.sqlite` and its `-wal`/`-shm` files. |
| `PORT` / `HOST` | `3000` / `127.0.0.1` (`0.0.0.0` in the image) | Listening address. |
| `LOG_LEVEL` | `info` | `fatal`, `error`, `warn`, `info`, `debug`, `trace` or `silent`. |
| `CLIENT_DIR` | `client/dist` | The built web client (set in the image). |

Compose-only: `DAWR_PORT` (loopback port, 3000), `DAWR_IMAGE` (image tag),
`NODE_IMAGE` (base image, e.g. a registry mirror of `node:22-bookworm-slim`),
`CADDY_IMAGE` (`caddy:2.10`).

The container runs as the unprivileged `node` user with a read-only root
filesystem, no Linux capabilities, `no-new-privileges`, a 512 MB memory
limit and only `/data` writable (a volume). `deploy/smoke.sh` checks all of
this against a real container and runs in CI on every push.

## Without Docker

Node.js 22.12 or newer on the host:

```sh
npm ci && npm run build
export NODE_ENV=production SESSION_SECRET=... BASE_URL=https://dawr.example.org TRUST_PROXY=1
export DATA_DIR=/var/lib/dawr HOST=127.0.0.1 PORT=3000
npm start
```

Run it under a service manager as its own user, with only `DATA_DIR`
writable. A systemd unit:

```ini
[Service]
User=dawr
WorkingDirectory=/opt/dawr
EnvironmentFile=/etc/dawr.env
ExecStart=/usr/bin/node server/dist/server/main.js
ProtectSystem=strict
ReadWritePaths=/var/lib/dawr
NoNewPrivileges=true
PrivateTmp=true
Restart=on-failure
```

`server/dist/server/main.js` is what `npm start` runs; calling node directly
keeps npm from writing its own logs.

## Upgrade

1. Take a backup: `deploy/backup.sh` (below).
2. Fetch the new version: `git fetch && git checkout <tag or branch>`.
3. Rebuild and restart: `docker compose -f deploy/compose.yml --profile caddy up -d --build`.
4. Check: `docker compose -f deploy/compose.yml ps` says healthy, and
   `/api/health` reports the new `version` and the migration count.

Migrations are numbered, checksummed and run forward on start, each in its
own transaction. The server refuses to start if a migration it applied
earlier has changed or disappeared, which is also what happens when an
older version is started on a newer database. To go back a version,
restore the backup you took in step 1 and run the older image.

## Backup and restore

`deploy/backup.sh` makes an online copy while Dawr runs (SQLite's backup
API, what the `sqlite3` shell's `.backup` does), checks it with
`PRAGMA integrity_check` and by recomputing every circle's hash chain,
and keeps it as `backups/dawr-YYYY-MM-DDTHHMMSSZ.sqlite` (UTC, mode 0600).
The newest 30 are kept (`KEEP`), older ones removed.

```sh
deploy/backup.sh                                       # Docker Compose install
BACKUP_DIR=/srv/backups/dawr KEEP=30 deploy/backup.sh  # elsewhere, keep 30
DAWR_DB=/var/lib/dawr/dawr.sqlite deploy/backup.sh     # without Docker
```

Daily from cron, mailing failures (cron mails non-empty output; the script
prints to stderr only when something is wrong):

```cron
17 3 * * *  cd /srv/dawr && deploy/backup.sh >/dev/null
```

A copy holds password hashes (scrypt), session hashes and every circle's
records: copy it off the host encrypted (for example with `age` or `gpg`)
and keep the decryption key apart from the server. A backup on the same
disk is not a backup.

If the check fails, the script exits 2, keeps the copy as
`dawr-<time>.sqlite.broken` as evidence, and removes no older copy; see
[If the ledger check is red](#if-the-ledger-check-is-red).

### Restore

```sh
deploy/restore.sh --check backups/dawr-2026-10-17T031700Z.sqlite   # check only
deploy/restore.sh backups/dawr-2026-10-17T031700Z.sqlite           # restore
DAWR_DB=/var/lib/dawr/dawr.sqlite deploy/restore.sh <file>         # without Docker: stop the server first
```

The script checks the copy first (a copy that fails is never restored),
stops the service, moves the current database and its `-wal`/`-shm` files
aside as `before-restore-<time>.sqlite*` in `/data` (they are never
deleted; remove them yourself when satisfied), puts the copy in place,
starts the service and waits for it to become healthy. Then open any
circle's **Ledger** and press **Verify chain**.

Everything after the backup is gone from the restored instance. Members'
own exports and shared round summaries still hold what happened since:
re-enter it as new records (history is never edited, only added to).

Restore into the same or a newer Dawr version. The session secret is not in
the database and sessions do not depend on it, so whoever was signed in
when the backup was made stays signed in after the restore.

Without Docker, both scripts run `deploy/dbtool.mjs` with the checkout's
own build, so run them where `npm ci && npm run build` was done.

## Rotating the session secret

Rotate when the secret may have leaked, when someone who knew it leaves,
or on a schedule you choose.

```sh
openssl rand -hex 32          # put it in deploy/.env as SESSION_SECRET
docker compose -f deploy/compose.yml up -d    # recreates the container with the new value
```

What changes:

- **Nobody is signed out.** Session tokens are stored as SHA-256 hashes,
  not keyed by the secret. A page already open has its next change refused
  for a stale CSRF token; the client fetches a fresh one and retries once
  by itself, so members do not notice.
- **Correlation restarts.** The keyed hashes in the operator log (`userId`)
  and the audit trail (user-agent hash, failed sign-in target) are
  different after rotation, so entries before and after cannot be matched
  to each other by those fields. The audit rows themselves (who, by user
  id; what; when; request id) are unaffected.

To end every session after a suspected compromise of the database itself,
ask members to use **Account → Sign out everywhere**; an operator-wide
sign-out is not part of v0.1.

## Reading logs

```sh
docker compose -f deploy/compose.yml logs -f dawr          # follow
docker compose -f deploy/compose.yml logs --since 1h dawr  # the last hour
```

One JSON object per line on stdout (pino). Every request ends with a
`"msg":"request"` line:

| Field | Meaning |
|---|---|
| `level`, `time` | `info`/`warn`/`error`/...; ISO 8601 UTC. |
| `app` | Always `dawr`. |
| `requestId` | Generated by the server per request (a client cannot choose it); also sent as the `x-request-id` response header. |
| `method`, `route` | The route pattern, e.g. `/api/circles/:id/ledger`: ids from the URL do not land in the log. |
| `status`, `durationMs` | Response status and time. |
| `userId` | A keyed 16-hex hash of the signed-in user, or absent. |

Other lines: `migrations` (`applied`, `total`) at start; `client error`
(`errorCode`, `status`) for refused requests; `unhandled error` (`err`, a
stack trace for you, never sent to the browser); `shutting down`.

**Finding one request.** When something fails in the browser, the error
message shows **Request id …**. Organizers also see the request id of every
change in the circle's **Activity** tab. Look it up with:

```sh
docker compose -f deploy/compose.yml logs dawr | grep '"requestId":"PASTE-THE-ID"'
```

Never in the log: passwords, session tokens, cookies, CSRF tokens,
invitation tokens, recovery codes and draw secrets (redacted, and tested
over a tour of every route); names, logins and IP addresses (no log line
has a field for them). The audit trail keeps IP addresses truncated to /24
(IPv4) or /48 (IPv6).

The health check calls `/api/health` every 30 seconds; each call is one
log line.

## Retention

- **Operator log**: with Compose, Docker's `json-file` driver keeps at most
  5 files of 10 MB per container (set in `deploy/compose.yml`); older lines
  are dropped. Without Docker, it is whatever your service manager does
  with stdout (journald: `SystemMaxUse=`).
- **Ledger and audit trail**: kept for the life of the database. Both
  tables refuse UPDATE and DELETE by trigger; neither Dawr nor the scripts
  here remove rows, and v0.1 has no pruning. They are small (next section).
- **Backups**: the newest 30 (`KEEP`); `.broken` evidence copies and
  `before-restore-*` files stay until you remove them.
- **Sessions**: expire after 30 days idle or 90 days in all; expired rows
  stay in the database and are never accepted again.

A full disk makes writes fail (the app answers with an error and the
transaction is rolled back; nothing half-written lands in the ledger).
Watch free space on the volume's disk; keep at least the database size
times three free (the database, a backup being made, its copy leaving the
container).

## Resources

Measured on the image (Node 22, x86-64):

- **Memory**: about 30 MB resident when idle. Each sign-in, sign-up,
  password change or recovery runs scrypt with 32 MB for a fraction of a
  second; Node runs at most four at once, so plan for 200 MB; the Compose
  limit is 512 MB. Eight simultaneous sign-in attempts finished in under
  0.5 s.
- **CPU**: one core is plenty for a community of hundreds of members.
- **Disk**: the image is about 385 MB unpacked. An empty database is about
  170 KB. A ledger entry is about 340 bytes and an audit row about 150; a
  12-member monthly circle produces a few hundred of each in a year, well
  under 1 MB. Thirty backups of a database of that size are tens of MB.

## Health

`GET /api/health` (no sign-in) answers
`{"ok":true,"version":"…","db":"ok","migrations":1}`, or 503 with
`"db":"error"` when the database cannot be read. The container's
`HEALTHCHECK` uses it (`deploy/healthcheck.mjs`), Compose starts Caddy only
once the app is healthy, and `docker compose -f deploy/compose.yml ps` shows
the state. An unhealthy container is restarted by `restart: unless-stopped`
only if the process exits; look at the log for the reason.

## If the ledger check is red

A red **Verify chain** in the browser, a `BROKEN` line from
`deploy/dbtool.mjs`, or `deploy/backup.sh` exiting 2 all mean the same
thing: a stored ledger entry no longer matches its hash or its link to the
previous entry. Dawr itself cannot cause this (the ledger table refuses
UPDATE and DELETE); it means the database file was changed outside Dawr,
or the disk corrupted it.

1. **Change nothing yet.** Do not edit the database and do not restore
   over it. Keep the `.broken` copy if a backup made one; otherwise take
   one now with `deploy/backup.sh` (it will exit 2 and keep the evidence).
2. **Find the break.** The Ledger screen names the first broken entry;
   for every circle at once, on the evidence copy:
   `deploy/restore.sh --check backups/dawr-<time>.sqlite.broken`
   (it prints each circle and the seq where its chain breaks, and changes
   nothing). `integrity` other than `ok` points at disk corruption.
3. **Compare with copies Dawr does not control.** Members' downloaded
   ledger exports (JSON/CSV) and the "Share this round" messages in the
   group chat carry entry numbers and hashes ("Ledger: entry N, hash …").
   The last head that matches tells you from where the record differs.
4. **Find the newest good backup**: run `deploy/restore.sh --check` on
   the dated copies, newest first, until one says good.
5. **Look for the cause** before anything else: who has access to the
   host and the volume, the operator log and the circle's **Activity** tab
   around the time of the broken entry (each row has its request id).
   Treat the host as possibly compromised: rotate `SESSION_SECRET`, review
   access, keep the evidence copy off the host.
6. **Decide with the circle.** Tell the organizer and the members what is
   broken from which entry. Either restore the newest good backup with
   `deploy/restore.sh` and re-enter what happened since as new records
   (members' exports and the group chat are the source), or keep running
   with the break known to everyone. Dawr never repairs a chain: a
   repaired chain would be indistinguishable from a forged one.

A red **Recompute in this browser** on the Draw tab is the same kind of
finding for the turn order: the recorded order does not follow from the
revealed secrets. Follow the same steps; the draw's commitments and
reveals are ledger entries, so the chain check covers them as well.
