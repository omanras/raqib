# Dawr

**Dawr** (دور, "turn") keeps a savings circle honest. A savings circle —
jam'iyya, ROSCA, tontine, committee — is a group that pays a fixed amount
every period while one member, in turn, receives the whole pot. Dawr is the
shared record of such a circle: who paid, who received, what the rules and
the turn order are, kept so that every member can check it and nobody can
quietly change it.

It is a small web application you host yourself: one container, one SQLite
file, English and Arabic, made for a phone.

## What Dawr is, and what it is not

Dawr **is** a record and a referee:

- an append-only ledger of every event, hash-chained, that any member can
  verify in their own browser;
- a turn-order draw nobody can rig, the organizer included;
- statements recomputed from the ledger, exportable as CSV;
- an activity log of every change, with who, when and from which request.

Dawr **is not** a bank, a wallet or an advisor. **It never moves money**:
no payments, no bank connections, no cards. Members pay each other the way
they always have (cash, transfer); Dawr records what members report and
what the organizer confirms, and shows the difference. It gives no
financial advice and makes no decision for the circle. It never makes an
outbound network connection: no analytics, no third-party scripts, no
e-mail.

## Self-host in ten minutes

You need a Linux server with Docker and the Compose plugin, a domain name
pointing at it, and ports 80 and 443 open. The bundled Caddy obtains the
TLS certificate automatically.

```sh
git clone https://github.com/omanras/raqib.git dawr && cd dawr
git checkout dawr
cp deploy/env.example deploy/.env
openssl rand -hex 32        # put this in deploy/.env as SESSION_SECRET
nano deploy/.env            # set BASE_URL=https://your.domain
docker compose -f deploy/compose.yml --profile caddy up -d --build
```

Open your domain and create the first account. Then:

- back up daily with `deploy/backup.sh` (dated copies, newest 30 kept,
  each one checked before it is kept) and restore with `deploy/restore.sh`;
- everything else an operator needs — upgrades, logs, rotating the
  secret, running without Docker or behind your own proxy, and what to do
  if a check turns red — is in [docs/OPERATIONS.md](docs/OPERATIONS.md).

To try it on your own computer instead (Node.js 22.12+), without TLS:

```sh
npm ci
npm run build
npm start                   # http://127.0.0.1:3000, data in ./data
```

## How a circle runs

Screen names are as they appear in English; the Arabic screens mirror them.

### The organizer

1. **Create your account**: a login, a display name and a password. Dawr
   shows **eight recovery codes once** — keep them: there is no e-mail
   reset.
2. **Create a circle** (**New circle**): its name, the **Currency**, the
   **Contribution per member**, **How often** (monthly, every two weeks,
   weekly), the **Due day**, the **Rules** every member will read, and
   optionally the **Start date**. Amounts are exact: no rounding, ever.
3. **Invite members**: in the circle's **Members** tab, **Create an
   invitation link** and send it to one person (a group chat is fine). Each
   link works once and for seven days; you can revoke it.
4. **Set the turn order** (**Members → Turn order**): move people up and
   down and **Save this order**, or **Run a draw instead** (below).
5. **Start the circle** (**Members**): this fixes the members, the order
   and the schedule and creates every round. It cannot be undone; Dawr
   lists anything that is not ready yet.
6. **Each round** (**Rounds → Round n**): members report their payments;
   you **Confirm** each one when the money has really arrived (or **Record
   a payment** for someone, or **Waive this contribution** with a reason).
   When you have paid the recipient, **Record the payout**. **Close this
   round**, then **Open this round** on the next one. Anything still
   unpaid stays visible as outstanding, with its age.
7. **Share this round** (**Overview**) copies a plain-text summary for the
   group chat, ending with the ledger's latest entry number and hash, so
   the chat keeps its own copy of where the record stood.
8. While the circle is a draft, **Settings** changes its rules (each change
   becomes a ledger entry) or cancels it; **Activity** shows every change
   with its request id.

### A member

1. Open the invitation link, sign in or **Create an account**, choose **Your
   name in this circle** and **Accept and join**.
2. **Overview** shows **Round n of N**, who **Receives this round**, the due
   date and days left, and what everyone has paid. **Report my payment**
   with **How it was paid** and a **Reference** if there is one; it shows
   as reported until the organizer confirms it.
3. In the round you receive, confirm it with **I received this payout**.
   Until you do, the payout is shown as not acknowledged.
4. At any time: **Ledger → Verify chain** checks every entry in your
   browser; **Statement** shows what was expected, confirmed and is
   outstanding, per round and per member, with **Download CSV**.

### The draw

When the organizer chooses a draw, they **Open the draw** with two
deadlines. Each member presses **Make my secret and commit**: the browser
makes a secret, keeps it, and sends only its fingerprint (the secret is
shown once to save, in case you change phones). When commitments close (at
the deadline, or earlier with **Close commitments** once everyone has
committed), everyone **Reveal**s. **Finalize the order** computes the turn order from
all the secrets together; members who never revealed go last. On the
**Draw** tab, **Recompute in this browser** repeats the computation from
the recorded secrets and must give the same order.

## What you can trust, in plain words

- **The record cannot be edited without it showing.** Every entry carries a
  fingerprint (SHA-256) of its content and of the entry before it. The
  database refuses to change or delete entries; if someone changed the file
  anyway, **Verify chain** on any member's phone shows the first entry that
  no longer matches. Corrections are new entries, never edits.
- **Nobody can choose the turn order** in a draw — not the organizer, not
  the server. The order follows from every member's secret, and nobody can
  see anyone's secret before committing their own. Anyone can recompute it.
- **Statements are arithmetic on the record.** Totals are recomputed from
  the ledger entries, in exact minor units (baisa, fils, halala, cents),
  and each line names the entries it rests on.
- **Silence is shown, not hidden.** An unpaid contribution is outstanding
  with its age; an unacknowledged payout says so; a missing reveal is
  named.
- **Members see what the organizer sees**: the same ledger, order and
  statements.

What it cannot do: stop an organizer from confirming money that never
arrived (the confirmation is recorded, with who and when, and the
recipient's acknowledgement is the counterweight), or protect a member
whose own device is compromised. The full list is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Languages

English and Arabic, complete. The **العربية** / **English** button in the
top bar switches; Arabic gets a right-to-left layout, with Latin digits and
ISO dates (2026-10-17) so amounts and dates read the same for everyone.
There is a light and a dark theme, following the system or chosen by hand.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
The design is in [docs/specs/ADR-0001-architecture.md](docs/specs/ADR-0001-architecture.md),
the checklist every release is held to in
[docs/SECURITY_REQUIREMENTS.md](docs/SECURITY_REQUIREMENTS.md), and the
threats with the test covering each in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## For developers

Node.js 22.12+, TypeScript (strict), Fastify 5, better-sqlite3, zod, pino,
Preact and Vite; vitest and Playwright.

```sh
npm ci
npm run typecheck
npm test                    # unit and API tests
npm run test:e2e            # Playwright (Chromium)
npm run build
tools/gate.sh               # everything a change must pass
```

`shared/` holds the domain (money, schedule, ledger, draw, state machines),
used by both `server/` and `client/`. `docs/` has the constitution, the
plan and the review notes; [CHANGELOG.md](CHANGELOG.md) lists what each
version delivered.

This repository also holds other projects on other branches (`main`,
`mizan`, `qayd`, `qayd-web`); Dawr lives on `dawr`.

License: MIT.
