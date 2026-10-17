-- Dawr schema v1 (ADR-0001 §3). Every table has created_at. Ids are random
-- (server/crypto.ts newId), never sequential, except the internal integer
-- keys of ledger and audit, which never appear in URLs.

CREATE TABLE users (
  id                  TEXT PRIMARY KEY,
  login               TEXT NOT NULL UNIQUE,
  display_name        TEXT NOT NULL,
  password_hash       TEXT NOT NULL,
  password_changed_at TEXT NOT NULL,
  created_at          TEXT NOT NULL
) STRICT;

CREATE TABLE sessions (
  id                  TEXT PRIMARY KEY,
  token_hash          TEXT NOT NULL UNIQUE,
  user_id             TEXT NOT NULL REFERENCES users(id),
  ua_hash             TEXT NOT NULL DEFAULT '',
  created_at          TEXT NOT NULL,
  last_seen_at        TEXT NOT NULL,
  idle_expires_at     TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL,
  revoked_at          TEXT,
  revoked_reason      TEXT
) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE recovery_codes (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id),
  code_hash  TEXT NOT NULL,
  used_at    TEXT,
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX recovery_codes_user ON recovery_codes(user_id);

CREATE TABLE circles (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  currency       TEXT NOT NULL,
  minor_unit     INTEGER NOT NULL CHECK (minor_unit IN (2, 3)),
  contribution   INTEGER NOT NULL CHECK (contribution > 0),
  period         TEXT NOT NULL CHECK (period IN ('monthly', 'weekly', 'biweekly')),
  due_day        INTEGER NOT NULL CHECK (due_day BETWEEN 1 AND 28),
  start_date     TEXT,
  member_count   INTEGER,
  recipient_pays INTEGER NOT NULL DEFAULT 1 CHECK (recipient_pays IN (0, 1)),
  status         TEXT NOT NULL DEFAULT 'draft'
                 CHECK (status IN ('draft', 'drawing', 'active', 'completed', 'cancelled')),
  rules_text     TEXT NOT NULL DEFAULT '',
  created_by     TEXT NOT NULL REFERENCES users(id),
  created_at     TEXT NOT NULL,
  started_at     TEXT,
  completed_at   TEXT,
  cancelled_at   TEXT
) STRICT;

CREATE TABLE members (
  id           TEXT PRIMARY KEY,
  circle_id    TEXT NOT NULL REFERENCES circles(id),
  user_id      TEXT NOT NULL REFERENCES users(id),
  role         TEXT NOT NULL CHECK (role IN ('organizer', 'member')),
  display_name TEXT NOT NULL,
  position     INTEGER,
  joined_at    TEXT NOT NULL,
  left_at      TEXT,
  created_at   TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX members_one_active ON members(circle_id, user_id) WHERE left_at IS NULL;
CREATE UNIQUE INDEX members_position ON members(circle_id, position) WHERE position IS NOT NULL AND left_at IS NULL;
CREATE INDEX members_user ON members(user_id);

CREATE TABLE rounds (
  id                  TEXT PRIMARY KEY,
  circle_id           TEXT NOT NULL REFERENCES circles(id),
  n                   INTEGER NOT NULL CHECK (n >= 1),
  due_date            TEXT NOT NULL,
  recipient_member_id TEXT NOT NULL REFERENCES members(id),
  status              TEXT NOT NULL DEFAULT 'upcoming' CHECK (status IN ('upcoming', 'open', 'closed')),
  opened_at           TEXT,
  closed_at           TEXT,
  created_at          TEXT NOT NULL,
  UNIQUE (circle_id, n)
) STRICT;

-- One row per (round, member) obligation: what is expected. What was
-- reported and confirmed is recorded as ledger entries (and indexed by a
-- later migration); totals are recomputed, never stored as the truth.
CREATE TABLE contributions (
  id           TEXT PRIMARY KEY,
  circle_id    TEXT NOT NULL REFERENCES circles(id),
  round_n      INTEGER NOT NULL,
  member_id    TEXT NOT NULL REFERENCES members(id),
  expected     INTEGER NOT NULL CHECK (expected >= 0),
  waived_at    TEXT,
  waived_by    TEXT REFERENCES users(id),
  waive_reason TEXT,
  created_at   TEXT NOT NULL,
  UNIQUE (circle_id, round_n, member_id)
) STRICT;

CREATE TABLE payouts (
  id              TEXT PRIMARY KEY,
  circle_id       TEXT NOT NULL REFERENCES circles(id),
  round_n         INTEGER NOT NULL,
  amount          INTEGER NOT NULL CHECK (amount > 0),
  paid_on         TEXT NOT NULL,
  method          TEXT NOT NULL DEFAULT '',
  reference       TEXT NOT NULL DEFAULT '',
  recorded_by     TEXT NOT NULL REFERENCES users(id),
  recorded_at     TEXT NOT NULL,
  acknowledged_at TEXT,
  acknowledged_by TEXT REFERENCES users(id),
  created_at      TEXT NOT NULL,
  UNIQUE (circle_id, round_n)
) STRICT;

CREATE TABLE invites (
  id          TEXT PRIMARY KEY,
  circle_id   TEXT NOT NULL REFERENCES circles(id),
  token_hash  TEXT NOT NULL UNIQUE,
  created_by  TEXT NOT NULL REFERENCES users(id),
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  accepted_at TEXT,
  accepted_by TEXT REFERENCES users(id),
  revoked_at  TEXT,
  revoked_by  TEXT REFERENCES users(id)
) STRICT;
CREATE INDEX invites_circle ON invites(circle_id);

-- The ledger (A2): append-only, hash-chained per circle.
CREATE TABLE ledger (
  id         INTEGER PRIMARY KEY,
  circle_id  TEXT NOT NULL REFERENCES circles(id),
  seq        INTEGER NOT NULL CHECK (seq >= 1),
  ts         TEXT NOT NULL,
  actor      TEXT NOT NULL,
  type       TEXT NOT NULL,
  payload    TEXT NOT NULL,
  prev_hash  TEXT NOT NULL,
  hash       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (circle_id, seq)
) STRICT;

CREATE TRIGGER ledger_no_update BEFORE UPDATE ON ledger
BEGIN
  SELECT RAISE(ABORT, 'ledger is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER ledger_no_delete BEFORE DELETE ON ledger
BEGIN
  SELECT RAISE(ABORT, 'ledger is append-only: DELETE is forbidden');
END;

-- Application-level audit (A8, S6.1): who did what, when, from which
-- request. Also append-only.
CREATE TABLE audit (
  id         INTEGER PRIMARY KEY,
  ts         TEXT NOT NULL,
  actor_id   TEXT,
  circle_id  TEXT,
  action     TEXT NOT NULL,
  target     TEXT,
  request_id TEXT NOT NULL,
  ip_prefix  TEXT NOT NULL,
  ua_hash    TEXT NOT NULL,
  details    TEXT,
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX audit_circle ON audit(circle_id, id);
CREATE INDEX audit_actor ON audit(actor_id, id);

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
BEGIN
  SELECT RAISE(ABORT, 'audit is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
BEGIN
  SELECT RAISE(ABORT, 'audit is append-only: DELETE is forbidden');
END;
