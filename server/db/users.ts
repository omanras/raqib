import { newId } from '../crypto.js';
import { stmt, type DB } from './db.js';

export interface UserRow {
  id: string;
  login: string;
  display_name: string;
  password_hash: string;
  password_changed_at: string;
  created_at: string;
}

export interface PublicUser {
  id: string;
  login: string;
  displayName: string;
  createdAt: string;
}

export function publicUser(u: UserRow): PublicUser {
  return { id: u.id, login: u.login, displayName: u.display_name, createdAt: u.created_at };
}

export function findUserByLogin(db: DB, login: string): UserRow | undefined {
  return stmt(db, 'SELECT * FROM users WHERE login = ?').get(login) as UserRow | undefined;
}

export function findUserById(db: DB, id: string): UserRow | undefined {
  return stmt(db, 'SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
}

export function insertUser(db: DB, input: { login: string; displayName: string; passwordHash: string; now: Date }): UserRow {
  const id = newId();
  const ts = input.now.toISOString();
  stmt(
    db,
    `INSERT INTO users (id, login, display_name, password_hash, password_changed_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(id, input.login, input.displayName, input.passwordHash, ts, ts);
  return findUserById(db, id) as UserRow;
}

export function setPassword(db: DB, userId: string, passwordHash: string, now: Date): void {
  stmt(db, 'UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?').run(
    passwordHash,
    now.toISOString(),
    userId,
  );
}

export function setDisplayName(db: DB, userId: string, displayName: string): void {
  stmt(db, 'UPDATE users SET display_name = ? WHERE id = ?').run(displayName, userId);
}
