import { useState } from 'preact/hooks';
import { patch, post } from '../api.js';
import { Button, Loading, Ltr, Notice, PasswordField, TextField } from '../components.js';
import { errorText, reportError } from '../errors.js';
import { useApi, useTitle } from '../hooks.js';
import { localDateTime } from '../format.js';
import { t, tx } from '../i18n/index.js';
import { IconLogout } from '../icons.js';
import { session, toast, useStore, type User } from '../store.js';
import type { SessionSummary } from '../types.js';
import { RecoveryCodes, signOut } from './auth.js';

function ProfileCard({ user }: { user: User }) {
  const [name, setName] = useState(user.displayName);
  const [busy, setBusy] = useState(false);
  const save = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await patch<{ user: User }>('/api/auth/me', { displayName: name });
      session.set(r.user);
      toast(t('account.profile.saved'));
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form class="card stack" onSubmit={(e) => void save(e)} aria-labelledby="profile-title">
      <h2 id="profile-title">{t('account.profile')}</h2>
      <TextField label={t('auth.displayName')} hint={t('auth.displayName.hint')} value={name} onInput={setName} autocomplete="name" dir="auto" maxLength={60} name="displayName" />
      <div>
        <Button type="submit" variant="primary" busy={busy} disabled={name.trim() === '' || name === user.displayName}>
          {t('common.save')}
        </Button>
      </div>
    </form>
  );
}

function PasswordCard({ onChanged }: { onChanged: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post('/api/auth/password', { currentPassword: current, newPassword: next });
      setCurrent('');
      setNext('');
      toast(t('account.password.done'));
      onChanged();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form class="card stack" onSubmit={(e) => void submit(e)} aria-labelledby="password-title">
      <div>
        <h2 id="password-title">{t('account.password')}</h2>
        <p class="muted small">{t('account.password.lead')}</p>
      </div>
      {error ? (
        <Notice tone="danger" role="alert">
          {errorText(error)}
        </Notice>
      ) : null}
      <PasswordField label={t('auth.passwordCurrent')} value={current} onInput={setCurrent} autocomplete="current-password" name="currentPassword" />
      <PasswordField label={t('auth.passwordNew')} hint={t('auth.password.hint')} value={next} onInput={setNext} autocomplete="new-password" showStrength name="newPassword" />
      <div>
        <Button type="submit" variant="primary" busy={busy} disabled={!current || !next}>
          {t('account.password.submit')}
        </Button>
      </div>
    </form>
  );
}

function CodesCard({ user, remaining, onChanged }: { user: User; remaining: number; onChanged: () => void }) {
  const [password, setPassword] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ recoveryCodes: string[] }>('/api/auth/recovery-codes', { password });
      setPassword('');
      setCodes(r.recoveryCodes);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  if (codes) {
    return (
      <RecoveryCodes
        codes={codes}
        login={user.login}
        doneLabel={t('common.close')}
        onDone={() => {
          setCodes(null);
          onChanged();
        }}
      />
    );
  }
  return (
    <form class="card stack" onSubmit={(e) => void submit(e)} aria-labelledby="codes-card-title">
      <div>
        <h2 id="codes-card-title">{t('account.codes')}</h2>
        <p data-testid="codes-remaining">{t('account.codes.remaining', { n: remaining })}</p>
        <p class="muted small">{t('account.codes.lead')}</p>
      </div>
      {error ? (
        <Notice tone="danger" role="alert">
          {errorText(error)}
        </Notice>
      ) : null}
      <PasswordField label={t('auth.password')} value={password} onInput={setPassword} autocomplete="current-password" name="codesPassword" />
      <div>
        <Button type="submit" busy={busy} disabled={!password}>
          {t('account.codes.submit')}
        </Button>
      </div>
    </form>
  );
}

/** Remounted (key) after a password change so the list is fetched again. */
function SessionsCard() {
  const sessions = useApi<{ sessions: SessionSummary[] }>('/api/auth/sessions');
  const revoke = async (s: SessionSummary) => {
    try {
      await post(`/api/auth/sessions/${encodeURIComponent(s.id)}/revoke`);
      if (s.current) {
        await signOut();
        return;
      }
      await sessions.reload();
    } catch (err) {
      reportError(err);
    }
  };
  return (
    <section class="card stack" aria-labelledby="sessions-title">
      <div>
        <h2 id="sessions-title">{t('account.sessions')}</h2>
        <p class="muted small">{t('account.sessions.lead')}</p>
      </div>
      {sessions.loading && !sessions.data ? <Loading /> : null}
      {sessions.data ? (
        <ul class="list" data-testid="sessions">
          {sessions.data.sessions.map((s) => (
            <li key={s.id} class="row-between">
              <div>
                <div class="row">
                  <strong>{tx('account.sessions.started', { date: <Ltr>{localDateTime(s.createdAt)}</Ltr> })}</strong>
                  {s.current ? <span class="chip chip-accent chip-plain">{t('account.sessions.current')}</span> : null}
                </div>
                <div class="muted small">{tx('account.sessions.lastSeen', { date: <Ltr>{localDateTime(s.lastSeenAt)}</Ltr> })}</div>
              </div>
              <Button small onClick={() => void revoke(s)}>
                {t('account.sessions.revoke')}
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
      <div class="stack-s">
        <Button variant="danger" onClick={() => void signOut('/api/auth/logout-all')} data-testid="signout-everywhere">
          <IconLogout />
          {t('account.sessions.everywhere')}
        </Button>
        <p class="muted xsmall">{t('account.sessions.everywhere.lead')}</p>
      </div>
    </section>
  );
}

export function Account() {
  useTitle(t('account.title'));
  const user = useStore(session) as User;
  const me = useApi<{ user: User; recoveryCodesRemaining: number }>('/api/auth/me');
  const [version, setVersion] = useState(0);
  const refresh = () => {
    setVersion((v) => v + 1);
    void me.reload();
  };
  return (
    <div class="stack">
      <div class="page-head row-between">
        <div>
          <h1>{t('account.title')}</h1>
          <p class="muted">{tx('account.signedInAs', { login: <Ltr>{user.login}</Ltr> })}</p>
        </div>
        <Button onClick={() => void signOut()} data-testid="signout">
          <IconLogout />
          {t('account.signout')}
        </Button>
      </div>
      <ProfileCard user={user} />
      <PasswordCard onChanged={refresh} />
      <CodesCard user={user} remaining={me.data?.recoveryCodesRemaining ?? 0} onChanged={refresh} />
      <SessionsCard key={version} />
    </div>
  );
}
