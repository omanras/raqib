import { useState } from 'preact/hooks';
import { post, setCsrfToken } from '../api.js';
import { Button, Checkbox, CopyButton, Link, Ltr, Notice, PasswordField, TextField, downloadText } from '../components.js';
import { errorText, requestIdOf } from '../errors.js';
import { useTitle } from '../hooks.js';
import { t, tx } from '../i18n/index.js';
import { IconDownload, IconKey, LogoMark } from '../icons.js';
import { navigate } from '../router.js';
import { session, toast, type User } from '../store.js';

/** Where to go after signing in: a same-origin path from ?next=, never another site. */
export function nextPath(): string {
  const next = new URLSearchParams(window.location.search).get('next');
  return next && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/circles';
}

export function withNext(path: string): string {
  const next = new URLSearchParams(window.location.search).get('next');
  return next ? `${path}?next=${encodeURIComponent(next)}` : path;
}

function FormError({ error }: { error: unknown }) {
  if (!error) return null;
  const id = requestIdOf(error);
  return (
    <Notice tone="danger" role="alert">
      <span data-testid="form-error">{errorText(error)}</span>
      {id ? <span class="block xsmall muted">{tx('common.requestId', { id: <Ltr>{id}</Ltr> })}</span> : null}
    </Notice>
  );
}

function AuthHead({ title, lead }: { title: string; lead: string }) {
  return (
    <div class="page-head">
      <LogoMark class="brand-mark" />
      <h1>{title}</h1>
      <p class="muted">{lead}</p>
    </div>
  );
}

export function SignIn() {
  useTitle(t('auth.signin.title'));
  const [login, setLogin] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ user: User }>('/api/auth/login', { login, password });
      session.set(r.user);
      navigate(nextPath(), { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="auth-wrap">
      <AuthHead title={t('auth.signin.title')} lead={t('auth.signin.lead')} />
      <form class="card stack" onSubmit={(e) => void submit(e)} noValidate>
        <FormError error={error} />
        <TextField label={t('auth.login')} name="login" value={login} onInput={setLogin} autocomplete="username" dir="ltr" required maxLength={64} />
        <PasswordField label={t('auth.password')} name="password" value={password} onInput={setPassword} autocomplete="current-password" />
        <Button type="submit" variant="primary" block busy={busy}>
          {t('auth.signin.submit')}
        </Button>
      </form>
      <div class="stack-s">
        <p class="muted small">
          {t('auth.signin.noAccount')} <Link href={withNext('/signup')}>{t('auth.signin.toSignup')}</Link>
        </p>
        <p class="muted small">
          {t('auth.signin.forgot')} <Link href={withNext('/recovery')}>{t('auth.signin.toRecovery')}</Link>
        </p>
      </div>
    </div>
  );
}

/** The eight codes, shown once, with copy and download, and an explicit "I saved them". */
export function RecoveryCodes({ codes, login, onDone, doneLabel }: { codes: string[]; login: string; onDone: () => void; doneLabel?: string }) {
  const [saved, setSaved] = useState(false);
  const text = `${t('codes.fileHeader', { login })}\n\n${codes.join('\n')}\n`;
  return (
    <section class="card stack" aria-labelledby="codes-title" data-testid="recovery-codes">
      <div class="row">
        <IconKey class="brand-mark" />
        <h2 id="codes-title">{t('codes.title')}</h2>
      </div>
      <p class="muted">{t('codes.lead')}</p>
      <ol class="codes">
        {codes.map((c) => (
          <li key={c} data-testid="recovery-code">
            {c}
          </li>
        ))}
      </ol>
      <div class="row">
        <CopyButton text={text} label={t('codes.copyAll')} small />
        <Button small onClick={() => downloadText(`dawr-recovery-codes-${login}.txt`, text)}>
          <IconDownload />
          {t('codes.download')}
        </Button>
      </div>
      <Checkbox label={t('codes.confirm')} checked={saved} onChange={setSaved} name="saved" />
      <Button variant="primary" block disabled={!saved} onClick={onDone}>
        {doneLabel ?? t('codes.continue')}
      </Button>
    </section>
  );
}

export function SignUp() {
  useTitle(t('auth.signup.title'));
  const [login, setLogin] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ user: User; codes: string[] } | null>(null);

  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ user: User; recoveryCodes: string[] }>('/api/auth/signup', { login, displayName, password });
      setCreated({ user: r.user, codes: r.recoveryCodes });
      window.scrollTo(0, 0);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  if (created) {
    return (
      <div class="auth-wrap">
        <RecoveryCodes
          codes={created.codes}
          login={created.user.login}
          onDone={() => {
            session.set(created.user);
            navigate(nextPath(), { replace: true });
          }}
        />
      </div>
    );
  }

  return (
    <div class="auth-wrap">
      <AuthHead title={t('auth.signup.title')} lead={t('auth.signup.lead')} />
      <form class="card stack" onSubmit={(e) => void submit(e)} noValidate>
        <FormError error={error} />
        <TextField label={t('auth.displayName')} name="displayName" hint={t('auth.displayName.hint')} value={displayName} onInput={setDisplayName} autocomplete="name" dir="auto" required maxLength={60} />
        <TextField label={t('auth.login')} name="login" hint={t('auth.login.hint')} value={login} onInput={setLogin} autocomplete="username" dir="ltr" required maxLength={32} />
        <PasswordField label={t('auth.password')} name="password" hint={t('auth.password.hint')} value={password} onInput={setPassword} autocomplete="new-password" showStrength />
        <Button type="submit" variant="primary" block busy={busy}>
          {t('auth.signup.submit')}
        </Button>
      </form>
      <p class="muted small">
        {t('auth.signup.haveAccount')} <Link href={withNext('/signin')}>{t('auth.signin.title')}</Link>
      </p>
    </div>
  );
}

export function Recovery() {
  useTitle(t('auth.recovery.title'));
  const [login, setLogin] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ user: User; recoveryCodesRemaining: number }>('/api/auth/recovery', { login, recoveryCode: code, newPassword: password });
      session.set(r.user);
      toast(t('auth.recovery.done', { n: r.recoveryCodesRemaining }));
      navigate(nextPath(), { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="auth-wrap">
      <AuthHead title={t('auth.recovery.title')} lead={t('auth.recovery.lead')} />
      <form class="card stack" onSubmit={(e) => void submit(e)} noValidate>
        <FormError error={error} />
        <TextField label={t('auth.login')} name="login" value={login} onInput={setLogin} autocomplete="username" dir="ltr" required maxLength={64} />
        <TextField label={t('auth.recovery.code')} name="recoveryCode" hint={t('auth.recovery.code.hint')} value={code} onInput={setCode} autocomplete="one-time-code" dir="ltr" required maxLength={64} class="mono" />
        <PasswordField label={t('auth.passwordNew')} name="newPassword" hint={t('auth.password.hint')} value={password} onInput={setPassword} autocomplete="new-password" showStrength />
        <Button type="submit" variant="primary" block busy={busy}>
          {t('auth.recovery.submit')}
        </Button>
      </form>
      <p class="muted small">
        <Link href={withNext('/signin')}>{t('auth.toSignin')}</Link>
      </p>
    </div>
  );
}

/** Signing out forgets the CSRF token with the session. */
export async function signOut(path: '/api/auth/logout' | '/api/auth/logout-all' = '/api/auth/logout'): Promise<void> {
  try {
    await post(path);
  } finally {
    setCsrfToken(null);
    session.set(null);
    navigate('/signin', { replace: true });
  }
}
