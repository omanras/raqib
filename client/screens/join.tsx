import { useState } from 'preact/hooks';
import { post } from '../api.js';
import { Button, EmptyState, Link, LinkButton, Loading, Notice, TextField } from '../components.js';
import { everyText, scheduleText } from '../describe.js';
import { errorText, reportError } from '../errors.js';
import { localDate, money } from '../format.js';
import { useApi, useTitle } from '../hooks.js';
import { t, useLang } from '../i18n/index.js';
import { IconMail } from '../icons.js';
import { navigate } from '../router.js';
import { session, toast, useStore } from '../store.js';
import type { CircleJson } from '../types.js';

interface Preview {
  circle: CircleJson;
  organizerName: string;
  invite: { expiresAt: string };
  alreadyMember: boolean;
}

function Signed({ token }: { token: string }) {
  const preview = useApi<Preview>(`/api/invites/${encodeURIComponent(token)}`);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  if (preview.loading && !preview.data) return <Loading />;
  if (preview.error || !preview.data) {
    if (preview.error?.offline) return <Notice tone="warn">{errorText(preview.error)}</Notice>;
    return <EmptyState icon={<IconMail />} title={t('join.invalid.title')} text={t('join.invalid.text')} action={<LinkButton href="/circles">{t('circle.back')}</LinkButton>} />;
  }
  const { circle, organizerName, invite, alreadyMember } = preview.data;
  const accept = async () => {
    setBusy(true);
    try {
      const r = await post<{ circleId: string }>(`/api/invites/${encodeURIComponent(token)}/accept`, name.trim() ? { displayName: name } : {});
      toast(t('join.joined'));
      navigate(`/circles/${r.circleId}`, { replace: true });
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card stack" data-testid="join-preview">
      <div>
        <h2 dir="auto" data-testid="join-circle-name">
          {circle.name}
        </h2>
        <p class="muted" dir="auto">
          {t('join.organizer', { name: organizerName })}
        </p>
      </div>
      <dl class="kv">
        <dt>{t('join.contribution')}</dt>
        <dd>
          <span class="amount ltr">{money(circle.contribution, circle.currency)}</span> {everyText(circle.period)}
        </dd>
        <dt>{t('join.schedule')}</dt>
        <dd>{scheduleText(circle.period, circle.dueDay)}</dd>
        <dt>{t('join.start')}</dt>
        <dd class="ltr">{circle.startDate ?? t('join.startUnset')}</dd>
        <dt>{t('join.members')}</dt>
        <dd>{circle.memberCount}</dd>
      </dl>
      <div>
        <h3>{t('join.rules')}</h3>
        <p class="pre-wrap" dir="auto">
          {circle.rulesText || t('join.noRules')}
        </p>
      </div>
      {alreadyMember ? (
        <Notice tone="ok">
          {t('join.already')}{' '}
          <Link href={`/circles/${circle.id}`}>{t('join.open')}</Link>
        </Notice>
      ) : (
        <>
          <p class="muted small">{t('join.expires', { date: localDate(invite.expiresAt) })}</p>
          <TextField label={t('join.myName')} hint={t('create.myName.hint')} value={name} onInput={setName} optional dir="auto" maxLength={60} name="displayName" />
          <Button variant="primary" block busy={busy} onClick={() => void accept()}>
            {t('join.accept')}
          </Button>
        </>
      )}
    </section>
  );
}

export function Join({ token }: { token: string }) {
  useTitle(t('join.title'));
  useLang();
  const user = useStore(session);
  const next = encodeURIComponent(`/join/${token}`);
  return (
    <div class="auth-wrap">
      <div class="page-head">
        <h1>{t('join.title')}</h1>
      </div>
      {user ? (
        <Signed token={token} />
      ) : (
        <section class="card stack">
          <p>{t('join.signinFirst')}</p>
          <div class="row">
            <LinkButton href={`/signup?next=${next}`} variant="primary">
              {t('auth.signin.toSignup')}
            </LinkButton>
            <LinkButton href={`/signin?next=${next}`}>{t('auth.signin.title')}</LinkButton>
          </div>
        </section>
      )}
    </div>
  );
}
