import { useState } from 'preact/hooks';
import { post } from '../api.js';
import { Button, CopyButton, Link, Loading, Notice, RoleChip, StatusChip } from '../components.js';
import { everyText, scheduleText } from '../describe.js';
import { errorText, reportError } from '../errors.js';
import { money } from '../format.js';
import { useApi, useTitle } from '../hooks.js';
import { t, useLang } from '../i18n/index.js';
import { IconBack, IconMail } from '../icons.js';
import type { CircleView } from '../types.js';

function InvitePanel({ circleId }: { circleId: string }) {
  const [link, setLink] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const create = async () => {
    setBusy(true);
    try {
      const r = await post<{ link: string }>(`/api/circles/${circleId}/invites`);
      setLink(r.link);
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card stack" aria-labelledby="invite-title" data-testid="invite-panel">
      <div class="row">
        <IconMail class="brand-mark" />
        <h2 id="invite-title">{t('invite.title')}</h2>
      </div>
      <p class="muted small">{t('invite.lead')}</p>
      {link ? (
        <div class="stack-s">
          <Notice tone="ok">{t('invite.created')}</Notice>
          <div class="link-box">
            <code data-testid="invite-link">{link}</code>
            <CopyButton text={link} small />
          </div>
        </div>
      ) : null}
      <div>
        <Button variant={link ? 'secondary' : 'primary'} busy={busy} onClick={() => void create()} data-testid="create-invite">
          {t('invite.create')}
        </Button>
      </div>
    </section>
  );
}

/** The circle page (M2.1: summary, members, invitations; M2.2 adds the round screens). */
export function CircleHome({ id }: { id: string }) {
  useLang();
  const view = useApi<CircleView>(`/api/circles/${encodeURIComponent(id)}`);
  useTitle(view.data?.circle.name ?? '');
  if (view.loading && !view.data) return <Loading />;
  if (!view.data) return <Notice tone="danger">{errorText(view.error)}</Notice>;
  const { circle, me, members } = view.data;
  return (
    <div class="stack">
      <div class="circle-head">
        <Link href="/circles" class="muted small row">
          <IconBack class="small-icon" />
          {t('circle.back')}
        </Link>
        <h1 dir="auto" data-testid="circle-title">
          {circle.name}
        </h1>
        <div class="row">
          <StatusChip status={circle.status} />
          <RoleChip role={me.role} />
        </div>
      </div>

      <section class="card stack" aria-labelledby="summary-title">
        <h2 id="summary-title">{t('circle.summary')}</h2>
        <dl class="kv">
          <dt>{t('circle.contribution')}</dt>
          <dd>
            <span class="amount ltr">{money(circle.contribution, circle.currency)}</span> {everyText(circle.period)}
          </dd>
          <dt>{t('circle.schedule')}</dt>
          <dd>{scheduleText(circle.period, circle.dueDay)}</dd>
          <dt>{t('circle.start')}</dt>
          <dd class="ltr">{circle.startDate ?? t('join.startUnset')}</dd>
          <dt>{t('circle.pot')}</dt>
          <dd class="amount ltr">{money(circle.pot, circle.currency)}</dd>
        </dl>
        <div>
          <h3>{t('circle.rules')}</h3>
          <p class="pre-wrap" dir="auto">
            {circle.rulesText || t('join.noRules')}
          </p>
        </div>
      </section>

      {me.role === 'organizer' && circle.status === 'draft' ? <InvitePanel circleId={circle.id} /> : null}

      <section class="card stack" aria-labelledby="members-title">
        <div class="row-between">
          <h2 id="members-title">{t('circle.members')}</h2>
          <span class="muted small" data-testid="member-count">
            {t('circle.membersCount', { n: members.length })}
          </span>
        </div>
        <ul class="list" data-testid="members">
          {members.map((m) => (
            <li key={m.id} class="row-between">
              <span dir="auto" data-testid="member-name">
                {m.displayName}
                {m.id === me.memberId ? <span class="muted small"> ({t('circle.you')})</span> : null}
              </span>
              <span class="row">
                <RoleChip role={m.role} />
                <span class="muted small">{m.position ? t('circle.position', { n: m.position }) : t('circle.noPosition')}</span>
              </span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
