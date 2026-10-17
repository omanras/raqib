import { useEffect, useState } from 'preact/hooks';
import { post } from '../../api.js';
import { Button, Chip, CopyButton, LinkButton, Ltr, Notice, RoleChip, type Tone } from '../../components.js';
import { codeText, reportError } from '../../errors.js';
import { localDate } from '../../format.js';
import { useApi } from '../../hooks.js';
import { t, tx, type MessageKeyOf } from '../../i18n/index.js';
import { IconMail } from '../../icons.js';
import { navigate } from '../../router.js';
import { toast } from '../../store.js';
import type { CircleView, InviteJson, MemberJson } from '../../types.js';
import { TwoStep } from './common.js';
import type { CircleProps } from './shell.js';

const INVITE_TONE: Record<InviteJson['status'], Tone> = { active: 'accent', accepted: 'ok', revoked: 'neutral', expired: 'neutral' };

function Invites({ view, version }: { view: CircleView; version: number }) {
  const list = useApi<{ invites: InviteJson[] }>(`/api/circles/${view.circle.id}/invites`);
  const [link, setLink] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (version > 0) void list.reload();
  }, [version]);
  const create = async () => {
    setBusy(true);
    try {
      const r = await post<{ link: string }>(`/api/circles/${view.circle.id}/invites`);
      setLink(r.link);
      void list.reload();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  const revoke = async (id: string) => {
    try {
      await post(`/api/circles/${view.circle.id}/invites/${id}/revoke`);
      toast(t('invite.revoked'));
      void list.reload();
    } catch (err) {
      reportError(err);
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
      <div>
        <h3>{t('invite.list')}</h3>
        {list.data && list.data.invites.length === 0 ? <p class="muted small">{t('invite.none')}</p> : null}
        <ul class="list" data-testid="invites">
          {(list.data?.invites ?? []).map((i) => (
            <li key={i.id} class="row-between">
              <span class="row">
                <Chip tone={INVITE_TONE[i.status]}>{t(`invite.status.${i.status}` as MessageKeyOf<'invite.status'>)}</Chip>
                <span class="muted small">{tx('invite.expires', { date: <Ltr>{localDate(i.expiresAt)}</Ltr> })}</span>
              </span>
              {i.status === 'active' ? (
                <Button small variant="ghost" onClick={() => void revoke(i.id)} data-testid="revoke-invite">
                  {t('invite.revoke')}
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/** Manual order with up/down buttons (keyboard and screen-reader friendly, works on phones). */
function OrderEditor({ view, onSaved }: { view: CircleView; onSaved: () => void }) {
  const initial = [...view.members].sort((a, b) => (a.position ?? 1e9) - (b.position ?? 1e9));
  const [order, setOrder] = useState<MemberJson[]>(initial);
  const [busy, setBusy] = useState(false);
  const move = (i: number, d: -1 | 1) => {
    const j = i + d;
    if (j < 0 || j >= order.length) return;
    const next = [...order];
    [next[i], next[j]] = [next[j] as MemberJson, next[i] as MemberJson];
    setOrder(next);
  };
  const save = async () => {
    setBusy(true);
    try {
      await post(`/api/circles/${view.circle.id}/order`, { order: order.map((m) => m.id) });
      toast(t('members.order.saved'));
      onSaved();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card stack" aria-labelledby="order-title" data-testid="order-editor">
      <div>
        <h2 id="order-title">{t('members.order.title')}</h2>
        <p class="muted small">{t('members.order.lead')}</p>
      </div>
      <ol class="list" data-testid="order-list">
        {order.map((m, i) => (
          <li key={m.id} class="row-between" data-testid="order-item">
            <span class="row">
              <span class="chip chip-plain">{t('circle.position', { n: i + 1 })}</span>
              <span dir="auto">{m.displayName}</span>
            </span>
            <span class="row">
              <Button small variant="ghost" aria-label={t('members.order.up', { name: m.displayName })} disabled={i === 0} onClick={() => move(i, -1)}>
                ↑
              </Button>
              <Button small variant="ghost" aria-label={t('members.order.down', { name: m.displayName })} disabled={i === order.length - 1} onClick={() => move(i, 1)}>
                ↓
              </Button>
            </span>
          </li>
        ))}
      </ol>
      <div class="row">
        <Button variant="primary" busy={busy} onClick={() => void save()} data-testid="save-order">
          {t('members.order.save')}
        </Button>
        <LinkButton href={`/circles/${view.circle.id}/draw`}>{t('members.order.toDraw')}</LinkButton>
      </div>
    </section>
  );
}

function StartCard({ view, onStarted }: { view: CircleView; onStarted: () => void }) {
  const [busy, setBusy] = useState(false);
  const check = view.startCheck;
  const start = async () => {
    setBusy(true);
    try {
      await post(`/api/circles/${view.circle.id}/start`);
      toast(t('members.start.done'));
      onStarted();
      navigate(`/circles/${view.circle.id}`);
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card stack" aria-labelledby="start-title" data-testid="start-card">
      <div>
        <h2 id="start-title">{t('members.start.title')}</h2>
        <p class="muted small">{t('members.start.lead')}</p>
      </div>
      {check.ok ? (
        <Notice tone="ok">{t('members.start.ready')}</Notice>
      ) : (
        <Notice tone="warn">
          <strong>{t('members.start.blocked')}</strong> <span data-testid="start-reason">{codeText(check.code, check.reason)}</span>
        </Notice>
      )}
      <div>
        <TwoStep first={t('members.start.submit')} confirm={t('members.start.submit')} busy={busy} onConfirm={() => void start()} testId="start-circle">
          <p class="small">{t('members.start.lead')}</p>
        </TwoStep>
      </div>
    </section>
  );
}

export function Members({ view, version, changed }: CircleProps) {
  const { circle, me, members } = view;
  const organizer = me.role === 'organizer';
  const leave = async () => {
    try {
      await post(`/api/circles/${circle.id}/leave`);
      toast(t('members.left'));
      navigate('/circles', { replace: true });
    } catch (err) {
      reportError(err);
    }
  };
  const sorted = [...members].sort((a, b) => (a.position ?? 1e9) - (b.position ?? 1e9));
  return (
    <div class="stack">
      <section class="card stack" aria-labelledby="members-title">
        <div class="row-between">
          <h2 id="members-title">{t('members.title')}</h2>
          <span class="muted small" data-testid="member-count">
            {t('circle.membersCount', { n: members.length })}
          </span>
        </div>
        <p class="muted small">{t('members.lead')}</p>
        <ul class="list" data-testid="members">
          {sorted.map((m) => (
            <li key={m.id} class="row-between">
              <span class="stack-s">
                <span dir="auto" data-testid="member-name">
                  {m.displayName}
                  {m.id === me.memberId ? <span class="muted small"> ({t('circle.you')})</span> : null}
                </span>
                <span class="muted xsmall">{tx('members.joined', { date: <Ltr>{localDate(m.joinedAt)}</Ltr> })}</span>
              </span>
              <span class="row">
                <RoleChip role={m.role} />
                <span class="muted small" data-testid="member-position">
                  {m.position ? t('circle.position', { n: m.position }) : t('circle.noPosition')}
                </span>
              </span>
            </li>
          ))}
        </ul>
      </section>
      {organizer && circle.status === 'draft' ? <Invites view={view} version={version} /> : null}
      {organizer && circle.status === 'draft' ? <OrderEditor key={`order-${version}`} view={view} onSaved={changed} /> : null}
      {organizer && (circle.status === 'draft' || circle.status === 'drawing') ? <StartCard view={view} onStarted={changed} /> : null}
      {!organizer && circle.status === 'draft' ? (
        <section class="card stack">
          <h2>{t('members.leave')}</h2>
          <p class="muted small">{t('members.leave.lead')}</p>
          <TwoStep first={t('members.leave')} confirm={t('members.leave.confirm')} danger onConfirm={() => void leave()} testId="leave" />
        </section>
      ) : null}
    </div>
  );
}
