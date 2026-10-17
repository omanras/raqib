import { useEffect, useState } from 'preact/hooks';
import { post } from '../../api.js';
import { Button, CopyButton, LinkButton, Loading, Ltr, Money, Notice } from '../../components.js';
import { codeText, errorText, reportError } from '../../errors.js';
import { money } from '../../format.js';
import { useApi } from '../../hooks.js';
import { t, tx } from '../../i18n/index.js';
import { toast } from '../../store.js';
import type { CircleView, OverviewJson, OverviewRoundJson } from '../../types.js';
import { RoundStatusChip, StateChip, dueText, stateText } from './common.js';
import { ReportForm } from './rounds.js';
import type { CircleProps } from './shell.js';

/** The plain-text summary for a messaging app ("share this round"). */
export function shareText(o: OverviewJson, round: OverviewRoundJson): string {
  const cur = o.circle.currency;
  return [
    t('share.title', { circle: o.circle.name, n: round.n, total: round.of }),
    t('share.recipient', { name: round.recipient.displayName }),
    t('share.due', { date: `${round.dueDate} (${dueText(round.daysUntilDue)})` }),
    t('share.pot', { confirmed: money(round.confirmed, cur), expected: money(round.expected, cur) }),
    ...round.members.map((m) => t('share.line', { name: m.displayName, state: stateText(m.state, m.ageDays) })),
    '',
    t('share.footer'),
  ].join('\n');
}

function Setup({ view }: { view: CircleView }) {
  const { circle, me, startCheck } = view;
  const base = `/circles/${circle.id}`;
  if (me.role !== 'organizer') {
    return <Notice>{circle.status === 'drawing' ? t('overview.drawing') : t('overview.waiting')}</Notice>;
  }
  return (
    <section class="card stack" data-testid="setup">
      <div>
        <h2>{t('overview.setup.title')}</h2>
        <p class="muted">{t('overview.setup.lead')}</p>
      </div>
      <p>{t('overview.setup.members', { n: view.members.length })}</p>
      {startCheck.ok ? (
        <Notice tone="ok">{t('overview.setup.ready')}</Notice>
      ) : (
        <Notice tone="warn">{codeText(startCheck.code, startCheck.reason)}</Notice>
      )}
      <div class="row">
        {circle.status === 'draft' ? (
          <LinkButton href={`${base}/members`} variant="primary">
            {t('overview.setup.invite')}
          </LinkButton>
        ) : null}
        <LinkButton href={`${base}/members`}>{t('overview.setup.order')}</LinkButton>
        <LinkButton href={`${base}/settings`}>{t('overview.setup.settings')}</LinkButton>
      </div>
    </section>
  );
}

function RoundCard({ o, view, onChanged }: { o: OverviewJson; view: CircleView; onChanged: () => void }) {
  const round = o.round as OverviewRoundJson;
  const cur = o.circle.currency;
  const [reporting, setReporting] = useState(false);
  const [busy, setBusy] = useState(false);
  const pct = round.expected > 0 ? Math.min(100, Math.round((round.confirmed * 100) / round.expected)) : 0;
  const pending = round.reported - round.confirmed;
  const ack = async () => {
    setBusy(true);
    try {
      await post(`/api/circles/${o.circle.id}/rounds/${round.n}/payout/ack`);
      toast(t('payout.ack.done'));
      onChanged();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card stack" data-testid="round-card">
      <div class="row-between">
        <h2 data-testid="round-heading">{t('overview.round', { n: round.n, total: round.of })}</h2>
        <RoundStatusChip status={round.status} />
      </div>
      <div class="grid-2">
        <div class="stat">
          <span class="stat-label">{o.me.isRecipient ? t('overview.youReceive') : t('overview.recipient')}</span>
          <span class="stat-value" dir="auto" data-testid="recipient">
            {round.recipient.displayName}
          </span>
        </div>
        <div class="stat">
          <span class="stat-label">{tx('overview.due', { date: <Ltr>{round.dueDate}</Ltr> })}</span>
          <span class={`stat-value ${round.daysUntilDue < 0 && round.status === 'open' ? 'text-danger' : ''}`} data-testid="due-text">
            {dueText(round.daysUntilDue)}
          </span>
        </div>
      </div>
      <div class="stack-s">
        <div class="row-between">
          <span class="stat-label">{t('overview.pot')}</span>
          <span data-testid="pot">
            {tx('overview.confirmedOf', { confirmed: <Money amount={round.confirmed} currency={cur} />, expected: <Money amount={round.expected} currency={cur} /> })}
          </span>
        </div>
        <div class="progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
          <span style={{ width: `${pct}%` }} />
        </div>
        {pending > 0 ? <span class="muted small">{tx('overview.reportedWaiting', { amount: <Money amount={pending} currency={cur} /> })}</span> : null}
      </div>
      <div class="stack-s" data-testid="payout-line">
        {round.payout ? (
          <>
            <span>{tx('overview.payout.recorded', { amount: <Money amount={round.payout.amount} currency={cur} />, date: <Ltr>{round.payout.paidOn}</Ltr> })}</span>
            <span class="muted small">{round.payout.acknowledgedSeq ? t('overview.payout.acknowledged') : t('overview.payout.waiting')}</span>
          </>
        ) : (
          <span class="muted small">{t('overview.payout.none')}</span>
        )}
      </div>
      <div class="row">
        {o.me.canReport && o.me.line && !reporting ? (
          <Button variant="primary" onClick={() => setReporting(true)} data-testid="report-my-payment">
            {t('overview.report')}
          </Button>
        ) : null}
        {o.me.isRecipient && round.payout && !round.payout.acknowledgedSeq ? (
          <Button variant="primary" busy={busy} onClick={() => void ack()} data-testid="ack-payout">
            {t('payout.ack')}
          </Button>
        ) : null}
        <CopyButton text={shareText(o, round)} label={t('overview.share')} testId="share-round" />
        <LinkButton href={`/circles/${o.circle.id}/rounds/${round.n}`}>{t('overview.openRound')}</LinkButton>
      </div>
      {reporting && o.me.line ? (
        <ReportForm
          circleId={o.circle.id}
          currency={cur}
          roundN={round.n}
          line={o.me.line}
          onDone={() => {
            setReporting(false);
            onChanged();
          }}
          onCancel={() => setReporting(false)}
        />
      ) : null}
      <div>
        <h3>{t('overview.membersThisRound')}</h3>
        <ul class="list" data-testid="overview-members">
          {round.members.map((m) => (
            <li key={m.memberId} class="row-between" data-testid="overview-member" data-member={m.memberId}>
              <span dir="auto">
                {m.displayName}
                {m.memberId === view.me.memberId ? <span class="muted small"> ({t('circle.you')})</span> : null}
              </span>
              <StateChip state={m.state} ageDays={m.ageDays} />
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

export function Overview({ view, version, changed }: CircleProps) {
  const overview = useApi<OverviewJson>(`/api/circles/${view.circle.id}/overview`);
  useEffect(() => {
    if (version > 0) void overview.reload();
  }, [version]);
  const status = view.circle.status;
  if (status === 'draft' || status === 'drawing') return <Setup view={view} />;
  if (status === 'cancelled') return <Notice tone="danger">{t('overview.cancelled')}</Notice>;
  if (overview.loading && !overview.data) return <Loading />;
  if (!overview.data) return <Notice tone="danger">{errorText(overview.error)}</Notice>;
  const o = overview.data;
  const onChanged = () => {
    changed();
    void overview.reload();
  };
  return (
    <div class="stack">
      {status === 'completed' ? <Notice tone="ok">{t('overview.completed')}</Notice> : null}
      {o.round ? <RoundCard o={o} view={view} onChanged={onChanged} /> : <Notice>{t('overview.noRoundOpen')}</Notice>}
      {o.arrears.length > 0 ? (
        <section class="card stack" data-testid="arrears">
          <h2>{t('overview.arrears')}</h2>
          <ul class="list">
            {o.arrears.map((a) => (
              <li key={`${a.roundN}:${a.memberId}`} class="row-between">
                <span dir="auto">{a.displayName}</span>
                <span class="row">
                  <span class="muted small">{tx('overview.arrears.line', { n: a.roundN, amount: <Money amount={a.outstanding} currency={o.circle.currency} /> })}</span>
                  <StateChip state={a.state} ageDays={a.ageDays} />
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
