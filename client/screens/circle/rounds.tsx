import { useEffect, useState } from 'preact/hooks';
import { post } from '../../api.js';
import { Button, EmptyState, Link, Loading, Ltr, Money, Notice, TextArea, TextField } from '../../components.js';
import { errorText, reportError } from '../../errors.js';
import { money, todayUtc } from '../../format.js';
import { useApi } from '../../hooks.js';
import { t, tx } from '../../i18n/index.js';
import { IconBack, IconCircles } from '../../icons.js';
import { toast } from '../../store.js';
import type { CircleView, LineJson, PayoutJson, StatementJson, StatementRoundJson } from '../../types.js';
import { useAmount } from '../circles.js';
import { AmountField, RoundStatusChip, StateChip, TwoStep, amountText } from './common.js';
import type { CircleProps } from './shell.js';

const nameOf = (view: CircleView, memberId: string) => view.members.find((m) => m.id === memberId)?.displayName ?? '';

/** Report (member, for self) or record (organizer, for anyone) a payment; partial amounts are fine. */
export function ReportForm(props: {
  circleId: string;
  currency: string;
  roundN: number;
  line: LineJson;
  forName?: string;
  onDone: () => void;
  onCancel?: () => void;
}) {
  const remaining = Math.max(0, props.line.expected - props.line.reported);
  const [text, setText] = useState(amountText(remaining, props.currency));
  const [method, setMethod] = useState('');
  const [reference, setReference] = useState('');
  const [busy, setBusy] = useState(false);
  const amount = useAmount(text, props.currency);
  const submit = async (e: Event) => {
    e.preventDefault();
    if (amount.value === null) return;
    setBusy(true);
    try {
      const body: Record<string, unknown> = { amount: amount.value, method, reference };
      if (props.forName !== undefined) body.memberId = props.line.memberId;
      await post(`/api/circles/${props.circleId}/rounds/${props.roundN}/contributions`, body);
      toast(t('report.done'));
      props.onDone();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form class="card stack" onSubmit={(e) => void submit(e)} data-testid="report-form">
      <h3>{props.forName !== undefined ? t('report.titleFor', { name: props.forName }) : t('report.title')}</h3>
      <AmountField label={t('report.amount')} name="amount" currency={props.currency} text={text} onText={setText} hint={tx('report.amount.hint', { amount: <Money amount={remaining} currency={props.currency} /> })} />
      <div class="grid-2">
        <TextField label={t('report.method')} name="method" hint={t('report.method.hint')} value={method} onInput={setMethod} optional maxLength={120} dir="auto" />
        <TextField label={t('report.reference')} name="reference" hint={t('report.reference.hint')} value={reference} onInput={setReference} optional maxLength={120} dir="auto" />
      </div>
      <div class="row">
        <Button type="submit" variant="primary" busy={busy} disabled={amount.value === null}>
          {t('report.submit')}
        </Button>
        {props.onCancel ? (
          <Button variant="ghost" onClick={props.onCancel}>
            {t('common.cancel')}
          </Button>
        ) : null}
      </div>
    </form>
  );
}

export function PayoutStatus({ payout, currency, confirmedPot }: { payout: PayoutJson | null; currency: string; confirmedPot?: number }) {
  if (!payout) return <p class="muted">{t('payout.none')}</p>;
  return (
    <div class="stack-s" data-testid="payout-status">
      <p>{tx('payout.recorded', { amount: <Money amount={payout.amount} currency={currency} />, date: <Ltr>{payout.paidOn}</Ltr> })}</p>
      {confirmedPot !== undefined && confirmedPot !== payout.amount ? (
        <p class="muted small">{tx('payout.difference', { pot: <Money amount={confirmedPot} currency={currency} /> })}</p>
      ) : null}
      {payout.acknowledgedSeq ? <Notice tone="ok">{t('payout.acked')}</Notice> : <Notice tone="warn">{t('payout.notAcked')}</Notice>}
    </div>
  );
}

function PayoutCard({ view, round, onDone }: { view: CircleView; round: StatementRoundJson; onDone: () => void }) {
  const { circle, me } = view;
  const isOrganizer = me.role === 'organizer';
  const isRecipient = me.memberId === round.recipientMemberId;
  const [text, setText] = useState(round.confirmed > 0 ? amountText(round.confirmed, circle.currency) : '');
  const [paidOn, setPaidOn] = useState(todayUtc());
  const [method, setMethod] = useState('');
  const [reference, setReference] = useState('');
  const [busy, setBusy] = useState(false);
  const amount = useAmount(text, circle.currency);
  const record = async (e: Event) => {
    e.preventDefault();
    if (amount.value === null) return;
    setBusy(true);
    try {
      await post(`/api/circles/${circle.id}/rounds/${round.n}/payout`, { amount: amount.value, paidOn, method, reference });
      toast(t('payout.done'));
      onDone();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  const ack = async () => {
    setBusy(true);
    try {
      await post(`/api/circles/${circle.id}/rounds/${round.n}/payout/ack`);
      toast(t('payout.ack.done'));
      onDone();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card stack" aria-labelledby="payout-title" data-testid="payout-card">
      <h2 id="payout-title">{t('payout.title')}</h2>
      <PayoutStatus payout={round.payout} currency={circle.currency} confirmedPot={round.confirmed} />
      {round.payout && isRecipient && !round.payout.acknowledgedSeq ? (
        <div>
          <Button variant="primary" busy={busy} onClick={() => void ack()} data-testid="ack-payout">
            {t('payout.ack')}
          </Button>
        </div>
      ) : null}
      {!round.payout && isOrganizer && round.status !== 'upcoming' ? (
        <form class="stack" onSubmit={(e) => void record(e)} data-testid="payout-form">
          <AmountField
            label={t('payout.amount')}
            name="payoutAmount"
            currency={circle.currency}
            text={text}
            onText={setText}
            hint={tx('payout.amount.hint', { pot: <Money amount={round.confirmed} currency={circle.currency} /> })}
          />
          <div class="grid-2">
            <TextField label={t('payout.paidOn')} name="paidOn" type="date" value={paidOn} onInput={setPaidOn} dir="ltr" />
            <TextField label={t('payout.method')} name="payoutMethod" value={method} onInput={setMethod} optional maxLength={120} dir="auto" />
          </div>
          <TextField label={t('payout.reference')} name="payoutReference" value={reference} onInput={setReference} optional maxLength={120} dir="auto" />
          <div>
            <Button type="submit" variant="primary" busy={busy} disabled={amount.value === null}>
              {t('payout.submit')}
            </Button>
          </div>
        </form>
      ) : null}
    </section>
  );
}

function WaiveForm({ circleId, roundN, line, onDone, onCancel }: { circleId: string; roundN: number; line: LineJson; onDone: () => void; onCancel: () => void }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    try {
      await post(`/api/circles/${circleId}/rounds/${roundN}/contributions/${line.contributionId}/waive`, { reason });
      toast(t('round.waive.done'));
      onDone();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form class="stack-s" onSubmit={(e) => void submit(e)} data-testid="waive-form">
      <TextArea label={t('round.waive.reason')} name="reason" hint={t('round.waive.reason.hint')} value={reason} onInput={setReason} maxLength={500} />
      <div class="row">
        <Button type="submit" variant="danger" busy={busy} disabled={reason.trim() === ''}>
          {t('round.waive.submit')}
        </Button>
        <Button variant="ghost" onClick={onCancel}>
          {t('common.cancel')}
        </Button>
      </div>
    </form>
  );
}

function LineRow({ view, round, line, onDone }: { view: CircleView; round: StatementRoundJson; line: LineJson; onDone: () => void }) {
  const { circle, me } = view;
  const [mode, setMode] = useState<'none' | 'report' | 'waive'>('none');
  const [busy, setBusy] = useState(false);
  const isOrganizer = me.role === 'organizer';
  const mine = line.memberId === me.memberId;
  const due = round.status !== 'upcoming';
  const pending = line.reports.filter((r) => r.confirmedSeq === null);
  const canReport = due && line.state !== 'waived' && line.reported < line.expected && (mine || isOrganizer);
  const done = () => {
    setMode('none');
    onDone();
  };
  const confirm = async () => {
    setBusy(true);
    try {
      await post(`/api/circles/${circle.id}/rounds/${round.n}/contributions/${line.contributionId}/confirm`);
      toast(t('round.confirm.done'));
      onDone();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  const name = nameOf(view, line.memberId);
  return (
    <li class="stack-s" data-testid="line" data-member={line.memberId}>
      <div class="row-between">
        <div class="stack-s">
          <strong dir="auto" data-testid="line-name">
            {name}
            {mine ? <span class="muted small"> ({t('circle.you')})</span> : null}
          </strong>
          <div class="row">
            <StateChip state={line.state} ageDays={line.ageDays} />
            <span class="muted small ltr">
              {money(line.confirmed, circle.currency)} / {money(line.expected, circle.currency)}
            </span>
          </div>
        </div>
        <div class="row">
          {isOrganizer && due && pending.length > 0 ? (
            <Button small variant="primary" busy={busy} onClick={() => void confirm()} data-testid="confirm">
              {t('round.confirm')}
            </Button>
          ) : null}
          {canReport && mode === 'none' ? (
            <Button small onClick={() => setMode('report')} data-testid={mine ? 'report-mine' : 'record-for'}>
              {mine ? t('round.report') : t('round.recordFor')}
            </Button>
          ) : null}
          {isOrganizer && due && line.state !== 'waived' && line.state !== 'confirmed' && mode === 'none' ? (
            <Button small variant="ghost" onClick={() => setMode('waive')} data-testid="waive">
              {t('round.waive')}
            </Button>
          ) : null}
        </div>
      </div>
      {line.reports.length > 0 ? (
        <ul class="xsmall muted" data-testid="reports">
          {line.reports.map((r) => (
            <li key={r.reportId} dir="auto">
              <span class="ltr">{money(r.amount, circle.currency)}</span>
              {r.method ? ` · ${r.method}` : ''}
              {r.reference ? ` · ${r.reference}` : ''}
              {r.confirmedSeq === null ? ` · ${t('round.pendingConfirmation')}` : ''}
            </li>
          ))}
        </ul>
      ) : null}
      {line.waiveReason ? (
        <p class="xsmall muted pre-wrap" dir="auto">
          {line.waiveReason}
        </p>
      ) : null}
      {mode === 'report' ? (
        <ReportForm circleId={circle.id} currency={circle.currency} roundN={round.n} line={line} forName={mine ? undefined : name} onDone={done} onCancel={() => setMode('none')} />
      ) : null}
      {mode === 'waive' ? <WaiveForm circleId={circle.id} roundN={round.n} line={line} onDone={done} onCancel={() => setMode('none')} /> : null}
    </li>
  );
}

export function RoundPage({ view, version, changed, n }: CircleProps & { n: number }) {
  const statement = useApi<StatementJson>(`/api/circles/${view.circle.id}/statement`);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (version > 0) void statement.reload();
  }, [version]);
  const { circle, me } = view;
  if (statement.loading && !statement.data) return <Loading />;
  if (!statement.data) return <Notice tone="danger">{errorText(statement.error)}</Notice>;
  const round = statement.data.statement.rounds.find((r) => r.n === n);
  if (!round) return <Notice tone="warn">{t('error.no_such_round')}</Notice>;
  const refresh = () => {
    changed();
    void statement.reload();
  };
  const act = async (path: 'open' | 'close') => {
    setBusy(true);
    try {
      await post(`/api/circles/${circle.id}/rounds/${n}/${path}`);
      toast(t(path === 'open' ? 'round.opened' : 'round.closed'));
      refresh();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  const outstandingCount = round.lines.filter((l) => l.outstanding > 0).length;
  const isOrganizer = me.role === 'organizer';
  const running = circle.status === 'active';
  return (
    <div class="stack">
      <Link href={`/circles/${circle.id}/rounds`} class="muted small row">
        <IconBack class="small-icon" />
        {t('round.back')}
      </Link>
      <section class="card stack" data-testid="round-page">
        <div class="row-between">
          <h2>{t('round.title', { n })}</h2>
          <RoundStatusChip status={round.status} />
        </div>
        <dl class="kv">
          <dt>{t('round.recipient')}</dt>
          <dd dir="auto">{nameOf(view, round.recipientMemberId)}</dd>
          <dt>{t('round.due')}</dt>
          <dd class="ltr">{round.dueDate}</dd>
        </dl>
        <p class="muted small" data-testid="round-totals">
          {tx('round.totals', {
            expected: <Money amount={round.expected} currency={circle.currency} />,
            confirmed: <Money amount={round.confirmed} currency={circle.currency} />,
            outstanding: <Money amount={round.outstanding} currency={circle.currency} />,
          })}
        </p>
        {isOrganizer && running && round.status === 'upcoming' ? (
          <div>
            <Button variant="primary" busy={busy} onClick={() => void act('open')} data-testid="open-round">
              {t('round.open')}
            </Button>
          </div>
        ) : null}
        {isOrganizer && running && round.status === 'open' ? (
          outstandingCount > 0 ? (
            <TwoStep first={t('round.close')} confirm={t('round.close.yes')} busy={busy} onConfirm={() => void act('close')} testId="close-round">
              <Notice tone="warn">{t('round.close.confirm', { n: outstandingCount })}</Notice>
            </TwoStep>
          ) : (
            <div>
              <Button busy={busy} onClick={() => void act('close')} data-testid="close-round">
                {t('round.close')}
              </Button>
            </div>
          )
        ) : null}
      </section>
      <section class="card stack" aria-labelledby="contributions-title">
        <h2 id="contributions-title">{t('round.contributions')}</h2>
        <ul class="list" data-testid="lines">
          {round.lines.map((line) => (
            <LineRow key={line.memberId} view={view} round={round} line={line} onDone={refresh} />
          ))}
        </ul>
      </section>
      <PayoutCard key={`payout-${round.confirmed}-${round.payout?.seq ?? 0}`} view={view} round={round} onDone={refresh} />
    </div>
  );
}

export function RoundsList({ view, version }: CircleProps) {
  const statement = useApi<StatementJson>(view.rounds.length ? `/api/circles/${view.circle.id}/statement` : null);
  const { circle } = view;
  if (view.rounds.length === 0) return <EmptyState icon={<IconCircles />} title={t('rounds.title')} text={t('rounds.empty')} />;
  if (statement.loading && !statement.data) return <Loading />;
  const byN = new Map((statement.data?.statement.rounds ?? []).map((r) => [r.n, r]));
  return (
    <div class="stack" data-version={version}>
      <div class="page-head">
        <h2>{t('rounds.title')}</h2>
        <p class="muted">{t('rounds.lead')}</p>
      </div>
      <ul class="list stack" data-testid="rounds">
        {view.rounds.map((r) => {
          const s = byN.get(r.n);
          const pct = s && s.expected > 0 ? Math.round((s.confirmed * 100) / s.expected) : 0;
          return (
            <li key={r.n}>
              <Link href={`/circles/${circle.id}/rounds/${r.n}`} class="card card-link card-tight stack-s">
                <div class="row-between">
                  <strong>{t('round.title', { n: r.n })}</strong>
                  <RoundStatusChip status={r.status} />
                </div>
                <div class="row-between muted small">
                  <span dir="auto">{t('rounds.recipient', { name: nameOf(view, r.recipientMemberId) })}</span>
                  <span class="ltr">{r.dueDate}</span>
                </div>
                {s && r.status !== 'upcoming' ? (
                  <>
                    <div class="progress" aria-hidden="true">
                      <span style={{ width: `${Math.min(100, pct)}%` }} />
                    </div>
                    <span class="xsmall muted">
                      {tx('overview.confirmedOf', { confirmed: <Money amount={s.confirmed} currency={circle.currency} />, expected: <Money amount={s.expected} currency={circle.currency} /> })}
                    </span>
                  </>
                ) : null}
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
