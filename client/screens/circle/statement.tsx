import { useEffect, useState } from 'preact/hooks';
import { addAmounts } from '../../../shared/money.js';
import { apiText } from '../../api.js';
import { Button, Link, Loading, Ltr, Money, Notice, Segmented, downloadText } from '../../components.js';
import { errorText, reportError } from '../../errors.js';
import { useApi } from '../../hooks.js';
import { t, tx } from '../../i18n/index.js';
import { IconDownload } from '../../icons.js';
import type { LineJson, StatementJson } from '../../types.js';
import { RoundStatusChip, StateChip } from './common.js';
import type { CircleProps } from './shell.js';

function SeqLinks({ circleId, seqs }: { circleId: string; seqs: number[] }) {
  if (seqs.length === 0) return <span class="muted">—</span>;
  return (
    <span data-testid="seq-links">
      {seqs.map((s) => (
        <Link key={s} href={`/circles/${circleId}/ledger#seq-${s}`} class="seq-link">
          #{s}
        </Link>
      ))}
    </span>
  );
}

interface MemberTotals {
  memberId: string;
  expected: number;
  confirmed: number;
  outstanding: number;
}

function byMember(data: StatementJson): MemberTotals[] {
  const map = new Map<string, MemberTotals>();
  for (const r of data.statement.rounds) {
    if (r.status === 'upcoming') continue;
    for (const l of r.lines) {
      const m = map.get(l.memberId) ?? { memberId: l.memberId, expected: 0, confirmed: 0, outstanding: 0 };
      m.expected = addAmounts(m.expected, l.expected);
      m.confirmed = addAmounts(m.confirmed, l.confirmed);
      m.outstanding = addAmounts(m.outstanding, l.outstanding);
      map.set(l.memberId, m);
    }
  }
  return [...map.values()];
}

function LinesTable({ circleId, currency, lines, names }: { circleId: string; currency: string; lines: LineJson[]; names: Record<string, string> }) {
  return (
    <div class="table-wrap">
      <table class="table" data-testid="statement-lines">
        <thead>
          <tr>
            <th>{t('col.member')}</th>
            <th>{t('col.state')}</th>
            <th class="num">{t('col.expected')}</th>
            <th class="num">{t('col.confirmed')}</th>
            <th class="num">{t('col.outstanding')}</th>
            <th>{t('statement.seqs')}</th>
          </tr>
        </thead>
        <tbody>
          {lines.map((l) => (
            <tr key={l.memberId} data-testid="statement-line">
              <td dir="auto">{names[l.memberId] ?? ''}</td>
              <td>
                <StateChip state={l.state} ageDays={l.ageDays} />
              </td>
              <td class="num">
                <Money amount={l.expected} currency={currency} />
              </td>
              <td class="num">
                <Money amount={l.confirmed} currency={currency} />
              </td>
              <td class="num">
                <Money amount={l.outstanding} currency={currency} />
              </td>
              <td>
                <SeqLinks circleId={circleId} seqs={l.seqs} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Statement({ view, version }: CircleProps) {
  const [scope, setScope] = useState<'whole' | 'mine'>('whole');
  const query = scope === 'mine' ? `?member=${encodeURIComponent(view.me.memberId)}` : '';
  const statement = useApi<StatementJson>(`/api/circles/${view.circle.id}/statement${query}`);
  useEffect(() => {
    if (version > 0) void statement.reload();
  }, [version]);
  const [busy, setBusy] = useState(false);
  const cur = view.circle.currency;
  const download = async () => {
    setBusy(true);
    try {
      const csv = await apiText(`/api/circles/${view.circle.id}/statement.csv${query}`);
      downloadText(`dawr-statement-${view.circle.id}${scope === 'mine' ? '-mine' : ''}.csv`, csv, 'text/csv;charset=utf-8');
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  const head = (
    <section class="card stack">
      <div>
        <h2>{t('statement.title')}</h2>
        <p class="muted small">{t('statement.lead')}</p>
      </div>
      <div class="row-between">
        <Segmented
          label={t('statement.title')}
          value={scope}
          onChange={setScope}
          options={[
            { value: 'whole', label: t('statement.whole') },
            { value: 'mine', label: t('statement.mine') },
          ]}
        />
        <Button small busy={busy} onClick={() => void download()} data-testid="statement-csv">
          <IconDownload />
          {t('statement.downloadCsv')}
        </Button>
      </div>
    </section>
  );
  if (statement.loading && !statement.data) return <div class="stack">{head}<Loading /></div>;
  if (!statement.data) return <div class="stack">{head}<Notice tone="danger">{errorText(statement.error)}</Notice></div>;
  const data = statement.data;
  const totals = data.statement.totals;
  const names = data.members;
  return (
    <div class="stack">
      {head}
      {data.statement.rounds.length === 0 ? (
        <Notice>{t('statement.noRounds')}</Notice>
      ) : (
        <>
          <section class="card stack" aria-labelledby="totals-title">
            <h2 id="totals-title">{t('statement.totals')}</h2>
            <div class="grid-2" data-testid="statement-totals">
              <div class="stat">
                <span class="stat-label">{t('statement.expectedDue')}</span>
                <Money amount={totals.expectedDue} currency={cur} testId="total-expected" />
              </div>
              <div class="stat">
                <span class="stat-label">{t('statement.confirmed')}</span>
                <Money amount={totals.confirmed} currency={cur} testId="total-confirmed" />
              </div>
              <div class="stat">
                <span class="stat-label">{t('statement.outstanding')}</span>
                <Money amount={totals.outstanding} currency={cur} testId="total-outstanding" />
              </div>
              <div class="stat">
                <span class="stat-label">{t('statement.paidOut')}</span>
                <Money amount={totals.paidOut} currency={cur} testId="total-paid" />
              </div>
            </div>
            <p class="xsmall muted">{t('statement.asOf', { seq: data.statement.asOfSeq })}</p>
          </section>
          {scope === 'whole' ? (
            <section class="card stack" aria-labelledby="by-member-title">
              <h2 id="by-member-title">{t('statement.byMember')}</h2>
              <div class="table-wrap">
                <table class="table" data-testid="by-member">
                  <thead>
                    <tr>
                      <th>{t('col.member')}</th>
                      <th class="num">{t('col.expected')}</th>
                      <th class="num">{t('col.confirmed')}</th>
                      <th class="num">{t('col.outstanding')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {byMember(data).map((m) => (
                      <tr key={m.memberId}>
                        <td dir="auto">{names[m.memberId] ?? ''}</td>
                        <td class="num">
                          <Money amount={m.expected} currency={cur} />
                        </td>
                        <td class="num">
                          <Money amount={m.confirmed} currency={cur} />
                        </td>
                        <td class="num">
                          <Money amount={m.outstanding} currency={cur} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}
          {data.statement.rounds.map((r) => (
            <section key={r.n} class="card stack" data-testid="statement-round">
              <div class="row-between">
                <h3>{tx('statement.round', { n: r.n, date: <Ltr>{r.dueDate}</Ltr> })}</h3>
                <RoundStatusChip status={r.status} />
              </div>
              <LinesTable circleId={view.circle.id} currency={cur} lines={r.lines} names={names} />
              {r.payout ? (
                <p class="small">
                  {tx('statement.payoutLine', {
                    name: names[r.recipientMemberId] ?? '',
                    amount: <Money amount={r.payout.amount} currency={cur} />,
                    date: <Ltr>{r.payout.paidOn}</Ltr>,
                  })}{' '}
                  <SeqLinks circleId={view.circle.id} seqs={[r.payout.seq, ...(r.payout.acknowledgedSeq ? [r.payout.acknowledgedSeq] : [])]} />
                </p>
              ) : null}
            </section>
          ))}
        </>
      )}
    </div>
  );
}
