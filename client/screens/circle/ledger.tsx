import { useEffect, useMemo, useState } from 'preact/hooks';
import type { LedgerEntry, VerifyResult } from '../../../shared/ledger.js';
import { Button, CopyButton, Loading, Ltr, Notice, downloadText } from '../../components.js';
import { errorText } from '../../errors.js';
import { localDateTime, localTime } from '../../format.js';
import { useApi } from '../../hooks.js';
import { t, tx, type MessageKeyOf } from '../../i18n/index.js';
import { IconDownload, IconShield } from '../../icons.js';
import { connection, useStore } from '../../store.js';
import { actionLabel } from './audit.js';
import { canVerify, ledgerCsv, ledgerJson, verifyLedger } from '../../trust.js';
import { actorName, summarize, type SummaryContext } from '../../summary.js';
import type { CircleView } from '../../types.js';
import type { CircleProps } from './shell.js';

interface LedgerJson {
  circleId: string;
  fetchedAt: string;
  head: { seq: number; hash: string } | null;
  entries: LedgerEntry[];
}

/** After this long without a refresh, the copy is labelled old even when online. */
const FRESH_MS = 5 * 60 * 1000;

export function summaryContext(view: CircleView): SummaryContext {
  return {
    members: Object.fromEntries(view.members.map((m) => [m.id, m.displayName])),
    users: Object.fromEntries(view.members.map((m) => [m.userId, m.displayName])),
    currency: view.circle.currency,
  };
}

function Freshness({ fetchedAt, failed }: { fetchedAt: Date | null; failed: boolean }) {
  const online = useStore(connection.store).online;
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(id);
  }, []);
  if (!fetchedAt) return null;
  const time = <Ltr>{localTime(fetchedAt)}</Ltr>;
  // A10: an old copy is never shown as current.
  if (failed || !online) {
    return (
      <Notice tone="warn" role="status">
        <span data-testid="ledger-freshness">{tx('ledger.stale', { time })}</span>
      </Notice>
    );
  }
  if (now - fetchedAt.getTime() > FRESH_MS) {
    return (
      <Notice tone="warn">
        <span data-testid="ledger-freshness">{tx('ledger.old', { time })}</span>
      </Notice>
    );
  }
  return (
    <p class="muted small" data-testid="ledger-freshness">
      {tx('ledger.fetched', { time })}
    </p>
  );
}

function VerifyPanel({ data, fetchedAt }: { data: LedgerJson; fetchedAt: Date | null }) {
  const [result, setResult] = useState<{ r: VerifyResult; at: Date; copyOf: Date | null } | null>(null);
  const [busy, setBusy] = useState(false);
  // A verification belongs to the copy it ran on; a new copy needs a new check.
  useEffect(() => setResult(null), [fetchedAt]);
  const run = async () => {
    setBusy(true);
    try {
      setResult({ r: await verifyLedger(data.entries), at: new Date(), copyOf: fetchedAt });
    } finally {
      setBusy(false);
    }
  };
  if (!canVerify()) return <Notice tone="warn">{t('ledger.noCrypto')}</Notice>;
  return (
    <div class="stack-s">
      <div>
        <Button variant="primary" busy={busy} onClick={() => void run()} data-testid="verify-chain">
          <IconShield />
          {t('ledger.verify')}
        </Button>
      </div>
      {busy ? <p class="muted small">{t('ledger.verifying')}</p> : null}
      {result?.r.ok ? (
        <Notice tone="ok" role="status">
          <span data-testid="verify-result" data-ok="true">
            {t('ledger.ok', { n: result.r.count })}
          </span>
          <span class="block xsmall">
            {tx('ledger.okHash', { hash: <code>{result.r.lastHash}</code> })}
          </span>
          <span class="block xsmall muted">{tx('ledger.verifiedAt', { time: <Ltr>{localTime(result.at)}</Ltr> })}</span>
          {data.head && data.head.hash !== result.r.lastHash ? <span class="block small">{t('ledger.headMismatch')}</span> : null}
        </Notice>
      ) : null}
      {result && !result.r.ok ? (
        <Notice tone="danger" role="alert">
          <span data-testid="verify-result" data-ok="false" data-seq={result.r.brokenSeq}>
            {t('ledger.broken', { seq: result.r.brokenSeq, reason: t(`ledger.reason.${result.r.reason}` as MessageKeyOf<'ledger.reason'>) })}
          </span>
          <span class="block small">{t('ledger.brokenHelp', { seq: result.r.brokenSeq })}</span>
        </Notice>
      ) : null}
    </div>
  );
}

export function Ledger({ view, version }: CircleProps) {
  const ledger = useApi<LedgerJson>(`/api/circles/${view.circle.id}/ledger`);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (version > 0) void ledger.reload();
  }, [version]);
  useEffect(() => setFailed(Boolean(ledger.error && ledger.data)), [ledger.error, ledger.data]);
  const ctx = useMemo(() => summaryContext(view), [view]);
  const highlight = typeof window !== 'undefined' ? Number(window.location.hash.replace('#seq-', '')) || null : null;
  useEffect(() => {
    if (highlight && ledger.data) document.getElementById(`seq-${highlight}`)?.scrollIntoView({ block: 'center' });
  }, [highlight, ledger.data]);

  if (ledger.loading && !ledger.data) return <Loading />;
  if (!ledger.data) return <Notice tone="danger">{errorText(ledger.error)}</Notice>;
  const data = ledger.data;
  const newestFirst = [...data.entries].reverse();
  const json = ledgerJson(view.circle.id, data.entries, ledger.fetchedAt);
  const csv = ledgerCsv(data.entries);
  const base = `dawr-ledger-${view.circle.id}`;
  return (
    <div class="stack">
      <section class="card stack">
        <div>
          <h2>{t('ledger.title')}</h2>
          <p class="muted small">{t('ledger.lead')}</p>
        </div>
        <div class="row-between">
          <Freshness fetchedAt={ledger.fetchedAt} failed={failed} />
          <Button small variant="ghost" busy={ledger.loading} onClick={() => void ledger.reload()} data-testid="ledger-refresh">
            {t('ledger.refresh')}
          </Button>
        </div>
        <VerifyPanel data={data} fetchedAt={ledger.fetchedAt} />
        <details>
          <summary class="small">{t('ledger.export')}</summary>
          <div class="row">
            <CopyButton text={json} label={t('ledger.copyJson')} small />
            <Button small onClick={() => downloadText(`${base}.json`, json, 'application/json')} data-testid="download-json">
              <IconDownload />
              {t('ledger.downloadJson')}
            </Button>
            <CopyButton text={csv} label={t('ledger.copyCsv')} small />
            <Button small onClick={() => downloadText(`${base}.csv`, csv, 'text/csv;charset=utf-8')} data-testid="download-csv">
              <IconDownload />
              {t('ledger.downloadCsv')}
            </Button>
          </div>
        </details>
      </section>
      {newestFirst.length === 0 ? <p class="muted">{t('ledger.empty')}</p> : null}
      <ol class="list stack" data-testid="ledger-entries" reversed>
        {newestFirst.map((e) => (
          <li key={e.seq} id={`seq-${e.seq}`} class={`card card-tight stack-s ${highlight === e.seq ? 'highlight' : ''}`} data-testid="ledger-entry" data-seq={e.seq}>
            <div class="row-between">
              <strong>{actionLabel(e.type)}</strong>
              <span class="chip chip-plain">{t('ledger.entry', { seq: e.seq })}</span>
            </div>
            <p class="small" dir="auto" data-testid="entry-summary">
              {summarize(e, ctx)}
            </p>
            <p class="xsmall muted">
              <Ltr>{localDateTime(e.ts)}</Ltr> · <span dir="auto">{t('ledger.by', { name: actorName(e.actor, ctx) })}</span>
            </p>
            <details>
              <summary class="xsmall">{t('ledger.raw')}</summary>
              <pre class="raw" data-testid="raw-entry">
                {JSON.stringify({ seq: e.seq, ts: e.ts, actor: e.actor, type: e.type, payload: e.payload, prevHash: e.prevHash, hash: e.hash }, null, 2)}
              </pre>
            </details>
          </li>
        ))}
      </ol>
    </div>
  );
}
