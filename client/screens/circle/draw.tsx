import { useEffect, useState } from 'preact/hooks';
import { webSha256Hex } from '../../../shared/hash.js';
import { commitAsync } from '../../../shared/lottery.js';
import { post } from '../../api.js';
import { Button, Chip, CopyButton, LinkButton, Loading, Ltr, Notice, TextField } from '../../components.js';
import { errorText, reportError } from '../../errors.js';
import { localDateTime } from '../../format.js';
import { useApi } from '../../hooks.js';
import { t, tx } from '../../i18n/index.js';
import { toast } from '../../store.js';
import { canVerify, newSecret, recomputeDraw, storeSecret, storedSecret, type DrawRecord, type Recomputed } from '../../trust.js';
import type { CircleView } from '../../types.js';
import type { CircleProps } from './shell.js';

interface DrawJson {
  draw: null | {
    phase: 'committing' | 'revealing' | 'finalized';
    commitDeadline: string;
    revealDeadline: string;
    memberCount: number;
    committedCount: number;
    revealedCount: number;
    takingPart: boolean;
    mine: { committed: boolean; revealed: boolean; commitment: string | null };
    result: null | (DrawRecord & { silent: string[]; notCommitted: string[]; seq: number });
  };
}

/** A datetime-local value (local time, minutes) for now + hours. */
function localInput(hoursAhead: number): string {
  const d = new Date(Date.now() + hoursAhead * 3600 * 1000);
  d.setSeconds(0, 0);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function OpenDraw({ view, onDone }: { view: CircleView; onDone: () => void }) {
  const [commit, setCommit] = useState(localInput(24));
  const [reveal, setReveal] = useState(localInput(48));
  const [busy, setBusy] = useState(false);
  const open = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    try {
      await post(`/api/circles/${view.circle.id}/draw/open`, {
        commitDeadline: new Date(commit).toISOString(),
        revealDeadline: new Date(reveal).toISOString(),
      });
      onDone();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form class="card stack" onSubmit={(e) => void open(e)} data-testid="open-draw">
      <h2>{t('draw.open.title')}</h2>
      <p class="muted small">{t('draw.none.organizer')}</p>
      {!view.circle.startDate ? <Notice tone="warn">{t('draw.open.needsDate')}</Notice> : null}
      <div class="grid-2">
        <TextField label={t('draw.open.commit')} name="commitDeadline" type="datetime-local" value={commit} onInput={setCommit} dir="ltr" />
        <TextField label={t('draw.open.reveal')} name="revealDeadline" type="datetime-local" value={reveal} onInput={setReveal} dir="ltr" />
      </div>
      <p class="hint muted xsmall">{t('draw.open.hint')}</p>
      <div>
        <Button type="submit" variant="primary" busy={busy} data-testid="open-draw-submit">
          {t('draw.open.submit')}
        </Button>
      </div>
    </form>
  );
}

function CommitCard({ view, onDone }: { view: CircleView; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState<string | null>(null);
  const commit = async () => {
    setBusy(true);
    try {
      const secret = newSecret();
      // Kept before sending, so a lost answer never loses the secret.
      storeSecret(view.circle.id, view.me.memberId, secret);
      const commitment = await commitAsync(secret, view.me.memberId, webSha256Hex);
      await post(`/api/circles/${view.circle.id}/draw/commit`, { commitment });
      setShown(secret);
      toast(t('draw.commit.done'));
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  if (shown) {
    return (
      <section class="card stack" data-testid="secret-shown">
        <h2>{t('draw.secret.title')}</h2>
        <p class="small">{t('draw.secret.lead')}</p>
        <div class="secret" data-testid="secret">
          {shown}
        </div>
        <div class="row">
          <CopyButton text={shown} small />
          <Button
            small
            variant="primary"
            onClick={() => {
              setShown(null);
              onDone();
            }}
          >
            {t('common.continue')}
          </Button>
        </div>
      </section>
    );
  }
  return (
    <section class="card stack" data-testid="commit-card">
      <h2>{t('draw.commit.title')}</h2>
      <p class="small muted">{t('draw.commit.lead')}</p>
      <div>
        <Button variant="primary" busy={busy} onClick={() => void commit()} data-testid="commit">
          {t('draw.commit.submit')}
        </Button>
      </div>
    </section>
  );
}

function RevealCard({ view, onDone }: { view: CircleView; onDone: () => void }) {
  const saved = storedSecret(view.circle.id, view.me.memberId);
  const [pasted, setPasted] = useState('');
  const [busy, setBusy] = useState(false);
  const reveal = async () => {
    setBusy(true);
    try {
      await post(`/api/circles/${view.circle.id}/draw/reveal`, { secret: (saved ?? pasted).trim().toLowerCase() });
      toast(t('draw.reveal.done'));
      onDone();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card stack" data-testid="reveal-card">
      <h2>{t('draw.reveal.title')}</h2>
      {saved ? (
        <Notice tone="ok">{t('draw.secret.saved')}</Notice>
      ) : (
        <>
          <Notice tone="warn">{t('draw.secret.missing')}</Notice>
          <TextField label={t('draw.reveal.paste')} name="secret" value={pasted} onInput={setPasted} dir="ltr" class="mono" maxLength={80} />
        </>
      )}
      <div>
        <Button variant="primary" busy={busy} disabled={!saved && pasted.trim() === ''} onClick={() => void reveal()} data-testid="reveal">
          {t('draw.reveal.submit')}
        </Button>
      </div>
    </section>
  );
}

function Result({ view, result }: { view: CircleView; result: NonNullable<NonNullable<DrawJson['draw']>['result']> }) {
  const names = Object.fromEntries(view.members.map((m) => [m.id, m.displayName]));
  const [check, setCheck] = useState<Recomputed | null>(null);
  const [busy, setBusy] = useState(false);
  const recompute = async () => {
    setBusy(true);
    try {
      setCheck(await recomputeDraw(view.circle.id, result));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card stack" data-testid="draw-result">
      <h2>{t('draw.result.title')}</h2>
      <ol class="order-list" data-testid="drawn-order">
        {result.order.map((m) => (
          <li key={m} data-testid="drawn-member">
            <bdi>{names[m] ?? m}</bdi>
          </li>
        ))}
      </ol>
      {result.silent.length > 0 ? (
        <Notice tone="warn">{t('draw.result.silent', { names: result.silent.map((m) => names[m] ?? m).join(', ') })}</Notice>
      ) : null}
      <div class="stack-s">
        <span class="stat-label">{t('draw.result.seed')}</span>
        <code data-testid="seed">{result.seed}</code>
      </div>
      {canVerify() ? (
        <div>
          <Button busy={busy} onClick={() => void recompute()} data-testid="recompute">
            {t('draw.recompute')}
          </Button>
        </div>
      ) : (
        <Notice tone="warn">{t('ledger.noCrypto')}</Notice>
      )}
      {check ? (
        <Notice tone={check.ok ? 'ok' : 'danger'} role="status">
          <span data-testid="recompute-result" data-ok={check.ok ? 'true' : 'false'}>
            {check.ok ? t('draw.recompute.ok') : t('draw.recompute.bad')}
          </span>
        </Notice>
      ) : null}
      {view.me.role === 'organizer' && view.circle.status === 'drawing' ? (
        <div>
          <LinkButton href={`/circles/${view.circle.id}/members`} variant="primary">
            {t('draw.toStart')}
          </LinkButton>
        </div>
      ) : null}
    </section>
  );
}

export function Draw({ view, version, changed }: CircleProps) {
  const draw = useApi<DrawJson>(`/api/circles/${view.circle.id}/draw`);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (version > 0) void draw.reload();
  }, [version]);
  const organizer = view.me.role === 'organizer';
  const refresh = () => {
    changed();
    void draw.reload();
  };
  const step = async (path: 'close-commits' | 'finalize') => {
    setBusy(true);
    try {
      await post(`/api/circles/${view.circle.id}/draw/${path}`);
      refresh();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  const intro = (
    <section class="card stack">
      <h2>{t('draw.title')}</h2>
      <p class="muted small">{t('draw.lead')}</p>
    </section>
  );
  if (draw.loading && !draw.data) return <Loading />;
  if (!draw.data) return <Notice tone="danger">{errorText(draw.error)}</Notice>;
  const d = draw.data.draw;
  if (!d) {
    return (
      <div class="stack">
        {intro}
        {organizer && view.circle.status === 'draft' ? <OpenDraw view={view} onDone={refresh} /> : <Notice>{t('draw.none.member')}</Notice>}
      </div>
    );
  }
  const phaseTone = d.phase === 'finalized' ? 'ok' : 'accent';
  return (
    <div class="stack">
      {intro}
      <section class="card stack" data-testid="draw-status">
        <div class="row-between">
          <Chip tone={phaseTone} testId="draw-phase">
            {t(`draw.phase.${d.phase}`)}
          </Chip>
          <span class="muted small">{t('draw.count.committed', { n: d.committedCount, total: d.memberCount })}</span>
        </div>
        <p class="small">
          {tx('draw.deadline.commit', { time: <Ltr>{localDateTime(d.commitDeadline)}</Ltr> })}
          <br />
          {tx('draw.deadline.reveal', { time: <Ltr>{localDateTime(d.revealDeadline)}</Ltr> })}
        </p>
        {d.phase !== 'committing' ? (
          <p class="small muted" data-testid="revealed-count">
            {t('draw.count.revealed', { n: d.revealedCount, committed: d.committedCount })}
          </p>
        ) : null}
        {organizer && d.phase === 'committing' ? (
          <div class="stack-s">
            <div>
              <Button busy={busy} disabled={d.committedCount < d.memberCount} onClick={() => void step('close-commits')} data-testid="close-commits">
                {t('draw.close.submit')}
              </Button>
            </div>
            {d.committedCount < d.memberCount ? <p class="muted xsmall">{t('draw.close.notYet')}</p> : null}
          </div>
        ) : null}
        {organizer && d.phase === 'revealing' ? (
          <div class="stack-s">
            <div>
              <Button variant="primary" busy={busy} onClick={() => void step('finalize')} data-testid="finalize">
                {t('draw.finalize.submit')}
              </Button>
            </div>
            <p class="muted xsmall">{t('draw.finalize.notYet')}</p>
          </div>
        ) : null}
      </section>
      {!d.takingPart && d.phase !== 'finalized' ? <Notice>{t('draw.notInDraw')}</Notice> : null}
      {d.takingPart && d.phase === 'committing' && !d.mine.committed ? <CommitCard view={view} onDone={refresh} /> : null}
      {d.takingPart && d.phase === 'committing' && d.mine.committed ? <Notice tone="ok">{t('draw.commit.done')} {t('draw.waitingClose')}</Notice> : null}
      {d.takingPart && d.phase === 'revealing' && d.mine.committed && !d.mine.revealed ? <RevealCard view={view} onDone={refresh} /> : null}
      {d.takingPart && d.phase === 'revealing' && d.mine.revealed ? <Notice tone="ok">{t('draw.reveal.done')} {t('draw.waitingFinalize')}</Notice> : null}
      {d.takingPart && d.phase !== 'committing' && !d.mine.committed && d.phase !== 'finalized' ? <Notice tone="warn">{t('draw.notCommitted')}</Notice> : null}
      {d.phase === 'finalized' && d.result ? <Result view={view} result={d.result} /> : null}
    </div>
  );
}
