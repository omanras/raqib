import { useEffect, useState } from 'preact/hooks';
import { get } from '../../api.js';
import { Button, Loading, Notice } from '../../components.js';
import { errorText } from '../../errors.js';
import { localDateTime } from '../../format.js';
import { en } from '../../i18n/en.js';
import { t, type MessageKey } from '../../i18n/index.js';
import type { AuditEntryJson } from '../../types.js';
import type { CircleProps } from './shell.js';

export function actionLabel(action: string): string {
  const key = `action.${action}`;
  return Object.prototype.hasOwnProperty.call(en, key) ? t(key as MessageKey) : action;
}

/** The organizers' activity log, newest first, fetched a page at a time. */
export function Audit({ view, version }: CircleProps) {
  const [entries, setEntries] = useState<AuditEntryJson[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const load = async (before: number | null) => {
    setLoading(true);
    try {
      const r = await get<{ entries: AuditEntryJson[]; nextBefore: number | null }>(
        `/api/circles/${view.circle.id}/audit?limit=50${before ? `&before=${before}` : ''}`,
      );
      setEntries((prev) => (before ? [...prev, ...r.entries] : r.entries));
      setNext(r.nextBefore);
      setError(null);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    void load(null);
  }, [version, view.circle.id]);
  return (
    <section class="card stack" aria-labelledby="audit-title">
      <div>
        <h2 id="audit-title">{t('audit.title')}</h2>
        <p class="muted small">{t('audit.lead')}</p>
      </div>
      {error ? <Notice tone="danger">{errorText(error)}</Notice> : null}
      {!loading && entries.length === 0 && !error ? <p class="muted">{t('audit.empty')}</p> : null}
      {entries.length > 0 ? (
        <div class="table-wrap">
          <table class="table" data-testid="audit-table">
            <thead>
              <tr>
                <th>{t('audit.time')}</th>
                <th>{t('audit.who')}</th>
                <th>{t('audit.what')}</th>
                <th>{t('audit.request')}</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} data-testid="audit-row">
                  <td class="ltr">{localDateTime(e.ts)}</td>
                  <td dir="auto">{e.actorId ? (e.actorName ?? t('audit.someone')) : t('audit.system')}</td>
                  <td>{actionLabel(e.action)}</td>
                  <td>
                    <code class="xsmall">{e.requestId}</code>
                    <div class="muted xsmall ltr">{e.ipPrefix}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {loading ? <Loading /> : null}
      {next && !loading ? (
        <div>
          <Button onClick={() => void load(next)} data-testid="audit-more">
            {t('audit.more')}
          </Button>
        </div>
      ) : null}
    </section>
  );
}
