import { useState } from 'preact/hooks';
import { CURRENCIES, minorUnitOf } from '../../../shared/money.js';
import { patch, post } from '../../api.js';
import { Button, Checkbox, Ltr, Notice, Segmented, Select, TextArea, TextField } from '../../components.js';
import { everyText, scheduleText, weekdayName } from '../../describe.js';
import { reportError } from '../../errors.js';
import { money } from '../../format.js';
import { t, tx } from '../../i18n/index.js';
import { toast } from '../../store.js';
import type { CircleView, Period } from '../../types.js';
import { useAmount } from '../circles.js';
import { AmountField, TwoStep, amountText } from './common.js';
import type { CircleProps } from './shell.js';

function ReadOnly({ view }: { view: CircleView }) {
  const c = view.circle;
  return (
    <section class="card stack" data-testid="settings-readonly">
      <h2>{t('settings.readonly')}</h2>
      <dl class="kv">
        <dt>{t('circle.contribution')}</dt>
        <dd>
          <span class="amount ltr">{money(c.contribution, c.currency)}</span> {everyText(c.period)}
        </dd>
        <dt>{t('circle.schedule')}</dt>
        <dd>{scheduleText(c.period, c.dueDay)}</dd>
        <dt>{t('circle.start')}</dt>
        <dd class="ltr">{c.startDate ?? t('join.startUnset')}</dd>
        <dt>{t('circle.pot')}</dt>
        <dd class="amount ltr">{money(c.pot, c.currency)}</dd>
        <dt>{t('circle.members')}</dt>
        <dd>{c.memberCount}</dd>
      </dl>
      <p class="muted small">{c.recipientPays ? t('settings.recipientPays.yes') : t('settings.recipientPays.no')}</p>
      <div>
        <h3>{t('circle.rules')}</h3>
        <p class="pre-wrap" dir="auto">
          {c.rulesText || t('join.noRules')}
        </p>
      </div>
    </section>
  );
}

function EditForm({ view, onSaved }: { view: CircleView; onSaved: () => void }) {
  const c = view.circle;
  const drawing = c.status === 'drawing';
  const [name, setName] = useState(c.name);
  const [currency, setCurrency] = useState(c.currency);
  const [amountTextValue, setAmountText] = useState(amountText(c.contribution, c.currency));
  const [period, setPeriod] = useState<Period>(c.period);
  const [dueDay, setDueDay] = useState(c.dueDay);
  const [startDate, setStartDate] = useState(c.startDate ?? '');
  const [rulesText, setRulesText] = useState(c.rulesText);
  const [recipientPays, setRecipientPays] = useState(c.recipientPays);
  const [busy, setBusy] = useState(false);
  const amount = useAmount(amountTextValue, currency);

  const save = async (e: Event) => {
    e.preventDefault();
    const body: Record<string, unknown> = {};
    if (!drawing) {
      if (name !== c.name) body.name = name;
      if (currency !== c.currency) body.currency = currency;
      if (amount.value !== null && (amount.value !== c.contribution || minorUnitOf(currency) !== c.minorUnit)) body.contribution = amount.value;
      if (period !== c.period) body.period = period;
      if (dueDay !== c.dueDay) body.dueDay = dueDay;
      if (rulesText !== c.rulesText) body.rulesText = rulesText;
      if (recipientPays !== c.recipientPays) body.recipientPays = recipientPays;
    }
    if ((startDate || null) !== c.startDate) body.startDate = startDate || null;
    if (Object.keys(body).length === 0) {
      toast(t('settings.nothing'));
      return;
    }
    setBusy(true);
    try {
      const r = await patch<{ changed: string[] }>(`/api/circles/${c.id}`, body);
      toast(t('settings.saved', { n: r.changed.length }));
      onSaved();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };

  const dueOptions =
    period === 'monthly'
      ? Array.from({ length: 28 }, (_, i) => ({ value: String(i + 1), label: String(i + 1) }))
      : Array.from({ length: 7 }, (_, i) => ({ value: String(i + 1), label: weekdayName(i + 1) }));

  return (
    <form class="card stack" onSubmit={(e) => void save(e)} data-testid="settings-form">
      <p class="muted small">{drawing ? t('settings.lead.drawing') : t('settings.lead.draft')}</p>
      {!drawing ? (
        <>
          <TextField label={t('create.name')} name="name" value={name} onInput={setName} dir="auto" maxLength={80} />
          <div class="grid-2">
            <Select label={t('create.currency')} name="currency" value={currency} onChange={setCurrency} options={Object.keys(CURRENCIES).map((x) => ({ value: x, label: x }))} />
            <AmountField label={t('create.amount')} name="amount" currency={currency} text={amountTextValue} onText={setAmountText} hint={tx('create.amount.hint', { currency: <Ltr>{currency}</Ltr>, decimals: minorUnitOf(currency) })} />
          </div>
          <Segmented
            label={t('create.period')}
            value={period}
            onChange={(p) => {
              setPeriod(p);
              if (p !== 'monthly' && dueDay > 7) setDueDay(4);
            }}
            options={(['monthly', 'weekly', 'biweekly'] as const).map((p) => ({ value: p, label: t(`period.${p}`) }))}
          />
          <Select label={t('create.dueDay')} name="dueDay" value={String(dueDay)} onChange={(v) => setDueDay(Number(v))} options={dueOptions} />
        </>
      ) : null}
      <TextField label={t('create.startDate')} name="startDate" type="date" value={startDate} onInput={setStartDate} dir="ltr" hint={startDate || t('create.startDate.hint')} />
      {!drawing ? (
        <>
          <TextArea label={t('create.rules')} name="rulesText" hint={t('create.rules.hint')} value={rulesText} onInput={setRulesText} maxLength={4000} />
          <Checkbox label={t('create.recipientPays')} hint={t('create.recipientPays.hint')} checked={recipientPays} onChange={setRecipientPays} name="recipientPays" />
        </>
      ) : null}
      <div>
        <Button type="submit" variant="primary" busy={busy} disabled={!drawing && amount.value === null}>
          {t('settings.save')}
        </Button>
      </div>
    </form>
  );
}

function CancelCard({ view, onCancelled }: { view: CircleView; onCancelled: () => void }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const cancel = async () => {
    setBusy(true);
    try {
      await post(`/api/circles/${view.circle.id}/cancel`, { reason });
      toast(t('settings.cancel.done'));
      onCancelled();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card stack" aria-labelledby="cancel-title" data-testid="cancel-card">
      <div>
        <h2 id="cancel-title">{t('settings.cancel.title')}</h2>
        <p class="muted small">{t('settings.cancel.lead')}</p>
      </div>
      <TwoStep first={t('settings.cancel.first')} confirm={t('settings.cancel.confirm')} back={t('settings.cancel.back')} danger busy={busy} onConfirm={() => void cancel()} testId="cancel-circle">
        <TextArea label={t('settings.cancel.reason')} name="cancelReason" value={reason} onInput={setReason} optional maxLength={500} />
      </TwoStep>
    </section>
  );
}

export function Settings({ view, changed }: CircleProps) {
  const status = view.circle.status;
  const editable = status === 'draft' || status === 'drawing';
  return (
    <div class="stack">
      <div class="page-head">
        <h2>{t('settings.title')}</h2>
        {!editable ? <p class="muted">{t('settings.lead.started')}</p> : null}
      </div>
      {editable ? <EditForm key={view.ledgerHead?.seq ?? 0} view={view} onSaved={changed} /> : <ReadOnly view={view} />}
      {editable ? <CancelCard view={view} onCancelled={changed} /> : null}
      {status === 'cancelled' ? <Notice tone="danger">{t('overview.cancelled')}</Notice> : null}
    </div>
  );
}
