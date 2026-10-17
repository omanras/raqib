import { useMemo, useState } from 'preact/hooks';
import { CURRENCIES, minorUnitOf, mulAmount, parseAmount, type MinorUnit } from '../../shared/money.js';
import { post } from '../api.js';
import { Button, Checkbox, Chip, EmptyState, Link, LinkButton, Loading, Ltr, Money, Notice, RoleChip, Segmented, Select, StatusChip, TextArea, TextField } from '../components.js';
import { everyText, scheduleText, weekdayName } from '../describe.js';
import { errorText, reportError } from '../errors.js';
import { money, todayUtc } from '../format.js';
import { useApi, useTitle } from '../hooks.js';
import { t, tx, useLang, type MessageKeyOf } from '../i18n/index.js';
import { IconCircles, IconPlus } from '../icons.js';
import { navigate } from '../router.js';
import { toast } from '../store.js';
import type { CircleListItem, CircleView, Period } from '../types.js';

export function MyCircles() {
  useTitle(t('circles.title'));
  useLang();
  const list = useApi<{ circles: CircleListItem[] }>('/api/circles');
  return (
    <div>
      <div class="page-head row-between">
        <div>
          <h1>{t('circles.title')}</h1>
          <p class="muted">{t('circles.lead')}</p>
        </div>
        <LinkButton href="/circles/new" variant="primary">
          <IconPlus />
          {t('circles.new')}
        </LinkButton>
      </div>
      {list.loading && !list.data ? <Loading /> : null}
      {list.error && !list.data ? <Notice tone="danger">{errorText(list.error)}</Notice> : null}
      {list.data && list.data.circles.length === 0 ? (
        <EmptyState
          icon={<IconCircles />}
          title={t('circles.empty.title')}
          text={t('circles.empty.text')}
          action={
            <LinkButton href="/circles/new" variant="primary">
              {t('circles.empty.action')}
            </LinkButton>
          }
        />
      ) : null}
      <ul class="list stack" data-testid="circle-list">
        {(list.data?.circles ?? []).map((c) => (
          <li key={c.id} class="list-plain">
            <Link href={`/circles/${c.id}`} class="card card-link circle-card">
              <div class="circle-card-head">
                <h2 data-testid="circle-name" dir="auto">
                  {c.name}
                </h2>
                {c.myOutstandingCount > 0 ? (
                  <span class="badge" title={t('circles.outstanding', { n: c.myOutstandingCount })} data-testid="outstanding-badge">
                    {c.myOutstandingCount}
                  </span>
                ) : null}
              </div>
              <div class="row">
                <StatusChip status={c.status} />
                <RoleChip role={c.role} />
                {c.myOutstandingCount > 0 ? <Chip tone="danger">{t('circles.outstanding.short', { n: c.myOutstandingCount })}</Chip> : null}
              </div>
              <div class="row-between muted small">
                <span>
                  <span class="amount ltr">{money(c.contribution, c.currency)}</span> {everyText(c.period)}
                </span>
                <span>{t('circles.members', { n: c.memberCount })}</span>
              </div>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

const AMOUNT_ERRORS = ['empty', 'sign', 'exponent', 'format', 'grouping', 'leading_zero', 'too_many_decimals', 'too_large', 'zero'] as const;

/** Parses typed money into minor units with a message for each refusal (shared/money.parseAmount). */
export function useAmount(text: string, currency: string): { value: number | null; error: string | null } {
  return useMemo(() => {
    if (text.trim() === '') return { value: null, error: null };
    const unit = minorUnitOf(currency) as MinorUnit;
    const r = parseAmount(text, unit);
    if (!r.ok) {
      const key = AMOUNT_ERRORS.includes(r.error) ? r.error : 'format';
      return { value: null, error: t(`create.amount.error.${key}` as MessageKeyOf<'create.amount.error'>, { currency, decimals: unit }) };
    }
    if (r.value === 0) return { value: null, error: t('create.amount.error.zero') };
    return { value: r.value, error: null };
  }, [text, currency]);
}

export function CreateCircle() {
  useTitle(t('create.title'));
  useLang();
  const [name, setName] = useState('');
  const [currency, setCurrency] = useState('OMR');
  const [amountText, setAmountText] = useState('');
  const [period, setPeriod] = useState<Period>('monthly');
  const [dueDay, setDueDay] = useState(5);
  const [startDate, setStartDate] = useState('');
  const [rulesText, setRulesText] = useState('');
  const [recipientPays, setRecipientPays] = useState(true);
  const [myName, setMyName] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [touched, setTouched] = useState(false);
  const amount = useAmount(amountText, currency);
  const unit = minorUnitOf(currency);

  const changePeriod = (p: Period) => {
    setPeriod(p);
    if (p !== 'monthly' && dueDay > 7) setDueDay(4);
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    setTouched(true);
    if (amount.value === null || name.trim() === '') return;
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = { name, currency, contribution: amount.value, period, dueDay, rulesText, recipientPays };
      if (startDate) body.startDate = startDate;
      if (myName.trim()) body.displayName = myName;
      const r = await post<CircleView>('/api/circles', body);
      toast(t('create.created'));
      navigate(`/circles/${r.circle.id}/members`, { replace: true });
    } catch (err) {
      setError(err);
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
    <div>
      <div class="page-head">
        <h1>{t('create.title')}</h1>
        <p class="muted">{t('create.lead')}</p>
      </div>
      <form class="card stack" onSubmit={(e) => void submit(e)} noValidate data-testid="create-circle">
        {error ? (
          <Notice tone="danger" role="alert">
            {errorText(error)}
          </Notice>
        ) : null}
        <TextField
          label={t('create.name')}
          name="name"
          hint={t('create.name.hint')}
          value={name}
          onInput={setName}
          dir="auto"
          maxLength={80}
          required
          error={touched && name.trim() === '' ? t('error.invalid_input') : null}
        />
        <div class="grid-2">
          <Select
            label={t('create.currency')}
            name="currency"
            value={currency}
            onChange={setCurrency}
            options={Object.keys(CURRENCIES).map((c) => ({ value: c, label: c }))}
          />
          <TextField
            label={t('create.amount')}
            name="amount"
            hint={tx('create.amount.hint', { currency: <Ltr>{currency}</Ltr>, decimals: unit })}
            value={amountText}
            onInput={setAmountText}
            inputMode="decimal"
            dir="ltr"
            class="input-amount"
            placeholder={unit === 3 ? '50.000' : '50.00'}
            error={amount.error ?? (touched && amount.value === null ? t('create.amount.error.empty') : null)}
          />
        </div>
        <Segmented
          label={t('create.period')}
          value={period}
          onChange={changePeriod}
          options={(['monthly', 'weekly', 'biweekly'] as const).map((p) => ({ value: p, label: t(`period.${p}`) }))}
        />
        <div class="grid-2">
          <Select
            label={t('create.dueDay')}
            name="dueDay"
            value={String(dueDay)}
            onChange={(v) => setDueDay(Number(v))}
            options={dueOptions}
            hint={period === 'monthly' ? t('create.dueDay.monthly.hint') : t('create.dueDay.weekly.hint')}
          />
          <TextField
            label={t('create.startDate')}
            name="startDate"
            type="date"
            value={startDate}
            onInput={setStartDate}
            optional
            dir="ltr"
            hint={startDate ? `${startDate} · ${scheduleText(period, dueDay)}` : t('create.startDate.hint')}
            placeholder={todayUtc()}
          />
        </div>
        <TextArea label={t('create.rules')} name="rulesText" hint={t('create.rules.hint')} value={rulesText} onInput={setRulesText} optional maxLength={4000} />
        <Checkbox label={t('create.recipientPays')} hint={t('create.recipientPays.hint')} checked={recipientPays} onChange={setRecipientPays} name="recipientPays" />
        <TextField label={t('create.myName')} name="myName" hint={t('create.myName.hint')} value={myName} onInput={setMyName} optional dir="auto" maxLength={60} />
        {amount.value !== null ? (
          <Notice tone="ok">
            <span data-testid="create-summary">
              {tx('create.summary', {
                amount: <Money amount={amount.value} currency={currency} />,
                every: everyText(period),
                n: 10,
                pot: <Money amount={mulAmount(amount.value, recipientPays ? 10 : 9)} currency={currency} />,
              })}
            </span>
          </Notice>
        ) : null}
        <div class="form-actions">
          <Button type="submit" variant="primary" busy={busy}>
            {t('create.submit')}
          </Button>
          <LinkButton href="/circles">{t('common.cancel')}</LinkButton>
        </div>
      </form>
    </div>
  );
}
