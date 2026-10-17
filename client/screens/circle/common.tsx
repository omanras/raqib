import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import { formatMinor, minorUnitOf, type MinorUnit } from '../../../shared/money.js';
import { Button, Chip, TextField, type Tone } from '../../components.js';
import { t, type MessageKeyOf } from '../../i18n/index.js';
import { useAmount } from '../circles.js';
import type { LineState } from '../../types.js';

const STATE_TONE: Record<LineState, Tone> = {
  outstanding: 'warn',
  reported: 'info',
  confirmed: 'ok',
  waived: 'neutral',
  not_due: 'neutral',
};

/** State chip of a contribution; outstanding shows its age when late (A5: silence is visible). */
export function StateChip({ state, ageDays }: { state: LineState; ageDays: number | null }) {
  if (state === 'outstanding' && ageDays) {
    return (
      <Chip tone="danger" testId="state-chip">
        {t('state.outstanding')} · {t('state.late', { n: ageDays })}
      </Chip>
    );
  }
  return (
    <Chip tone={STATE_TONE[state]} testId="state-chip">
      {t(`state.${state}` as MessageKeyOf<'state'>)}
    </Chip>
  );
}

export function stateText(state: LineState, ageDays: number | null): string {
  const base = t(`state.${state}` as MessageKeyOf<'state'>);
  return state === 'outstanding' && ageDays ? `${base} (${t('state.late', { n: ageDays })})` : base;
}

const ROUND_TONE: Record<string, Tone> = { upcoming: 'neutral', open: 'accent', closed: 'ok' };

export function RoundStatusChip({ status }: { status: string }) {
  return (
    <Chip tone={ROUND_TONE[status] ?? 'neutral'} testId="round-status">
      {t(`roundStatus.${status}` as MessageKeyOf<'roundStatus'>)}
    </Chip>
  );
}

/** "12 days left" / "Due today" / "3 days overdue". */
export function dueText(daysUntilDue: number): string {
  if (daysUntilDue > 0) return t('overview.daysLeft', { n: daysUntilDue });
  if (daysUntilDue === 0) return t('overview.dueToday');
  return t('overview.overdue', { n: -daysUntilDue });
}

/** Two clicks for anything that cannot be undone. */
export function TwoStep(props: {
  first: string;
  confirm: string;
  back?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  children?: ComponentChildren;
  testId?: string;
}) {
  const [armed, setArmed] = useState(false);
  if (!armed) {
    return (
      <Button variant={props.danger ? 'danger' : 'secondary'} onClick={() => setArmed(true)} data-testid={props.testId}>
        {props.first}
      </Button>
    );
  }
  return (
    <div class="stack-s">
      {props.children}
      <div class="row">
        <Button variant={props.danger ? 'danger-solid' : 'primary'} busy={props.busy} onClick={props.onConfirm} data-testid={props.testId ? `${props.testId}-confirm` : undefined}>
          {props.confirm}
        </Button>
        <Button variant="ghost" onClick={() => setArmed(false)}>
          {props.back ?? t('common.cancel')}
        </Button>
      </div>
    </div>
  );
}

/** A money input in the circle's currency: parsed to minor units as the person types. */
export function AmountField(props: {
  label: string;
  currency: string;
  text: string;
  onText: (v: string) => void;
  hint?: ComponentChildren;
  name?: string;
}) {
  const parsed = useAmount(props.text, props.currency);
  return (
    <TextField
      label={props.label}
      name={props.name}
      value={props.text}
      onInput={props.onText}
      inputMode="decimal"
      dir="ltr"
      class="input-amount"
      hint={props.hint}
      error={parsed.error}
    />
  );
}

/** Minor units as editable text ("25.500") for prefilling amount fields. */
export function amountText(amount: number, currency: string): string {
  return formatMinor(amount, minorUnitOf(currency) as MinorUnit, { grouping: false });
}
