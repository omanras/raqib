import { t, type MessageKeyOf } from './i18n/index.js';
import type { Period } from './types.js';

export function weekdayName(day: number): string {
  return t(`weekday.${day}` as MessageKeyOf<'weekday'>);
}

/** "every month" / "every week" / "every two weeks". */
export function everyText(period: Period): string {
  return t(`period.every.${period}` as MessageKeyOf<'period.every'>);
}

export function periodName(period: Period): string {
  return t(`period.${period}` as MessageKeyOf<'period'>);
}

/** "Due on day 5 of each month" / "Due every Thursday". */
export function scheduleText(period: Period, dueDay: number): string {
  if (period === 'monthly') return t('period.due.monthly', { day: dueDay });
  return t(period === 'weekly' ? 'period.due.weekly' : 'period.due.biweekly', { weekday: weekdayName(dueDay) });
}
