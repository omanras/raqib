import { formatMoney, formatMinor, type MinorUnit } from '../shared/money.js';

/** Amounts always with their currency, Latin digits (ADR §5). */
export function money(amount: number, currency: string): string {
  try {
    return formatMoney(amount, currency);
  } catch {
    return `${amount} ${currency}`;
  }
}

export function minor(amount: number, minorUnit: number): string {
  return formatMinor(amount, minorUnit as MinorUnit);
}

const pad = (n: number) => String(n).padStart(2, '0');

/** ISO date (YYYY-MM-DD) of an instant, in local time. */
export function localDate(iso: string | Date): string {
  const d = typeof iso === 'string' ? new Date(iso) : iso;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** "YYYY-MM-DD HH:MM" in local time, Latin digits. */
export function localDateTime(iso: string | Date): string {
  const d = typeof iso === 'string' ? new Date(iso) : iso;
  return `${localDate(d)} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function localTime(iso: string | Date): string {
  const d = typeof iso === 'string' ? new Date(iso) : iso;
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Today's date in UTC, as the server counts due days. */
export function todayUtc(): string {
  return new Date().toISOString().slice(0, 10);
}
