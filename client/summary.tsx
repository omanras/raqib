import type { ComponentChildren } from 'preact';
import type { LedgerEntry } from '../shared/ledger.js';
import { Ltr, Money } from './components.js';
import { everyText } from './describe.js';
import { en } from './i18n/en.js';
import { t, tx, type MessageKey, type MessageKeyOf } from './i18n/index.js';
import { localDateTime } from './format.js';
import type { Period } from './types.js';

export interface SummaryContext {
  /** member id -> display name */
  members: Record<string, string>;
  /** user id -> display name (ledger actors are user ids) */
  users: Record<string, string>;
  currency: string;
}

type P = Record<string, unknown>;

const has = (k: string): k is MessageKey => Object.prototype.hasOwnProperty.call(en, k);

function fieldName(field: string): string {
  const key = `field.${field}`;
  return has(key) ? t(key) : field;
}

function value(field: string, v: unknown, currency: string): ComponentChildren {
  if (v === null || v === undefined || v === '') return '—';
  if (field === 'contribution' && typeof v === 'number') return <Money amount={v} currency={currency} />;
  if (field === 'recipientPays') return v ? t('common.yes') : t('common.no');
  if (field === 'period' && typeof v === 'string') return t(`period.${v}` as MessageKeyOf<'period'>);
  if (field === 'rulesText' && typeof v === 'string') return `“${v.length > 60 ? `${v.slice(0, 60)}…` : v}”`;
  return <Ltr>{String(v)}</Ltr>;
}

/** A readable sentence for one ledger entry (M2.3 E1), in the current language. */
export function summarize(entry: LedgerEntry, ctx: SummaryContext): ComponentChildren {
  const p = entry.payload as P;
  const member = (id: unknown) => (typeof id === 'string' ? (ctx.members[id] ?? id.slice(0, 6)) : '');
  const order = (ids: unknown) =>
    Array.isArray(ids) ? ids.map((id, i) => `${i + 1}. ${member(id)}`).join(', ') : '';
  const money = (n: unknown, currency = ctx.currency) => (typeof n === 'number' ? <Money amount={n} currency={currency} /> : '');
  switch (entry.type) {
    case 'circle.created':
      return tx('entry.circle.created', {
        name: String(p.name ?? ''),
        amount: money(p.contribution, String(p.currency ?? ctx.currency)),
        every: everyText(p.period as Period),
      });
    case 'circle.rule_changed':
      return tx('entry.circle.rule_changed', {
        field: fieldName(String(p.field)),
        from: value(String(p.field), p.from, ctx.currency),
        to: value(String(p.field), p.to, ctx.currency),
      });
    case 'circle.started':
      return tx('entry.circle.started', { n: Number(p.memberCount), date: <Ltr>{String(p.startDate)}</Ltr>, pot: money(p.pot) });
    case 'circle.cancelled':
      return tx('entry.circle.cancelled', { reason: String(p.reason ?? '') });
    case 'circle.completed':
      return tx('entry.circle.completed', { n: Number(p.rounds) });
    case 'member.joined':
      return tx('entry.member.joined', { name: String(p.displayName ?? ''), role: t(`role.${String(p.role)}` as MessageKeyOf<'role'>) });
    case 'member.left':
      return tx('entry.member.left', { name: String(p.displayName ?? '') });
    case 'order.set':
      return tx('entry.order.set', { order: order(p.order) });
    case 'draw.opened':
      return tx('entry.draw.opened', {
        commit: <Ltr>{localDateTime(String(p.commitDeadline))}</Ltr>,
        reveal: <Ltr>{localDateTime(String(p.revealDeadline))}</Ltr>,
      });
    case 'draw.committed':
      return tx('entry.draw.committed', { name: member(p.memberId), hash: <code>{String(p.commitment).slice(0, 12)}…</code> });
    case 'draw.commits_closed':
      return tx('entry.draw.commits_closed', {
        how: p.automatic ? t('entry.draw.commits_closed.auto') : t('entry.draw.commits_closed.manual'),
        n: Number(p.committed ?? 0),
      });
    case 'draw.revealed':
      return tx('entry.draw.revealed', { name: member(p.memberId) });
    case 'draw.finalized':
      return tx('entry.draw.finalized', { order: order(p.order) });
    case 'round.opened':
      return tx('entry.round.opened', { n: Number(p.n), expected: money(p.expected) });
    case 'round.closed':
      return tx('entry.round.closed', { n: Number(p.n), k: Array.isArray(p.outstanding) ? p.outstanding.length : 0 });
    case 'contribution.reported':
      return tx('entry.contribution.reported', { name: member(p.memberId), amount: money(p.amount), n: Number(p.roundN) });
    case 'contribution.confirmed':
      return tx('entry.contribution.confirmed', { name: member(p.memberId), amount: money(p.amount), n: Number(p.roundN) });
    case 'contribution.waived':
      return tx('entry.contribution.waived', { name: member(p.memberId), n: Number(p.roundN), reason: String(p.reason ?? '') });
    case 'payout.recorded':
      return tx('entry.payout.recorded', { name: member(p.recipientMemberId), amount: money(p.amount), n: Number(p.roundN) });
    case 'payout.acknowledged':
      return tx('entry.payout.acknowledged', { name: member(p.recipientMemberId), n: Number(p.roundN) });
    default: {
      const key = `entry.${entry.type}`;
      return has(key) ? t(key) : entry.type;
    }
  }
}

export function actorName(actor: string, ctx: SummaryContext): string {
  if (actor === 'system') return t('ledger.system');
  return ctx.users[actor] ?? t('ledger.unknownActor');
}
