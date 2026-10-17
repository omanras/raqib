/**
 * Ledger payloads per entry type (ADR §2: "payload (JSON, schema per
 * type)"). The server writes exactly these shapes; the client reads them to
 * summarize entries and to recompute the draw. Amounts are integer minor
 * units; ids are the random ids used in URLs; dates are ISO calendar dates.
 */

export interface CircleCreated {
  circleId: string;
  name: string;
  currency: string;
  minorUnit: number;
  contribution: number;
  period: string;
  dueDay: number;
  startDate: string | null;
  recipientPays: boolean;
  rulesText: string;
}

export interface RuleChanged {
  field: string;
  from: string | number | boolean | null;
  to: string | number | boolean | null;
}

export interface MemberJoined {
  memberId: string;
  userId: string;
  displayName: string;
  role: 'organizer' | 'member';
}

export interface MemberLeft {
  memberId: string;
  userId: string;
  displayName: string;
}

export interface OrderSet {
  /** Member ids by position: order[0] receives in round 1. */
  order: string[];
  method: 'manual';
}

export interface CircleStarted {
  memberCount: number;
  startDate: string;
  contribution: number;
  currency: string;
  recipientPays: boolean;
  /** Expected pot of every round, minor units. */
  pot: number;
  rounds: { n: number; dueDate: string; recipientMemberId: string }[];
}

export interface CircleCancelled {
  reason: string;
  status: string;
}

export type MemberRole = 'organizer' | 'member';
