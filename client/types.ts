/** Shapes of the JSON the server sends (server/views.ts, routes/*). */

export type CircleStatus = 'draft' | 'drawing' | 'active' | 'completed' | 'cancelled';
export type Period = 'monthly' | 'weekly' | 'biweekly';
export type Role = 'organizer' | 'member';

export interface CircleJson {
  id: string;
  name: string;
  currency: string;
  minorUnit: number;
  contribution: number;
  period: Period;
  dueDay: number;
  startDate: string | null;
  recipientPays: boolean;
  status: CircleStatus;
  rulesText: string;
  memberCount: number;
  pot: number;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  cancelledAt: string | null;
}

export interface MemberJson {
  id: string;
  userId: string;
  displayName: string;
  role: Role;
  position: number | null;
  joinedAt: string;
}

export interface RoundJson {
  n: number;
  dueDate: string;
  recipientMemberId: string;
  status: 'upcoming' | 'open' | 'closed';
  openedAt: string | null;
  closedAt: string | null;
}

export interface Check {
  ok: boolean;
  code?: string;
  reason?: string;
}

export interface CircleView {
  circle: CircleJson;
  me: { memberId: string; userId: string; role: Role; displayName: string; position: number | null };
  members: MemberJson[];
  rounds: RoundJson[];
  summary: { outstandingCount: number; outstandingAmount: number; myOutstandingCount: number; myOutstandingAmount: number };
  startCheck: Check;
  ledgerHead: { seq: number; hash: string } | null;
}

export interface CircleListItem {
  id: string;
  name: string;
  status: CircleStatus;
  role: Role;
  memberId: string;
  currency: string;
  minorUnit: number;
  contribution: number;
  period: Period;
  memberCount: number;
  pot: number;
  startDate: string | null;
  myOutstandingCount: number;
  myOutstandingAmount: number;
  outstandingCount: number;
}

export interface InviteJson {
  id: string;
  createdAt: string;
  expiresAt: string;
  status: 'active' | 'accepted' | 'revoked' | 'expired';
  acceptedAt: string | null;
}

export interface SessionSummary {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  current: boolean;
}

export type LineState = 'outstanding' | 'reported' | 'confirmed' | 'waived' | 'not_due';

export interface ReportJson {
  reportId: string;
  amount: number;
  method: string;
  reference: string;
  recordedBy: string;
  ts: string;
  seq: number;
  confirmedSeq: number | null;
}

export interface LineJson {
  roundN: number;
  memberId: string;
  state: LineState;
  expected: number;
  reported: number;
  confirmed: number;
  outstanding: number;
  ageDays: number | null;
  seqs: number[];
  reports: ReportJson[];
  waiveReason: string | null;
  contributionId: string;
  displayName?: string;
}

export interface PayoutJson {
  amount: number;
  paidOn: string;
  method: string;
  reference: string;
  seq: number;
  acknowledgedSeq: number | null;
}

export interface StatementRoundJson {
  n: number;
  dueDate: string;
  status: 'upcoming' | 'open' | 'closed';
  recipientMemberId: string;
  expected: number;
  reported: number;
  confirmed: number;
  outstanding: number;
  payout: PayoutJson | null;
  seqs: number[];
  lines: LineJson[];
}

export interface StatementJson {
  circleId: string;
  name: string;
  members: Record<string, string>;
  statement: {
    currency: string;
    minorUnit: number;
    memberId: string | null;
    asOfSeq: number;
    today: string;
    rounds: StatementRoundJson[];
    totals: { expected: number; expectedDue: number; reported: number; confirmed: number; outstanding: number; paidOut: number };
  };
}

export interface OverviewRoundJson {
  n: number;
  of: number;
  dueDate: string;
  status: 'upcoming' | 'open' | 'closed';
  recipientMemberId: string;
  recipient: { memberId: string; displayName: string };
  payout: PayoutJson | null;
  expected: number;
  reported: number;
  confirmed: number;
  outstanding: number;
  daysUntilDue: number;
  members: (LineJson & { displayName: string })[];
}

export interface OverviewJson {
  circle: { id: string; name: string; status: CircleStatus; currency: string; minorUnit: number; contribution: number; memberCount: number; rounds: number };
  today: string;
  round: OverviewRoundJson | null;
  arrears: (LineJson & { displayName: string })[];
  me: { memberId: string; role: Role; line: (LineJson & { displayName: string }) | null; canReport: boolean; isRecipient: boolean };
  ledgerHead: { seq: number; hash: string } | null;
}

export interface AuditEntryJson {
  id: number;
  ts: string;
  action: string;
  target: string | null;
  actorId: string | null;
  actorName: string | null;
  requestId: string;
  ipPrefix: string;
  uaHash: string;
  details: Record<string, unknown> | null;
}
