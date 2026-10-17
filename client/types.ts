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
