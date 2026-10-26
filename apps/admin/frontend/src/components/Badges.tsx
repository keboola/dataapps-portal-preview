/**
 * State marks shared by the pages. Colour never carries the meaning alone: every badge says its
 * state in words. Badge `color` green / red / amber is the design system's semantic set.
 */
import { Badge } from '@keboola/design';
import type { AuthMode, DiscoveryStatus } from '../api/types';

export function DecisionBadge({ allowed }: { allowed: boolean }) {
  return allowed ? <Badge color="green">allowed</Badge> : <Badge color="red">denied</Badge>;
}

/** Shown only for an app anyone signed in may open; the default (grants) needs no mark. */
export function AccessBadge({ access }: { access: 'grants' | 'all_signed_in' }) {
  return access === 'all_signed_in' ? <Badge color="amber">everyone signed in</Badge> : null;
}

export function ActiveBadge({ active }: { active: boolean }) {
  return active ? <Badge color="green">active</Badge> : <Badge color="red">inactive</Badge>;
}

/** Shown only for an inactive entity, next to its name. */
export function InactiveBadge({ active }: { active: boolean }) {
  return active ? null : <Badge color="red">inactive</Badge>;
}

export function GrantedBadge() {
  return <Badge color="green">granted</Badge>;
}

export function UnknownGroupBadge() {
  return <Badge color="amber">unknown</Badge>;
}

const DISCOVERY_LABELS: Record<Exclude<DiscoveryStatus, 'new'>, { label: string; color: 'green' | 'amber' }> = {
  registered: { label: 'already registered', color: 'green' },
  launcher: { label: "this suite's launcher", color: 'amber' },
  not_deployed: { label: 'not deployed yet', color: 'amber' },
};

export function DiscoveryStatusBadge({ status }: { status: DiscoveryStatus }) {
  if (status === 'new') return <Badge color="blue">new</Badge>;
  const { label, color } = DISCOVERY_LABELS[status];
  return <Badge color={color}>{label}</Badge>;
}

const AUTH_MODE_LABELS: Record<AuthMode, { label: string; color: 'green' | 'amber' | 'red' }> = {
  required: { label: 'login required', color: 'green' },
  partial: { label: 'login on some paths', color: 'amber' },
  public: { label: 'public - no login', color: 'red' },
  unknown: { label: 'unknown', color: 'amber' },
};

export function AuthModeBadge({ mode }: { mode: AuthMode }) {
  const { label, color } = AUTH_MODE_LABELS[mode];
  return <Badge color={color}>{label}</Badge>;
}
