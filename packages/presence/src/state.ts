/**
 * The presence state machine (spec §7.2).
 *
 * Presence is a **signal, never proof of intent**. Nothing here grants
 * anything: a state only ever tells a policy which of its rules applies, and
 * the policy is what decides. The most a presence change can do is make an
 * answer more restrictive.
 *
 * Two rules the type system is used to enforce:
 *
 *  * **Never inferred from IP or geolocation.** §7.2 says so, and the way to
 *    guarantee it is to have nowhere to put one: `PresenceSource` is a closed
 *    set of things that actually witnessed the human, and no field accepts an
 *    address.
 *  * **Absence is `away`, never `active`.** An expired or missing record means
 *    nobody has seen the user recently, which is not evidence they are there.
 */

export const PRESENCE_STATES = ['active', 'away', 'locked', 'automation'] as const;
export type PresenceState = (typeof PRESENCE_STATES)[number];

/**
 * How strongly the state is believed.
 *
 * A state set by a fresh passkey is a different claim from one set by a
 * keystroke, and a policy protecting something sensitive should be able to
 * require the stronger one. Ordered, so comparison is meaningful.
 */
export const ASSURANCE_LEVELS = ['low', 'medium', 'high'] as const;
export type Assurance = (typeof ASSURANCE_LEVELS)[number];

export const assuranceRank = (level: Assurance): number => ASSURANCE_LEVELS.indexOf(level);

export const meetsAssurance = (actual: Assurance, required: Assurance): boolean =>
  assuranceRank(actual) >= assuranceRank(required);

/**
 * What witnessed the human.
 *
 * A closed set. `passkey` is the only one that can carry `high` assurance,
 * because it is the only one where a human demonstrably did something only they
 * could do.
 */
export const PRESENCE_SOURCES = ['passkey', 'dashboard', 'device_activity', 'schedule', 'operator'] as const;
export type PresenceSource = (typeof PRESENCE_SOURCES)[number];

export const MAX_ASSURANCE: Readonly<Record<PresenceSource, Assurance>> = {
  passkey: 'high',
  // A person clicking in the dashboard is authenticated but not freshly
  // verified: a stolen session clicks just as well.
  dashboard: 'medium',
  device_activity: 'low',
  schedule: 'low',
  operator: 'medium',
};

export interface Presence {
  readonly state: PresenceState;
  readonly assurance: Assurance;
  readonly source: PresenceSource;
  readonly changedAt: Date;
  readonly expiresAt: Date | null;
}

export class PresenceTransitionError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(reason);
    this.name = 'PresenceTransitionError';
    this.reason = reason;
  }
}

/**
 * Which transitions are legal.
 *
 * `locked` is the important row: it is reachable from anywhere and leaves only
 * deliberately. An emergency lock that a background device-activity ping could
 * clear would be no lock at all — so leaving `locked` requires an explicit
 * operator or passkey action, checked below rather than encoded here.
 */
const LEGAL: Readonly<Record<PresenceState, readonly PresenceState[]>> = {
  active: ['active', 'away', 'locked', 'automation'],
  away: ['active', 'away', 'locked', 'automation'],
  locked: ['locked', 'active', 'away'],
  // Automation ends by being switched off, not by drifting into an interactive
  // state on a stray signal.
  automation: ['automation', 'locked', 'away'],
};

export interface TransitionRequest {
  readonly to: PresenceState;
  readonly source: PresenceSource;
  readonly assurance: Assurance;
  readonly ttlMs?: number | null;
}

/** Ten minutes of assumed presence. Long enough to be useful, short enough that a walk-away decays. */
export const DEFAULT_TTL_MS = 10 * 60 * 1000;

export function assertTransition(from: PresenceState, request: TransitionRequest): void {
  if (!PRESENCE_STATES.includes(request.to)) {
    throw new PresenceTransitionError('unknown state');
  }

  if (!LEGAL[from].includes(request.to)) {
    throw new PresenceTransitionError(`cannot move from ${from} to ${request.to}`);
  }

  // A source cannot claim more confidence than it is capable of. Without this,
  // "assurance" is a number the caller picks.
  if (assuranceRank(request.assurance) > assuranceRank(MAX_ASSURANCE[request.source])) {
    throw new PresenceTransitionError(`${request.source} cannot assert ${request.assurance} assurance`);
  }

  // Leaving a lock is an operator act. Device activity resuming must not lift
  // an emergency lock somebody deliberately set (§12.1 lock-during-session).
  if (from === 'locked' && request.to !== 'locked') {
    if (request.source !== 'operator' && request.source !== 'passkey') {
      throw new PresenceTransitionError('only an operator or a passkey can clear a lock');
    }
  }

  // Entering automation names a window; an open-ended one is a standing grant.
  if (request.to === 'automation' && (request.ttlMs === null || request.ttlMs === undefined)) {
    throw new PresenceTransitionError('automation requires an expiry');
  }
}

/**
 * What a stored record means now.
 *
 * Expiry decays **downward** to `away`. It never decays to `active`, and it
 * never extends `locked` into something permissive: a lock that lapsed on a
 * timer would be a lock that an attacker only has to outwait.
 */
export function effectiveState(presence: Presence | null, now: Date = new Date()): Presence {
  if (!presence) {
    return { state: 'away', assurance: 'low', source: 'schedule', changedAt: now, expiresAt: null };
  }

  if (presence.expiresAt !== null && presence.expiresAt.getTime() <= now.getTime()) {
    // A lapsed lock stays locked. Clearing it is a decision somebody makes.
    if (presence.state === 'locked') return presence;
    return { ...presence, state: 'away', assurance: 'low' };
  }

  return presence;
}
