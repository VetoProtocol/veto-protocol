/**
 * The eight events (spec §5.4), and what they are allowed to say.
 *
 * ## The payload is the control
 *
 * Invariant 5 forbids secrets and protected content in anything that leaves the
 * system, and a webhook leaves the system harder than a log does: it goes to a
 * URL somebody else chose, over a network, to a receiver we know nothing about.
 * So the payload type has no field that could carry a document body, a token, a
 * set of tool arguments or a passkey challenge — the same move `AuditEventInput`
 * makes. Keeping it unrepresentable beats remembering not to.
 *
 * What an event carries is: what happened, to which named object, when, and a
 * correlation id. A receiver that needs more asks the API with its own
 * credentials, which is the point at which authorization happens again.
 *
 * ## Why the set is closed
 *
 * §5.4 names eight. A ninth would be a change to a published contract, and a
 * typo in an emitter should be a compile error rather than an event nobody
 * subscribed to and nobody noticed was missing.
 */

export const WEBHOOK_EVENTS = [
  'decision.denied',
  'approval.requested',
  'approval.resolved',
  'agent.revoked',
  'workspace.locked',
  'connection.expired',
  'credential.revoked',
  'risk.anomaly_detected',
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENTS)[number];

export const isWebhookEvent = (value: string): value is WebhookEventType =>
  (WEBHOOK_EVENTS as readonly string[]).includes(value);

/**
 * One line of plain English per event, for the dashboard and the docs.
 *
 * Held beside the names rather than in a template somewhere, so an event and
 * its explanation cannot drift apart.
 */
export const EVENT_MEANING: Readonly<Record<WebhookEventType, string>> = {
  'decision.denied': 'An agent asked for something and was refused.',
  'approval.requested': 'Someone needs to approve an action before it can happen.',
  'approval.resolved': 'A pending approval was approved or refused.',
  'agent.revoked': 'An agent was cut off. Its next request is already being refused.',
  'workspace.locked': 'The emergency lock was thrown. Everything is denied.',
  'connection.expired': 'A connected account stopped working.',
  'credential.revoked': 'A stored credential was destroyed.',
  'risk.anomaly_detected': 'Something unusual was spotted in a request.',
};

/**
 * The body of an event.
 *
 * Every field is an identifier, a code, or a timestamp. There is deliberately
 * no `arguments`, `content`, `token`, `body` or `challenge` — adding one would
 * be a change to this type, which is a change a reviewer sees.
 */
export interface WebhookEvent {
  /** Stable across every delivery attempt. An idempotent consumer keys on this. */
  readonly id: string;
  readonly type: WebhookEventType;
  readonly workspace_id: string;
  readonly occurred_at: string;
  /** One id spans request, decision, approval, upstream call and audit event. */
  readonly correlation_id: string | null;
  readonly data: WebhookEventData;
}

/**
 * What the event is about.
 *
 * Names, not contents. `resource_ref` is the same string the audit trail uses —
 * a type and an id, such as `google_file:/Finance/payroll.csv` — which is a
 * classification and not the thing itself.
 */
export interface WebhookEventData {
  readonly agent_id?: string | null;
  readonly human_id?: string | null;
  readonly decision_id?: string | null;
  readonly approval_id?: string | null;
  readonly connection_id?: string | null;
  readonly resource_ref?: string | null;
  readonly reason_code?: string | null;
  readonly outcome?: 'allow' | 'deny' | 'challenge' | null;
  /** Counts, for events that describe a sweep — how much a lock stopped. */
  readonly grants_revoked?: number | null;
  readonly sessions_dropped?: number | null;
  /** OAuth refresh chains killed. A chain outlives every token it issued. */
  readonly oauth_chains_revoked?: number | null;
  /**
   * Where the delegating user goes to resolve this approval.
   *
   * A Veto-controlled dashboard URL and never a third party's (invariant 8),
   * carrying an approval id and nothing else — no challenge, no arguments, no
   * resource contents. It is safe to send because it confers nothing:
   * `routes/approvals.ts` refuses anyone but the delegator with
   * `APPROVER_NOT_DELEGATOR`, and refuses them too without a passkey assertion
   * over that approval's own stored challenge. The link saves somebody finding
   * the page; it is not a way in.
   *
   * Absent when the emitter has no dashboard origin configured. A missing link
   * makes the alert less useful, never less safe, so it is omitted rather than
   * guessed.
   */
  readonly approval_url?: string | null;
}
