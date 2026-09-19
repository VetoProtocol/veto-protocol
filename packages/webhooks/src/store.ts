/**
 * Endpoints, and the delivery queue (spec §5.4).
 *
 * `enqueue` is the half every emitter calls, and it takes a `Db` rather than a
 * `Pool` on purpose: the caller passes the transaction that is already writing
 * the thing being announced, so the event and the fact it describes commit
 * together. An event for something that rolled back is a lie, and an event
 * missing for something that committed is a hole — one transaction removes both
 * possibilities.
 *
 * Nothing here makes a network request. Delivery is `delivery.ts`, running
 * outside the request, because a receiver that hangs must not be able to hold
 * up a decision.
 */

import { randomBytes } from 'node:crypto';
import { newId } from '@veto/core';
import type { Db } from '@veto/db';
import { open, seal, type EncryptionContext, type KeyWrapper } from '@veto/vault';
import { WEBHOOK_EVENTS, type WebhookEvent, type WebhookEventData, type WebhookEventType } from './events.ts';

/** Bound into the AEAD, so an endpoint secret cannot be opened as anything else. */
export const SIGNING_SECRET_PURPOSE = 'webhook.endpoint.signing_secret';

export const contextFor = (workspaceId: string, endpointId: string): EncryptionContext => ({
  workspaceId,
  purpose: SIGNING_SECRET_PURPOSE,
  resourceId: endpointId,
});

export interface Endpoint {
  readonly id: string;
  readonly url: string;
  readonly events: readonly WebhookEventType[];
  readonly status: 'active' | 'disabled';
  readonly createdAt: Date;
  readonly disabledAt: Date | null;
}

export interface CreateEndpointInput {
  readonly workspaceId: string;
  readonly url: string;
  readonly events: readonly WebhookEventType[];
  readonly createdBy: string;
}

export interface CreatedEndpoint {
  readonly endpoint: Endpoint;
  /**
   * The signing secret, in the clear, exactly once.
   *
   * Generated here rather than accepted from the caller: a secret somebody
   * chose is a secret somebody can guess, and one that arrived over the wire
   * has already been somewhere it should not have been. It is returned on
   * creation and never again — there is no read path, only rotation.
   */
  readonly secret: string;
}

export async function createEndpoint(
  db: Db,
  wrapper: KeyWrapper,
  input: CreateEndpointInput,
): Promise<CreatedEndpoint> {
  const id = newId('whe_');
  // 32 bytes. The MAC is HMAC-SHA256, so a longer secret buys nothing and a
  // shorter one is the only thing an attacker would attack.
  const secret = randomBytes(32).toString('base64url');
  const sealed = await seal(wrapper, secret, contextFor(input.workspaceId, id));

  const { rows } = await db.query<EndpointRow>(
    `insert into webhook_endpoints
       (id, workspace_id, url, secret_sealed, secret_key_id, events, created_by)
     values ($1,$2,$3,$4,$5,$6,$7)
     returning id, url, events, status, created_at, disabled_at`,
    [id, input.workspaceId, input.url, sealed.blob, sealed.keyId, [...input.events], input.createdBy],
  );

  const row = rows[0];
  if (!row) throw new Error('endpoint insert returned no row');

  return { endpoint: toEndpoint(row), secret };
}

export async function listEndpoints(db: Db, workspaceId: string): Promise<Endpoint[]> {
  const { rows } = await db.query<EndpointRow>(
    `select id, url, events, status, created_at, disabled_at
       from webhook_endpoints where workspace_id = $1 order by created_at desc`,
    [workspaceId],
  );
  return rows.map(toEndpoint);
}

/**
 * Stop sending, without forgetting.
 *
 * Disabled rather than deleted, because the deliveries reference it and because
 * "this endpoint used to receive your security alerts" is a fact worth keeping
 * after somebody turns it off.
 */
export async function disableEndpoint(
  db: Db,
  workspaceId: string,
  endpointId: string,
): Promise<boolean> {
  const { rowCount } = await db.query(
    `update webhook_endpoints
        set status = 'disabled', disabled_at = now()
      where workspace_id = $1 and id = $2 and status = 'active'`,
    [workspaceId, endpointId],
  );
  return (rowCount ?? 0) > 0;
}

export interface EnqueueInput {
  readonly workspaceId: string;
  readonly type: WebhookEventType;
  readonly data: WebhookEventData;
  readonly correlationId?: string | null;
}

/**
 * Fan one event out to every endpoint that asked for it.
 *
 * Returns the delivery ids created, which is zero when nobody subscribed —
 * the normal case for a workspace with no endpoints, and not an error. An
 * emitter never depends on the result.
 *
 * `on conflict do nothing` against the (endpoint, event) uniqueness makes this
 * safe to call twice for the same event id: a caller retrying after a partial
 * failure produces one delivery, not two.
 */
export async function enqueue(db: Db, input: EnqueueInput): Promise<readonly string[]> {
  const eventId = newId('evt_');

  const { rows: endpoints } = await db.query<{ id: string }>(
    `select id from webhook_endpoints
      where workspace_id = $1 and status = 'active' and $2 = any (events)`,
    [input.workspaceId, input.type],
  );

  if (endpoints.length === 0) return [];

  const created: string[] = [];
  for (const endpoint of endpoints) {
    const deliveryId = newId('whd_');
    const payload: WebhookEvent = {
      id: eventId,
      type: input.type,
      workspace_id: input.workspaceId,
      occurred_at: new Date().toISOString(),
      correlation_id: input.correlationId ?? null,
      data: input.data,
    };

    const { rows } = await db.query<{ id: string }>(
      `insert into webhook_deliveries
         (id, workspace_id, endpoint_id, event_id, event_type, payload)
       values ($1,$2,$3,$4,$5,$6)
       on conflict (workspace_id, endpoint_id, event_id) do nothing
       returning id`,
      [deliveryId, input.workspaceId, endpoint.id, eventId, input.type, JSON.stringify(payload)],
    );

    const row = rows[0];
    if (row) created.push(row.id);
  }

  return created;
}

export interface DeliveryRow {
  readonly id: string;
  readonly endpoint_id: string;
  readonly event_id: string;
  readonly event_type: string;
  readonly payload: WebhookEvent;
  readonly status: 'pending' | 'delivered' | 'failed';
  readonly attempts: number;
  readonly next_attempt_at: Date;
  readonly last_status: number | null;
  readonly last_error: string | null;
  readonly delivered_at: Date | null;
  readonly occurred_at: Date;
}

export async function listDeliveries(
  db: Db,
  workspaceId: string,
  limit: number,
): Promise<DeliveryRow[]> {
  const { rows } = await db.query<DeliveryRow>(
    `select id, endpoint_id, event_id, event_type, payload, status, attempts,
            next_attempt_at, last_status, last_error, delivered_at, occurred_at
       from webhook_deliveries
      where workspace_id = $1
      order by occurred_at desc
      limit $2`,
    [workspaceId, limit],
  );
  return rows;
}

/**
 * Read an endpoint's signing secret.
 *
 * Module-private in spirit and named so: only the delivery worker calls it, and
 * it holds the value for the length of one signature. There is no HTTP route
 * that returns this, which is why `createEndpoint` gives it to the operator
 * once and the only recovery is to make a new endpoint.
 */
export async function revealSigningSecretForDelivery(
  db: Db,
  wrapper: KeyWrapper,
  workspaceId: string,
  endpointId: string,
): Promise<string> {
  const { rows } = await db.query<{ secret_sealed: Buffer; secret_key_id: string }>(
    `select secret_sealed, secret_key_id from webhook_endpoints
      where workspace_id = $1 and id = $2`,
    [workspaceId, endpointId],
  );

  const row = rows[0];
  if (!row) throw new Error('no such endpoint');

  return open(
    wrapper,
    { blob: row.secret_sealed, keyId: row.secret_key_id },
    contextFor(workspaceId, endpointId),
  );
}

interface EndpointRow {
  id: string;
  url: string;
  events: string[];
  status: 'active' | 'disabled';
  created_at: Date;
  disabled_at: Date | null;
}

const toEndpoint = (row: EndpointRow): Endpoint => ({
  id: row.id,
  url: row.url,
  // Filtered rather than cast. A row written by an older build could name an
  // event this build does not have, and silently claiming it does would be
  // worse than dropping it.
  events: row.events.filter((e): e is WebhookEventType =>
    (WEBHOOK_EVENTS as readonly string[]).includes(e),
  ),
  status: row.status,
  createdAt: row.created_at,
  disabledAt: row.disabled_at,
});
