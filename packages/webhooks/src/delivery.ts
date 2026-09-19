/**
 * Draining the queue (spec §5.4).
 *
 * Runs outside any request. That is the whole reason the queue is a table: a
 * receiver that hangs for thirty seconds must not be able to hold a decision
 * open for thirty seconds, and §11's authorization budget is 200 ms.
 *
 * ## The destination check is injected, not imported
 *
 * A webhook target is a caller-supplied URL that this server fetches from
 * inside the network perimeter, which is §12.1's SSRF scenario wearing a
 * different hat. The check that catches it lives in `@veto/decisions`, and this
 * package sits below that in the dependency graph — emitters in decisions call
 * `enqueue` here, so importing decisions back would be a cycle. So it arrives
 * as a port, the way `KeyWrapper` and `PolicyDecisions` do.
 *
 * It is **not optional**. There is no default that skips it: a caller that has
 * nothing to pass cannot construct a worker.
 *
 * ## Backoff
 *
 * Six attempts over about two and a half hours, then the delivery is `failed`
 * and stays in the table. Failed, not deleted — "we tried to tell you and could
 * not" is exactly the fact an operator needs after an incident.
 */

import type { Db } from '@veto/db';
import type { KeyWrapper } from '@veto/vault';
import { signDelivery } from './signature.ts';
import { revealSigningSecretForDelivery, type DeliveryRow } from './store.ts';

/**
 * Seconds before each attempt. Index is the attempt number just completed, so
 * the first failure waits ten seconds and running off the end ends the road.
 */
export const BACKOFF_SECONDS = [10, 60, 300, 1800, 7200] as const;
export const MAX_ATTEMPTS = BACKOFF_SECONDS.length + 1;

/** How long a receiver gets. Generous for a webhook, and still a hard ceiling. */
export const DELIVERY_TIMEOUT_MS = 10_000;

/**
 * The SSRF check, as a port.
 *
 * Mirrors `checkDestination` in `@veto/decisions`: it answers whether this
 * server is allowed to make a request to that URL at all.
 */
export interface DestinationCheck {
  (url: string): Promise<{ ok: boolean; reason?: string }>;
}

export interface DeliveryDeps {
  readonly wrapper: KeyWrapper;
  readonly checkDestination: DestinationCheck;
  /** Injected so tests do not need a listening socket. */
  readonly fetch?: typeof globalThis.fetch;
}

export interface DrainResult {
  readonly attempted: number;
  readonly delivered: number;
  readonly retrying: number;
  readonly failed: number;
}

/**
 * Deliver everything that is due, once each.
 *
 * Rows are claimed with `for update skip locked`, so two workers running at the
 * same time split the queue instead of both sending the same event. A receiver
 * getting one event twice is survivable — it has an idempotency key — but it is
 * not something to cause on purpose.
 */
export async function drainDeliveries(
  db: Db,
  deps: DeliveryDeps,
  workspaceId: string,
  batchSize = 20,
): Promise<DrainResult> {
  const { rows } = await db.query<DeliveryRow & { endpoint_url: string }>(
    `select d.id, d.endpoint_id, d.event_id, d.event_type, d.payload, d.status,
            d.attempts, d.next_attempt_at, d.last_status, d.last_error,
            d.delivered_at, d.occurred_at, e.url as endpoint_url
       from webhook_deliveries d
       join webhook_endpoints e
         on e.workspace_id = d.workspace_id and e.id = d.endpoint_id
      where d.workspace_id = $1
        and d.status = 'pending'
        and d.next_attempt_at <= now()
        and e.status = 'active'
      order by d.next_attempt_at
      limit $2
      for update of d skip locked`,
    [workspaceId, batchSize],
  );

  let delivered = 0;
  let retrying = 0;
  let failed = 0;

  for (const row of rows) {
    const outcome = await attempt(db, deps, workspaceId, row);
    if (outcome === 'delivered') delivered += 1;
    else if (outcome === 'failed') failed += 1;
    else retrying += 1;
  }

  return { attempted: rows.length, delivered, retrying, failed };
}

type Outcome = 'delivered' | 'retrying' | 'failed';

async function attempt(
  db: Db,
  deps: DeliveryDeps,
  workspaceId: string,
  row: DeliveryRow & { endpoint_url: string },
): Promise<Outcome> {
  // Re-checked on every attempt, not only at registration. DNS can change after
  // an endpoint is approved, and a name that resolved to the public internet
  // last week can resolve to the metadata service today — which is what makes
  // this a rebinding defence rather than a one-time validation.
  const destination = await deps.checkDestination(row.endpoint_url);
  if (!destination.ok) {
    // Not retried. A private address does not become public by waiting, and
    // repeatedly attempting it is the SSRF attempt happening on a schedule.
    return record(db, workspaceId, row, 'failed', null, destination.reason ?? 'destination refused');
  }

  const body = JSON.stringify(row.payload);

  let secret: string;
  try {
    secret = await revealSigningSecretForDelivery(db, deps.wrapper, workspaceId, row.endpoint_id);
  } catch {
    // An unopenable secret is a configuration or key problem, not a transient
    // one. Sending unsigned would be worse than not sending.
    return record(db, workspaceId, row, 'failed', null, 'signing secret unavailable');
  }

  // A fresh timestamp for this attempt, the same event id as every other. See
  // signature.ts — the id is what makes the retry recognisable as a duplicate.
  const signed = signDelivery(secret, { eventId: row.event_id, body });

  const send = deps.fetch ?? globalThis.fetch;
  let status: number;
  try {
    const response = await send(row.endpoint_url, {
      method: 'POST',
      headers: signed.headers,
      body: signed.body,
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
      // A 30x to somewhere else is a destination this server never checked.
      redirect: 'error',
    });
    status = response.status;
  } catch (error) {
    // The message is ours, never the receiver's. An error page is somebody
    // else's content and may echo what we sent it.
    return retryOrFail(db, workspaceId, row, null, describe(error));
  }

  if (status >= 200 && status < 300) {
    return record(db, workspaceId, row, 'delivered', status, null);
  }

  return retryOrFail(db, workspaceId, row, status, `receiver answered ${status}`);
}

async function retryOrFail(
  db: Db,
  workspaceId: string,
  row: DeliveryRow,
  status: number | null,
  error: string,
): Promise<Outcome> {
  const attempts = row.attempts + 1;
  const wait = BACKOFF_SECONDS[attempts - 1];

  if (wait === undefined) {
    return record(db, workspaceId, row, 'failed', status, error);
  }

  await db.query(
    `update webhook_deliveries
        set attempts = $3, next_attempt_at = now() + make_interval(secs => $4),
            last_status = $5, last_error = $6
      where workspace_id = $1 and id = $2`,
    [workspaceId, row.id, attempts, wait, status, truncate(error)],
  );

  return 'retrying';
}

async function record(
  db: Db,
  workspaceId: string,
  row: DeliveryRow,
  status: 'delivered' | 'failed',
  code: number | null,
  error: string | null,
): Promise<Outcome> {
  await db.query(
    `update webhook_deliveries
        set status = $3,
            attempts = $4,
            delivered_at = case when $3 = 'delivered' then now() else null end,
            last_status = $5,
            last_error = $6
      where workspace_id = $1 and id = $2`,
    [workspaceId, row.id, status, row.attempts + 1, code, error === null ? null : truncate(error)],
  );
  return status;
}

/** The column is capped at 200; truncate rather than let the update fail. */
const truncate = (value: string): string =>
  value.length <= 200 ? value : `${value.slice(0, 197)}...`;

function describe(error: unknown): string {
  const name = error instanceof Error ? error.name : '';
  if (name === 'TimeoutError' || name === 'AbortError') return 'receiver timed out';
  // The class of failure, not the library's message: that can contain the URL
  // with whatever a caller put in its query string.
  return 'could not reach receiver';
}
