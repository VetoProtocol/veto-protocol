/**
 * The thing that calls the delivery worker (spec §5.4).
 *
 * `drainDeliveries` has always known how to send a batch, retry with backoff and
 * give up after enough attempts. Nothing called it: `/alerts` had a "deliver
 * now" button, which was honest about there being no cron rather than draining
 * silently when somebody happened to load a page.
 *
 * ## Why a loop here rather than an external cron
 *
 * An external cron would need a credential, a route to call, and a workspace to
 * name — and §5.4's retry schedule starts at ten seconds, which is finer than a
 * cron reaches. The interval belongs next to the backoff it serves.
 *
 * ## Concurrency is the queue's problem, not this file's
 *
 * `drainDeliveries` claims rows `for update skip locked`, so two schedulers
 * split the queue rather than both sending the same event. That is what makes
 * it safe to run one of these in every API instance instead of electing a
 * leader — a receiver getting one event twice is survivable, it has an
 * idempotency key, but it is not worth causing.
 *
 * ## It never throws
 *
 * A background loop that dies on one bad tick stops delivering for everybody,
 * silently, until somebody notices the queue. Every tick is wrapped; a failure
 * is logged and the next tick happens anyway.
 */

import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import { drainDeliveries, type DeliveryDeps, type DrainResult } from './delivery.ts';

/**
 * How often to look.
 *
 * Five seconds. The first retry in `BACKOFF_SECONDS` is ten, so this is fine
 * enough that the schedule means what it says, and coarse enough that an idle
 * queue costs one cheap query a tick.
 */
export const TICK_MS = 5_000;

export interface SchedulerDeps extends DeliveryDeps {
  readonly pool: Pool;
  /** Structured, and never carrying a payload — invariant 5 applies to a worker. */
  readonly log: {
    error(details: Record<string, unknown>, message: string): void;
    info(details: Record<string, unknown>, message: string): void;
  };
}

export interface TickResult {
  readonly workspaces: number;
  readonly delivered: number;
  readonly retrying: number;
  readonly failed: number;
}

/**
 * One pass: find the workspaces with work, drain each.
 *
 * Exported so a test can run exactly one tick rather than start a timer and
 * wait — a scheduler tested through its own interval is a slow test that
 * sometimes fails.
 */
export async function tick(deps: SchedulerDeps): Promise<TickResult> {
  // The one cross-tenant read: workspace ids and nothing else. See migration
  // 0018 for why this is a function and what it deliberately cannot say.
  const client = await deps.pool.connect();
  let workspaceIds: string[];
  try {
    const { rows } = await client.query<{ workspace_id: string }>(
      'select workspace_id from due_delivery_workspaces()',
    );
    workspaceIds = rows.map((row) => row.workspace_id);
  } finally {
    client.release();
  }

  let delivered = 0;
  let retrying = 0;
  let failed = 0;

  for (const workspaceId of workspaceIds) {
    // Each workspace drains inside its own transaction, scoped normally. The
    // function above said where to look; row-level security still governs
    // everything read here.
    let result: DrainResult;
    try {
      result = await withWorkspace(deps.pool, workspaceId, (db) =>
        drainDeliveries(db, deps, workspaceId),
      );
    } catch (error) {
      // One workspace failing must not stop the others. The id is safe to log —
      // it is a tenant name, not a payload.
      deps.log.error(
        { workspaceId, err: String(error).slice(0, 160) },
        'webhook drain failed for one workspace',
      );
      continue;
    }
    delivered += result.delivered;
    retrying += result.retrying;
    failed += result.failed;
  }

  return { workspaces: workspaceIds.length, delivered, retrying, failed };
}

export interface Scheduler {
  /** Stop after the tick in flight. Safe to call twice. */
  stop(): void;
}

/**
 * Start ticking.
 *
 * Returns a handle rather than running forever unattended, so a process can
 * shut down without leaving a timer holding the event loop open.
 */
export function startScheduler(deps: SchedulerDeps, tickMs = TICK_MS): Scheduler {
  let stopped = false;
  let running = false;

  const timer = setInterval(() => {
    // Skip rather than overlap. A slow receiver must not cause ticks to pile up
    // on top of each other.
    if (stopped || running) return;
    running = true;

    void tick(deps)
      .then((result) => {
        if (result.delivered > 0 || result.failed > 0) {
          deps.log.info({ ...result }, 'webhook deliveries drained');
        }
      })
      .catch((error: unknown) => {
        deps.log.error(
          { err: String(error).slice(0, 160) },
          'webhook scheduler tick failed; continuing',
        );
      })
      .finally(() => {
        running = false;
      });
  }, tickMs);

  // Never hold the process open on its own account.
  timer.unref?.();

  return {
    stop() {
      stopped = true;
      clearInterval(timer);
    },
  };
}
