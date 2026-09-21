/**
 * The scheduler, one tick at a time.
 *
 * `tick` is exported so these run it directly rather than starting a timer and
 * waiting — a scheduler tested through its own interval is a slow test that
 * sometimes fails for reasons that have nothing to do with the code.
 *
 * What matters here is not that a delivery succeeds; `delivery.test.ts` covers
 * that. It is that one workspace's failure does not stop the others, and that a
 * tick never throws — a background loop that dies on a bad tick stops
 * delivering for everybody, silently, until somebody notices the queue.
 */

import { describe, expect, it, vi } from 'vitest';
import { startScheduler, tick, TICK_MS } from '../src/scheduler.ts';

const silentLog = { error: vi.fn(), info: vi.fn() };

/** A pool whose one query answers with the workspaces we want to see tried. */
const poolOf = (workspaceIds: readonly string[], onConnect?: () => void) =>
  ({
    async connect() {
      onConnect?.();
      return {
        query: async () => ({ rows: workspaceIds.map((workspace_id) => ({ workspace_id })) }),
        release() {},
      };
    },
  }) as never;

describe('one tick', () => {
  it('reports nothing to do when no workspace has work', async () => {
    const result = await tick({
      pool: poolOf([]),
      wrapper: {} as never,
      checkDestination: async () => ({ ok: true }),
      log: silentLog,
    });
    expect(result).toEqual({ workspaces: 0, delivered: 0, retrying: 0, failed: 0 });
  });

  it('asks the database only for workspace ids', async () => {
    let sql = '';
    const pool = {
      async connect() {
        return {
          query: async (text: string) => {
            sql = text;
            return { rows: [] };
          },
          release() {},
        };
      },
    } as never;

    await tick({
      pool,
      wrapper: {} as never,
      checkDestination: async () => ({ ok: true }),
      log: silentLog,
    });

    // The one cross-tenant read in this path returns a workspace id and nothing
    // else — no payload, no endpoint, no event type. See migration 0018.
    expect(sql).toContain('due_delivery_workspaces()');
    expect(sql).toContain('workspace_id');
    expect(sql).not.toMatch(/payload|endpoint|event_type/);
  });

  it('keeps going when one workspace fails', async () => {
    const log = { error: vi.fn(), info: vi.fn() };
    // Three workspaces, and `withWorkspace` will refuse all of them because the
    // ids are malformed — which is the failure path under test.
    const result = await tick({
      pool: poolOf(['not-a-workspace', 'also-bad', 'still-bad']),
      wrapper: {} as never,
      checkDestination: async () => ({ ok: true }),
      log,
    });

    // It tried all three rather than stopping at the first.
    expect(log.error).toHaveBeenCalledTimes(3);
    expect(result.workspaces).toBe(3);
    expect(result.delivered).toBe(0);
  });

  it('logs the workspace and the reason, never a payload', async () => {
    const log = { error: vi.fn(), info: vi.fn() };
    await tick({
      pool: poolOf(['not-a-workspace']),
      wrapper: {} as never,
      checkDestination: async () => ({ ok: true }),
      log,
    });

    const [details] = log.error.mock.calls[0] as [Record<string, unknown>, string];
    expect(Object.keys(details).sort()).toEqual(['err', 'workspaceId']);
  });
});

describe('the loop around it', () => {
  it('stops when told, and stopping twice is not an error', () => {
    const scheduler = startScheduler(
      { pool: poolOf([]), wrapper: {} as never, checkDestination: async () => ({ ok: true }), log: silentLog },
      60_000,
    );
    expect(() => {
      scheduler.stop();
      scheduler.stop();
    }).not.toThrow();
  });

  it('ticks faster than the first retry it serves', () => {
    // BACKOFF_SECONDS starts at 10s. A scheduler slower than that would make
    // the published retry schedule a fiction.
    expect(TICK_MS).toBeLessThan(10_000);
  });
});
