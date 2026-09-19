/**
 * The delivery queue against a real database (spec §5.4).
 *
 * The signature scheme has its own file. This one is about the queue: who gets
 * an event, what happens when a receiver is down, when the system gives up, and
 * what it refuses to send to at all.
 *
 * `fetch` is injected, so nothing here opens a socket. That matters beyond
 * speed — a test that really posted to a URL would be a test that behaves
 * differently on a machine with different DNS.
 */

import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { createPool, withWorkspace, type Db } from '@veto/db';
import { createLocalKeyWrapper } from '@veto/vault';
import {
  BACKOFF_SECONDS,
  createEndpoint,
  disableEndpoint,
  drainDeliveries,
  enqueue,
  listDeliveries,
  listEndpoints,
  verifyDelivery,
  type DeliveryDeps,
} from '../src/index.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const wrapper = createLocalKeyWrapper(randomBytes(32).toString('base64'));

let pool: Pool;
const s = Math.random().toString(36).slice(2, 10);
const WS = `ws_wh${s}`;
const OTHER_WS = `ws_wo${s}`;
const USER = `usr_wh${s}`;
const OTHER_USER = `usr_wo${s}`;

const RECEIVER = 'https://hooks.example.com/veto';
const OTHER_RECEIVER = 'https://other.example.com/veto';

/** Everything resolves, unless a test says otherwise. */
const allowAll = async (): Promise<{ ok: boolean; reason?: string }> => ({ ok: true });

interface Recorded {
  url: string;
  headers: Record<string, string>;
  body: string;
}

/** A receiver that answers however the test wants, and remembers what arrived. */
function fakeReceiver(status = 200) {
  const seen: Recorded[] = [];
  const state = {
    seen,
    status,
    throws: false,
    fetch: (async (url: unknown, init: unknown) => {
      const request = init as { headers: Record<string, string>; body: string };
      seen.push({ url: String(url), headers: request.headers, body: request.body });
      if (state.throws) throw new Error('connection refused');
      return new Response(null, { status: state.status });
    }) as unknown as typeof globalThis.fetch,
  };
  return state;
}

const deps = (over: Partial<DeliveryDeps> = {}): DeliveryDeps => ({
  wrapper,
  checkDestination: over.checkDestination ?? allowAll,
  // Spread rather than assigned: `exactOptionalPropertyTypes` distinguishes an
  // absent optional property from one explicitly set to undefined, and
  // `DeliveryDeps.fetch` means "use the global one" when absent.
  ...(over.fetch === undefined ? {} : { fetch: over.fetch }),
});

const inWorkspace = <T>(ws: string, fn: (db: Db) => Promise<T>): Promise<T> =>
  withWorkspace(pool, ws, fn);

beforeAll(async () => {
  const runner = process.env['NODE_ENV'];
  try {
    process.loadEnvFile(path.join(here, '..', '..', '..', '.env'));
  } catch {
    /* present */
  }
  if (runner !== undefined) process.env['NODE_ENV'] = runner;
  pool = createPool(process.env['DATABASE_URL'] ?? '');

  // users.id is a global primary key, so each workspace needs its own.
  for (const [ws, user] of [
    [WS, USER],
    [OTHER_WS, OTHER_USER],
  ]) {
    const c = await pool.connect();
    try {
      await c.query('begin');
      await c.query('select set_config($1,$2,true)', ['veto.workspace_id', ws]);
      await c.query(`insert into workspaces (id,name,type) values ($1,$1,'organization')`, [ws]);
      await c.query(`insert into users (id,workspace_id,identity_subject) values ($1,$2,$3)`, [
        user,
        ws,
        `oidc|${user}`,
      ]);
      await c.query('commit');
    } catch (e) {
      await c.query('rollback').catch(() => {});
      throw e;
    } finally {
      c.release();
    }
  }
});

afterAll(async () => {
  await pool.end();
});

beforeEach(async () => {
  // Each test starts with an empty queue, so a count is about what this test
  // produced rather than about test order.
  await inWorkspace(WS, (db) =>
    db.query(`delete from webhook_deliveries where workspace_id = $1`, [WS]),
  );
  await inWorkspace(WS, (db) =>
    db.query(`delete from webhook_endpoints where workspace_id = $1`, [WS]),
  );
});

const register = (events: string[], url = RECEIVER, ws = WS, user = USER) =>
  inWorkspace(ws, (db) =>
    createEndpoint(db, wrapper, {
      workspaceId: ws,
      url,
      events: events as never,
      createdBy: user,
    }),
  );

describe('who gets an event', () => {
  it('sends only to endpoints that subscribed to it', async () => {
    await register(['workspace.locked']);
    await register(['decision.denied'], OTHER_RECEIVER);

    const created = await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: {} }),
    );

    expect(created).toHaveLength(1);
  });

  it('sends nothing when nobody subscribed, and does not treat that as an error', async () => {
    // The normal case for a workspace with no endpoints. An emitter must never
    // depend on the result.
    const created = await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'agent.revoked', data: { agent_id: 'agt_x' } }),
    );
    expect(created).toEqual([]);
  });

  it('skips a disabled endpoint', async () => {
    const { endpoint } = await register(['workspace.locked']);
    await inWorkspace(WS, (db) => disableEndpoint(db, WS, endpoint.id));

    const created = await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: {} }),
    );
    expect(created).toEqual([]);
  });

  it('gives every subscriber the same event id', async () => {
    // One event, two receivers. They must agree on what it was called, or a
    // downstream correlating the two sees two incidents.
    await register(['workspace.locked']);
    await register(['workspace.locked'], OTHER_RECEIVER);

    await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: {} }),
    );

    const rows = await inWorkspace(WS, (db) => listDeliveries(db, WS, 10));
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((r) => r.event_id)).size).toBe(1);
  });

  it('never reaches another workspace’s endpoint', async () => {
    await register(['workspace.locked'], RECEIVER, OTHER_WS, OTHER_USER);

    const created = await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: {} }),
    );

    expect(created).toEqual([]);
  });
});

describe('delivering', () => {
  it('posts a signed body the receiver can verify', async () => {
    const { secret } = await register(['workspace.locked']);
    const receiver = fakeReceiver(200);

    await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: { grants_revoked: 2 } }),
    );
    const result = await inWorkspace(WS, (db) =>
      drainDeliveries(db, deps({ fetch: receiver.fetch }), WS),
    );

    expect(result).toMatchObject({ attempted: 1, delivered: 1, retrying: 0, failed: 0 });

    const sent = receiver.seen[0];
    expect(sent?.url).toBe(RECEIVER);
    // End to end: the secret handed to the operator at registration is the one
    // that verifies what arrived.
    expect(
      verifyDelivery(secret, { body: sent?.body ?? '', headers: sent?.headers ?? {} }),
    ).toMatchObject({ ok: true });
  });

  it('carries no content, no arguments and no tokens', async () => {
    await register(['decision.denied']);
    const receiver = fakeReceiver(200);

    await inWorkspace(WS, (db) =>
      enqueue(db, {
        workspaceId: WS,
        type: 'decision.denied',
        data: {
          agent_id: 'agt_x',
          resource_ref: 'google_file:/Finance/payroll.csv',
          reason_code: 'TOOL_NOT_ALLOWED',
        },
      }),
    );
    await inWorkspace(WS, (db) => drainDeliveries(db, deps({ fetch: receiver.fetch }), WS));

    const body = receiver.seen[0]?.body ?? '';
    // A reference to the resource, which is a classification. Not the file.
    expect(body).toContain('google_file:/Finance/payroll.csv');
    for (const forbidden of ['arguments', 'content', 'token', 'challenge', 'secret']) {
      expect(body, forbidden).not.toContain(forbidden);
    }
  });

  it('marks it delivered exactly once, and does not send it again', async () => {
    await register(['workspace.locked']);
    const receiver = fakeReceiver(200);

    await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: {} }),
    );
    await inWorkspace(WS, (db) => drainDeliveries(db, deps({ fetch: receiver.fetch }), WS));
    const second = await inWorkspace(WS, (db) =>
      drainDeliveries(db, deps({ fetch: receiver.fetch }), WS),
    );

    expect(second.attempted).toBe(0);
    expect(receiver.seen).toHaveLength(1);
  });
});

describe('when the receiver is down', () => {
  it('backs off instead of hammering', async () => {
    await register(['workspace.locked']);
    const receiver = fakeReceiver(503);

    await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: {} }),
    );
    const result = await inWorkspace(WS, (db) =>
      drainDeliveries(db, deps({ fetch: receiver.fetch }), WS),
    );

    expect(result).toMatchObject({ delivered: 0, retrying: 1, failed: 0 });

    const row = (await inWorkspace(WS, (db) => listDeliveries(db, WS, 1)))[0];
    expect(row?.status).toBe('pending');
    expect(row?.attempts).toBe(1);
    expect(row?.last_status).toBe(503);
    // Scheduled forward, so an immediate second drain does not pick it up.
    expect(row?.next_attempt_at.getTime()).toBeGreaterThan(Date.now());

    const immediate = await inWorkspace(WS, (db) =>
      drainDeliveries(db, deps({ fetch: receiver.fetch }), WS),
    );
    expect(immediate.attempted).toBe(0);
  });

  it('gives up after the last attempt, and keeps the row', async () => {
    await register(['workspace.locked']);
    const receiver = fakeReceiver(500);

    await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: {} }),
    );

    // Walk the whole backoff ladder, pulling each attempt forward so the test
    // does not have to wait two and a half hours.
    for (let i = 0; i < BACKOFF_SECONDS.length + 1; i += 1) {
      await inWorkspace(WS, (db) =>
        db.query(`update webhook_deliveries set next_attempt_at = now() where workspace_id = $1`, [
          WS,
        ]),
      );
      await inWorkspace(WS, (db) => drainDeliveries(db, deps({ fetch: receiver.fetch }), WS));
    }

    const row = (await inWorkspace(WS, (db) => listDeliveries(db, WS, 1)))[0];
    // Failed, not deleted. "We tried to tell you and could not" is the fact an
    // operator needs after an incident.
    expect(row?.status).toBe('failed');
    expect(row?.attempts).toBe(BACKOFF_SECONDS.length + 1);
    expect(row?.last_error).toContain('500');
  });

  it('reports a network failure without quoting the receiver', async () => {
    await register(['workspace.locked']);
    const receiver = fakeReceiver(200);
    receiver.throws = true;

    await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: {} }),
    );
    await inWorkspace(WS, (db) => drainDeliveries(db, deps({ fetch: receiver.fetch }), WS));

    const row = (await inWorkspace(WS, (db) => listDeliveries(db, WS, 1)))[0];
    // Our phrase, not the library's message — that can carry the URL with
    // whatever a caller put in its query string.
    expect(row?.last_error).toBe('could not reach receiver');
  });
});

describe('where it refuses to send', () => {
  it('fails a blocked destination immediately and does not retry it', async () => {
    // §12.1's SSRF scenario. A private address does not become public by
    // waiting, so retrying would be the attempt happening on a schedule.
    await register(['workspace.locked']);
    const receiver = fakeReceiver(200);

    await inWorkspace(WS, (db) =>
      enqueue(db, { workspaceId: WS, type: 'workspace.locked', data: {} }),
    );

    const result = await inWorkspace(WS, (db) =>
      drainDeliveries(
        db,
        deps({
          fetch: receiver.fetch,
          checkDestination: async () => ({ ok: false, reason: 'address is private' }),
        }),
        WS,
      ),
    );

    expect(result).toMatchObject({ delivered: 0, retrying: 0, failed: 1 });
    // Nothing was sent. The check runs before the request, not after.
    expect(receiver.seen).toHaveLength(0);

    const row = (await inWorkspace(WS, (db) => listDeliveries(db, WS, 1)))[0];
    expect(row?.status).toBe('failed');
    expect(row?.last_error).toBe('address is private');
  });
});

describe('endpoints', () => {
  it('returns the signing secret once and never stores it in the clear', async () => {
    const { endpoint, secret } = await register(['workspace.locked']);
    expect(secret.length).toBeGreaterThan(20);

    const { rows } = await inWorkspace(WS, (db) =>
      db.query<{ secret_sealed: Buffer }>(
        `select secret_sealed from webhook_endpoints where workspace_id = $1 and id = $2`,
        [WS, endpoint.id],
      ),
    );

    expect(rows[0]?.secret_sealed.toString('utf8')).not.toContain(secret);
  });

  it('lists what it stored, without the secret', async () => {
    await register(['workspace.locked', 'agent.revoked']);
    const listed = await inWorkspace(WS, (db) => listEndpoints(db, WS));

    expect(listed).toHaveLength(1);
    expect(listed[0]?.events).toEqual(['workspace.locked', 'agent.revoked']);
    // The type has no secret field to omit.
    expect(JSON.stringify(listed)).not.toContain('secret');
  });

  it('refuses a second endpoint for the same URL', async () => {
    await register(['workspace.locked']);
    // Two rows for one receiver would double every delivery and halve the value
    // of the idempotency key.
    await expect(register(['agent.revoked'])).rejects.toThrow();
  });
});
