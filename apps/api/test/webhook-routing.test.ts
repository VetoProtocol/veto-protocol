/**
 * Routing an alert endpoint to one person, over HTTP (migration 0029).
 *
 * Only the delegating user can resolve their own challenge (invariant 7), so
 * an `approval.requested` alert has exactly one correct recipient. These are
 * about the boundary on *asking* for that: a caller may route an endpoint to
 * themselves and has no way to route one to anybody else.
 *
 * `checkDestination` runs on the URL before anything is stored (§12.1 SSRF),
 * so the receivers here are public names that resolve.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_whr${s}`;
const ALICE = `usr_alice${s}`;
const BOB = `usr_bob${s}`;

let urlCounter = 0;
/**
 * A distinct public URL per endpoint — one endpoint per URL per workspace.
 *
 * `example.com` rather than a made-up subdomain, because `checkDestination`
 * resolves the host for real before storing anything: a name that does not
 * exist is refused with `DESTINATION_NOT_PERMITTED`, which is the SSRF guard
 * working rather than a test fixture problem.
 */
const receiver = () => `https://example.com/veto-${s}-${(urlCounter += 1)}`;

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE, BOB]);

  app = createApp({
    pool,
    redis,
    policy: createFakePolicyFacts(),
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    authenticate: headerAuthenticator(),
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const create = (body: Record<string, unknown>, user = ALICE) =>
  app.inject({ method: 'POST', url: '/v1/webhooks', headers: as(WS, user), payload: body });

describe('routing an endpoint to yourself', () => {
  it('routes to the authenticated user, not to a value from the body', async () => {
    const res = await create({
      url: receiver(),
      events: ['approval.requested'],
      route_to: 'me',
    });

    expect(res.statusCode).toBe(201);
    expect(res.json().route_to_user_id).toBe(ALICE);
  });

  it('is workspace-wide when nothing asks otherwise', async () => {
    // Every endpoint behaved this way before the column existed, and the
    // default has to keep behaving that way.
    const res = await create({ url: receiver(), events: ['workspace.locked'] });

    expect(res.statusCode).toBe(201);
    expect(res.json().route_to_user_id).toBeNull();
  });

  it('gives the same caller a different target when a different person asks', async () => {
    const mine = await create({ url: receiver(), events: ['approval.requested'], route_to: 'me' });
    const theirs = await create(
      { url: receiver(), events: ['approval.requested'], route_to: 'me' },
      BOB,
    );

    expect(mine.json().route_to_user_id).toBe(ALICE);
    expect(theirs.json().route_to_user_id).toBe(BOB);
  });
});

describe('what a caller cannot ask for', () => {
  it('refuses a named user id outright', async () => {
    // The field has no way to say "somebody else". A caller naming an
    // arbitrary id would be asking to receive another person's alerts, and
    // the only safe answer is a refusal — so the schema does not accept the
    // question. `additionalProperties: false` is what makes this a 400
    // rather than a silently ignored key.
    const res = await create({
      url: receiver(),
      events: ['approval.requested'],
      route_to_user_id: BOB,
    });

    expect(res.statusCode).toBe(400);
  });

  it('refuses any route_to value but "me"', async () => {
    for (const value of [BOB, 'everyone', 'all', '']) {
      const res = await create({
        url: receiver(),
        events: ['approval.requested'],
        route_to: value,
      });
      expect(res.statusCode).toBe(400);
    }
  });

  it('still refuses an unsafe destination, routed or not', async () => {
    // Routing does not open a second path past the SSRF check.
    const res = await create({
      url: 'http://169.254.169.254/latest/meta-data/',
      events: ['approval.requested'],
      route_to: 'me',
    });

    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect(res.statusCode).toBeLessThan(500);
  });
});

describe('what the screen can show', () => {
  it('reports the routing target when listing', async () => {
    const created = await create({
      url: receiver(),
      events: ['approval.requested'],
      route_to: 'me',
    });

    const list = await app.inject({
      method: 'GET',
      url: '/v1/webhooks',
      headers: as(WS, ALICE),
    });

    const found = list
      .json()
      .endpoints.find((e: { id: string }) => e.id === created.json().id);

    expect(found.route_to_user_id).toBe(ALICE);
  });

  it('does not leak another workspace’s endpoints', async () => {
    const other = `ws_whr2${s}`;
    const carol = `usr_carol${s}`;
    await seed(pool, other, [carol]);

    await create({ url: receiver(), events: ['approval.requested'], route_to: 'me' });

    const theirs = await app.inject({
      method: 'GET',
      url: '/v1/webhooks',
      headers: as(other, carol),
    });

    expect(theirs.json().endpoints).toEqual([]);
  });

  it('writes a routed endpoint against the right tenant', async () => {
    const created = await create({
      url: receiver(),
      events: ['approval.requested'],
      route_to: 'me',
    });

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ route_to_user_id: string | null; workspace_id: string }>(
        `select route_to_user_id, workspace_id from webhook_endpoints where id = $1`,
        [created.json().id],
      ),
    );

    expect(rows[0]?.workspace_id).toBe(WS);
    expect(rows[0]?.route_to_user_id).toBe(ALICE);
  });
});
