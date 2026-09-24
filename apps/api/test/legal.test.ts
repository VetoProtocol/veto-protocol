/**
 * /v1/legal/acceptance.
 *
 * Two things are being protected here.
 *
 * The **record** must be true: a caller cannot name the version it is agreeing
 * to, cannot agree on somebody else's behalf, and cannot turn a double-click
 * into two agreements.
 *
 * The **versions** must be real. `CURRENT` in the route is what the record
 * says a person read; the "Last updated" line on the page is what they
 * actually read. They are two hand-kept copies in two packages, and this
 * codebase has already been bitten three times by exactly that shape — a
 * service list, a label map, a connection lookup — so the pair is compared
 * here rather than trusted.
 */

import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { createApp } from '../src/app.ts';
import { CURRENT } from '../src/routes/legal.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_lg${s}`;
const OTHER = `ws_lg2${s}`;
const ALICE = `usr_alice${s}`;
const BOB = `usr_bob${s}`;
const CAROL = `usr_carol${s}`;

const dashboard = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
  'apps/dashboard/src/app',
);

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE, BOB]);
  await seed(pool, OTHER, [CAROL]);

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

const get = (ws: string, user: string) =>
  app.inject({ method: 'GET', url: '/v1/legal/acceptance', headers: as(ws, user) });

const accept = (ws: string, user: string) =>
  app.inject({
    method: 'POST',
    url: '/v1/legal/acceptance',
    headers: { ...as(ws, user), 'content-type': 'application/json' },
    payload: {},
  });

describe('published versions', () => {
  it.each(['terms', 'privacy'] as const)(
    'the %s page shows the version the record claims',
    (document) => {
      const page = readFileSync(path.join(dashboard, document, 'page.tsx'), 'utf8');
      const shown = /updated="([^"]+)"/.exec(page)?.[1];
      expect(shown, `no "updated" prop on the ${document} page`).toBeTruthy();

      // The page writes a human date; CURRENT holds ISO. Compare as dates so
      // the two can be written in their own idiom without drifting apart.
      const onPage = new Date(`${shown} UTC`).toISOString().slice(0, 10);
      expect(onPage).toBe(CURRENT[document]);
    },
  );
});

describe('GET /v1/legal/acceptance', () => {
  it('starts with everything outstanding', async () => {
    const response = await get(WS, ALICE);
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.current).toEqual(CURRENT);
    expect([...body.outstanding].sort()).toEqual(['privacy', 'terms']);
  });

  it('refuses an unauthenticated caller', async () => {
    const response = await app.inject({ method: 'GET', url: '/v1/legal/acceptance' });
    expect(response.statusCode).toBe(401);
  });
});

describe('POST /v1/legal/acceptance', () => {
  it('records both documents and settles the account', async () => {
    expect((await accept(WS, ALICE)).statusCode).toBe(200);
    expect((await get(WS, ALICE)).json().outstanding).toEqual([]);
  });

  it('is idempotent — a second click is the same agreement', async () => {
    expect((await accept(WS, ALICE)).statusCode).toBe(200);
    // Inside withWorkspace: legal_acceptances has FORCEd row-level security,
    // so a bare count from outside a tenant returns zero however many rows
    // exist — which reads as "nothing was written" and means nothing at all.
    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ n: number }>(
        `select count(*)::int as n from legal_acceptances
          where workspace_id = $1 and user_id = $2`,
        [WS, ALICE],
      ),
    );
    expect(rows[0]?.n).toBe(2); // terms + privacy, not four
  });

  it('agrees for the caller only, never for a colleague', async () => {
    expect((await get(WS, BOB)).json().outstanding).toHaveLength(2);
  });

  it('accepts no version from the caller, so none can be forged', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/legal/acceptance',
      headers: { ...as(WS, BOB), 'content-type': 'application/json' },
      payload: { terms: '1999-01-01', privacy: '1999-01-01' },
    });
    // The body schema is closed; an unknown property is a refusal, not a
    // silently edited request.
    expect(response.statusCode).toBe(400);
    expect((await get(WS, BOB)).json().outstanding).toHaveLength(2);
  });

  it('does not leak across workspaces', async () => {
    expect((await get(OTHER, CAROL)).json().outstanding).toHaveLength(2);
  });
});
