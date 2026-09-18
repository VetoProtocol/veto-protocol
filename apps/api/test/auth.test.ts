/**
 * Credential scope and sign-in resolution.
 *
 * Two things under test. First, that a credential minted for one purpose
 * cannot be replayed at another — the containment that makes it safe for the
 * dashboard to hold a sign-in credential at all. Second, that the one read
 * allowed to precede a tenant stays as narrow as migration 0007 claims.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { createFakePolicyFacts } from '@veto/permit';
import { mintCapability, verifyCapability } from '@veto/tokens';
import type { FastifyInstance } from 'fastify';
import { createApp } from '../src/app.ts';
import { capabilityAuthenticator, CONTROL_PLANE_AUDIENCE } from '../src/capability-auth.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS_A = `ws_a${s}`;
const WS_B = `ws_b${s}`;
const ALICE = `usr_alice${s}`;
const CAROL = `usr_carol${s}`;
const SECRET = 'q'.repeat(40);

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS_A, [ALICE]);
  await seed(pool, WS_B, [CAROL]);
  app = createApp({
    pool,
    redis,
    policy: createFakePolicyFacts(),
    authenticate: headerAuthenticator(),
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const scoped = (ws: string, user: string, scope: string) => ({ ...as(ws, user), 'x-test-scope': scope });

describe('credential scope', () => {
  it('refuses an agents call made with a sign-in credential', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/agents',
      headers: scoped(WS_A, ALICE, 'identity-resolve'),
    });

    // 403 rather than 401: they are authenticated, just not with this token.
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('TOOL_NOT_ALLOWED');
  });

  it('refuses a resolve call made with a dashboard session credential', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/resolve',
      headers: scoped(WS_A, ALICE, 'control-plane'),
      payload: { subject: `oidc|${ALICE}` },
    });

    expect(res.statusCode).toBe(403);
  });

  it('refuses an unknown scope', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/agents',
      headers: scoped(WS_A, ALICE, 'something-else'),
    });
    expect(res.statusCode).toBe(403);
  });
});

describe('POST /v1/auth/resolve', () => {
  const resolve = (subject: unknown) =>
    app.inject({
      method: 'POST',
      url: '/v1/auth/resolve',
      headers: scoped(WS_A, ALICE, 'identity-resolve'),
      payload: { subject } as object,
    });

  it('finds a user across workspaces without a tenant being set', async () => {
    const res = await resolve(`oidc|${CAROL}`);

    expect(res.statusCode).toBe(200);
    // Carol is in workspace B while the credential names workspace A. That is
    // the point: the caller does not yet know which workspace to ask about.
    expect(res.json().identities).toEqual([{ user_id: CAROL, workspace_id: WS_B }]);
  });

  it('returns an empty list for an unknown subject rather than an error', async () => {
    const res = await resolve(`oidc|nobody-${suffix()}`);
    expect(res.statusCode).toBe(200);
    expect(res.json().identities).toEqual([]);
  });

  it('will not resolve a suspended user', async () => {
    // Sign-in is refused at the database, so no caller has to remember to check.
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query('select set_config($1,$2,true)', ['veto.workspace_id', WS_A]);
      await client.query(`update users set status='suspended' where workspace_id=$1 and id=$2`, [WS_A, ALICE]);
      await client.query('commit');
    } finally {
      client.release();
    }

    expect((await resolve(`oidc|${ALICE}`)).json().identities).toEqual([]);
  });

  it('cannot be used to enumerate', async () => {
    // No prefix, pattern or wildcard reaches the lookup — it is one exact
    // subject or nothing.
    for (const probe of ['oidc|%', '%', 'oidc|', "' or '1'='1"]) {
      expect((await resolve(probe)).json().identities).toEqual([]);
    }
  });

  it('rejects a body with anything extra in it', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/resolve',
      headers: scoped(WS_A, ALICE, 'identity-resolve'),
      payload: { subject: `oidc|${CAROL}`, workspace_id: WS_A },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('capabilityAuthenticator', () => {
  const authenticate = capabilityAuthenticator(SECRET);
  const req = (authorization?: string) =>
    ({ headers: authorization === undefined ? {} : { authorization } }) as never;

  const token = (over: Record<string, unknown> = {}) =>
    mintCapability(SECRET, {
      aud: CONTROL_PLANE_AUDIENCE,
      workspaceId: WS_A,
      humanId: ALICE,
      action: 'control-plane',
      resource: 'agents',
      ttlMs: 60_000,
      ...over,
    });

  it('turns a valid token into a principal', async () => {
    expect(await authenticate(req(`Bearer ${token()}`))).toEqual({
      workspaceId: WS_A,
      userId: ALICE,
      action: 'control-plane',
      agentId: null,
    });
  });

  it('accepts the scheme case-insensitively', async () => {
    expect(await authenticate(req(`bearer ${token()}`))).not.toBeNull();
  });

  it('returns null for every kind of bad credential', async () => {
    const forToken = mintCapability(SECRET, {
      aud: 'veto-gateway',
      workspaceId: WS_A,
      humanId: ALICE,
      action: 'control-plane',
      resource: 'agents',
      ttlMs: 60_000,
    });

    for (const header of [
      undefined,
      '',
      'Basic abc',
      'Bearer',
      'Bearer ',
      'Bearer not-a-token',
      `Bearer ${forToken}`, // minted for a different service
      `Token ${token()}`,
    ]) {
      expect(await authenticate(req(header)), String(header)).toBeNull();
    }
  });

  it('refuses to be built with a weak key', () => {
    expect(() => capabilityAuthenticator('short')).toThrow(/at least 32/);
  });

  it('pins its audience', () => {
    expect(verifyCapability(SECRET, token(), { audience: 'veto-gateway' })).toBeNull();
  });
});
