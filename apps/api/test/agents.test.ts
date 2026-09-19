/**
 * Route tests for /v1/agents.
 *
 * The cross-tenant cases are the point of this file. Everything else here is
 * ordinary CRUD; §12.1 lists IDOR and cross-tenant access as security tests
 * that must pass before the milestone is done, and the domain-level repository
 * tests cannot cover them because the domain never sees an HTTP path parameter.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { randomBytes } from 'node:crypto';
import { createLocalKeyWrapper } from '@veto/vault';
import { createFakePolicyDecisions, createFakePolicyFacts, type FakePolicyFacts } from '@veto/permit';
import { withWorkspace } from '@veto/db';
import { findAgent } from '@veto/identity';
import type { FastifyInstance } from 'fastify';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, setEmergencyLock, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyFacts;
let app: FastifyInstance;

const s = suffix();
const WS_A = `ws_a${s}`;
const WS_B = `ws_b${s}`;
const ALICE = `usr_alice${s}`;
const BOB = `usr_bob${s}`;
const CAROL = `usr_carol${s}`;

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyFacts();
  await seed(pool, WS_A, [ALICE, BOB]);
  await seed(pool, WS_B, [CAROL]);
  app = createApp({
    pool,
    redis,
    policy,
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

const register = (ws: string, user: string, body: unknown) =>
  app.inject({ method: 'POST', url: '/v1/agents', headers: as(ws, user), payload: body as object });

describe('authentication', () => {
  it('refuses every route without a resolvable principal', async () => {
    for (const [method, url] of [
      ['GET', '/v1/agents'],
      ['POST', '/v1/agents'],
      ['GET', '/v1/agents/agt_whatever'],
      ['DELETE', '/v1/agents/agt_whatever'],
    ] as const) {
      const res = await app.inject({ method, url, payload: {} });
      expect(res.statusCode, `${method} ${url}`).toBe(401);
      expect(res.json().error.code).toBe('IDENTITY_UNRESOLVED');
    }
  });

  it('cannot be constructed without an authenticator', () => {
    expect(() =>
      createApp({ pool, redis, policy, decisions: createFakePolicyDecisions(), wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')), authenticate: undefined as never }),
    ).toThrow(/fail closed/);
  });
});

describe('POST /v1/agents', () => {
  it('registers an agent owned by the caller', async () => {
    const res = await register(WS_A, ALICE, { provider: 'mcp', client_id: `claude-desktop-${suffix()}` });

    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.owner_user_id).toBe(ALICE);
    expect(body.workspace_id).toBe(WS_A);
    expect(body.status).toBe('active');
    expect(body.id).toMatch(/^agt_/);
  });

  it('never returns the fingerprint it was given', async () => {
    const res = await register(WS_A, ALICE, {
      provider: 'mcp',
      client_id: `fp-${suffix()}`,
      fingerprint: 'sha256:not-a-secret-but-not-yours-either',
    });

    expect(res.statusCode).toBe(201);
    expect(res.json().has_fingerprint).toBe(true);
    expect(res.payload).not.toContain('not-a-secret-but-not-yours-either');
    expect(Object.keys(res.json())).not.toContain('fingerprint');
  });

  it('rejects an unknown property instead of ignoring it', async () => {
    const res = await register(WS_A, ALICE, {
      provider: 'mcp',
      client_id: `extra-${suffix()}`,
      status: 'active',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('ARGUMENT_SCHEMA_INVALID');
  });

  it('refuses to let a caller register an agent owned by someone else', async () => {
    // owner_user_id is not in the schema, so this is a 400 rather than a
    // quietly-ignored field. If the schema ever gains the property, this test
    // is the one that fails.
    const res = await register(WS_A, ALICE, {
      provider: 'mcp',
      client_id: `owner-${suffix()}`,
      owner_user_id: BOB,
    });

    expect(res.statusCode).toBe(400);

    const agents = await withWorkspace(pool, WS_A, (db) =>
      db.query(`select id from agents where workspace_id = $1 and owner_user_id = $2`, [WS_A, BOB]),
    );
    expect(agents.rows).toHaveLength(0);
  });

  it('does not coerce types', async () => {
    const res = await register(WS_A, ALICE, { provider: 'mcp', client_id: 12345 });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('ARGUMENT_SCHEMA_INVALID');
  });

  it('rejects a second live agent for the same owner and client with 409', async () => {
    const clientId = `dup-${suffix()}`;
    expect((await register(WS_A, ALICE, { provider: 'mcp', client_id: clientId })).statusCode).toBe(201);

    const second = await register(WS_A, ALICE, { provider: 'mcp', client_id: clientId });
    expect(second.statusCode).toBe(409);
    expect(second.json().error.code).toBe('AGENT_ALREADY_REGISTERED');
  });

  it('lets a different user in the same workspace register the same client', async () => {
    const clientId = `shared-${suffix()}`;
    expect((await register(WS_A, ALICE, { provider: 'mcp', client_id: clientId })).statusCode).toBe(201);
    expect((await register(WS_A, BOB, { provider: 'mcp', client_id: clientId })).statusCode).toBe(201);
  });

  it('denies and persists nothing when the policy engine is unavailable', async () => {
    const clientId = `outage-${suffix()}`;
    policy.breakNext('syncAgent');

    const res = await register(WS_A, ALICE, { provider: 'mcp', client_id: clientId });

    expect(res.statusCode).toBe(503);
    expect(res.json().error.code).toBe('POLICY_UNAVAILABLE');

    // syncAgent runs inside the transaction, so the failure rolls the row back.
    // A registration that Permit never learned about must not exist.
    const { rows } = await withWorkspace(pool, WS_A, (db) =>
      db.query(`select id from agents where workspace_id = $1 and client_id = $2`, [WS_A, clientId]),
    );
    expect(rows).toHaveLength(0);
  });
});

describe('GET /v1/agents', () => {
  it('lists only the caller workspace', async () => {
    const aClient = `list-a-${suffix()}`;
    const bClient = `list-b-${suffix()}`;
    await register(WS_A, ALICE, { provider: 'mcp', client_id: aClient });
    await register(WS_B, CAROL, { provider: 'mcp', client_id: bClient });

    const res = await app.inject({ method: 'GET', url: '/v1/agents', headers: as(WS_A, ALICE) });
    expect(res.statusCode).toBe(200);

    const clients = res.json().agents.map((a: { client_id: string }) => a.client_id);
    expect(clients).toContain(aClient);
    expect(clients).not.toContain(bClient);

    for (const agent of res.json().agents) {
      expect(agent.workspace_id).toBe(WS_A);
    }
  });
});

describe('GET /v1/agents/:agentId — IDOR', () => {
  it('returns 404 for a real agent id belonging to another workspace', async () => {
    const created = await register(WS_B, CAROL, { provider: 'mcp', client_id: `idor-${suffix()}` });
    const victimId: string = created.json().id;

    // Carol can read it.
    const owner = await app.inject({
      method: 'GET',
      url: `/v1/agents/${victimId}`,
      headers: as(WS_B, CAROL),
    });
    expect(owner.statusCode).toBe(200);

    // Alice, guessing a valid id from another tenant, gets the same answer she
    // would get for an id that does not exist anywhere.
    const attacker = await app.inject({
      method: 'GET',
      url: `/v1/agents/${victimId}`,
      headers: as(WS_A, ALICE),
    });
    const missing = await app.inject({
      method: 'GET',
      url: '/v1/agents/agt_doesnotexist',
      headers: as(WS_A, ALICE),
    });

    expect(attacker.statusCode).toBe(404);
    expect(attacker.json()).toEqual(missing.json());
    expect(attacker.payload).not.toContain(WS_B);
    expect(attacker.payload).not.toContain(CAROL);
  });

  it('rejects a malformed agent id before it reaches a query', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/v1/agents/${encodeURIComponent("agt_'; drop table agents; --")}`,
      headers: as(WS_A, ALICE),
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('ARGUMENT_SCHEMA_INVALID');
  });
});

describe('DELETE /v1/agents/:agentId', () => {
  it('revokes, and is idempotent on a second call', async () => {
    const created = await register(WS_A, ALICE, { provider: 'mcp', client_id: `rev-${suffix()}` });
    const agentId: string = created.json().id;

    const first = await app.inject({
      method: 'DELETE',
      url: `/v1/agents/${agentId}`,
      headers: as(WS_A, ALICE),
    });
    expect(first.statusCode).toBe(200);
    expect(first.json()).toMatchObject({ agent_id: agentId, revoked: true, already_revoked: false });

    const second = await app.inject({
      method: 'DELETE',
      url: `/v1/agents/${agentId}`,
      headers: as(WS_A, ALICE),
    });
    expect(second.statusCode).toBe(200);
    expect(second.json()).toMatchObject({ revoked: false, already_revoked: true });

    const agent = await withWorkspace(pool, WS_A, (db) => findAgent(db, WS_A, agentId));
    expect(agent?.status).toBe('revoked');
  });

  it('returns 404 and changes nothing for another workspace agent', async () => {
    const created = await register(WS_B, CAROL, { provider: 'mcp', client_id: `idor-rev-${suffix()}` });
    const victimId: string = created.json().id;

    const res = await app.inject({
      method: 'DELETE',
      url: `/v1/agents/${victimId}`,
      headers: as(WS_A, ALICE),
    });

    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('AGENT_UNKNOWN');

    const victim = await withWorkspace(pool, WS_B, (db) => findAgent(db, WS_B, victimId));
    expect(victim?.status).toBe('active');
  });
});

describe('emergency lock', () => {
  it('refuses registration while locked but still allows revocation', async () => {
    const created = await register(WS_A, ALICE, { provider: 'mcp', client_id: `lock-${suffix()}` });
    const agentId: string = created.json().id;

    await setEmergencyLock(pool, WS_A, true);
    try {
      const blocked = await register(WS_A, ALICE, { provider: 'mcp', client_id: `lock-new-${suffix()}` });
      expect(blocked.statusCode).toBe(423);
      expect(blocked.json().error.code).toBe('WORKSPACE_LOCKED');

      // Revocation narrows access, so the lock must not stand in its way.
      const revoked = await app.inject({
        method: 'DELETE',
        url: `/v1/agents/${agentId}`,
        headers: as(WS_A, ALICE),
      });
      expect(revoked.statusCode).toBe(200);
      expect(revoked.json().revoked).toBe(true);
    } finally {
      await setEmergencyLock(pool, WS_A, false);
    }
  });
});

describe('unknown identity', () => {
  it('treats a principal naming a nonexistent user as unauthenticated', async () => {
    const res = await register(WS_A, `usr_ghost${suffix()}`, {
      provider: 'mcp',
      client_id: `ghost-${suffix()}`,
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error.code).toBe('IDENTITY_UNRESOLVED');
  });
});
