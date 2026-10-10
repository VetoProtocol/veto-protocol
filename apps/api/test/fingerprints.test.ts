/**
 * /v1/agents/fingerprints over HTTP.
 *
 * The screen's API. The assertions that matter are the boundary ones: the gate
 * runs before any work, one workspace cannot see or judge another's clients,
 * and a mode change is refused while the workspace is locked.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { observeClient, recordSighting } from '@veto/identity';
import { createApp } from '../src/app.ts';
import {
  as,
  headerAuthenticator,
  seed,
  setEmergencyLock,
  suffix,
  testPool,
  testRedis,
} from './helpers.ts';

const CLAUDE_CODE = 'claude-code/2.1.293 (sdk-cli)';
const OTHER_CLIENT = 'some-other-tool/3.1';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_fp${s}`;
const OTHER_WS = `ws_fp2${s}`;
const ALICE = `usr_alice${s}`;
const CAROL = `usr_carol${s}`;

let agentId: string;
let otherAgentId: string;

const register = async (ws: string, user: string, clientId: string): Promise<string> => {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: as(ws, user),
    payload: { provider: 'mcp', client_id: clientId },
  });
  return res.json().id as string;
};

const sight = (ws: string, agent: string, userAgent: string) =>
  withWorkspace(pool, ws, (db) =>
    recordSighting(db, {
      workspaceId: ws,
      agentId: agent,
      observation: observeClient(userAgent),
      handshake: null,
    }),
  );

const plan = (ws: string, value: 'free' | 'pro') =>
  withWorkspace(pool, ws, (db) =>
    db.query(`update workspaces set plan = $2 where id = $1`, [ws, value]),
  );

const list = (ws: string, user: string) =>
  app.inject({ method: 'GET', url: '/v1/agents/fingerprints', headers: as(ws, user) });

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE]);
  await seed(pool, OTHER_WS, [CAROL]);

  app = createApp({
    pool,
    redis,
    policy: createFakePolicyFacts(),
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    authenticate: headerAuthenticator(),
  });
  await app.ready();

  agentId = await register(WS, ALICE, `client-${s}`);
  otherAgentId = await register(OTHER_WS, CAROL, `client-other-${s}`);

  await sight(WS, agentId, CLAUDE_CODE);
  await sight(WS, agentId, OTHER_CLIENT);
  await sight(OTHER_WS, otherAgentId, 'tenant-b-client/1.0');

  await plan(WS, 'pro');
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

describe('the plan gate', () => {
  it('refuses a free workspace with 402, not 403', async () => {
    // The caller is permitted to ask; the workspace is not on the tier that
    // answers.
    await plan(WS, 'free');
    const res = await list(WS, ALICE);
    await plan(WS, 'pro');

    expect(res.statusCode).toBe(402);
    expect(res.json().error.code).toBe('PLAN_REQUIRED');
  });

  it('refuses before reading anything', async () => {
    // A gate applied after the queries have run has already spent them. The
    // body carries no agent list at all, not an empty one.
    await plan(WS, 'free');
    const res = await list(WS, ALICE);
    await plan(WS, 'pro');

    expect(res.json().agents).toBeUndefined();
  });

  it('gates the mutations too, not only the read', async () => {
    await plan(WS, 'free');

    const mode = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprint-mode`,
      headers: as(WS, ALICE),
      payload: { mode: 'deny' },
    });
    const judge = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprints`,
      headers: as(WS, ALICE),
      payload: { fingerprint: observeClient(OTHER_CLIENT).fingerprint, status: 'refused' },
    });

    await plan(WS, 'pro');

    expect(mode.statusCode).toBe(402);
    expect(judge.statusCode).toBe(402);
  });
});

describe('listing', () => {
  it('reports each agent with its mode and what has connected', async () => {
    const res = await list(WS, ALICE);
    expect(res.statusCode).toBe(200);

    const agent = res.json().agents.find((a: { agent_id: string }) => a.agent_id === agentId);
    expect(agent.fingerprint_mode).toBe('observe');

    const products = agent.fingerprints.map((f: { product: string }) => f.product);
    expect(products).toContain('claude-code');
    expect(products).toContain('some-other-tool');

    // Trust on first use: the first is pinned, the second is not.
    const first = agent.fingerprints.find((f: { product: string }) => f.product === 'claude-code');
    expect(first.status).toBe('pinned');
    expect(first.last_version).toBe('2.1.293');
    expect(first.sightings).toBe(1);
  });

  it('is not shadowed by the :agentId routes beside it', async () => {
    // `/v1/agents/fingerprints` is a static path sharing a prefix with
    // `/v1/agents/:agentId/...`. If the router preferred the parameter, this
    // would 400 on the id pattern instead of listing.
    expect((await list(WS, ALICE)).statusCode).toBe(200);
  });

  it('shows one workspace nothing of another', async () => {
    await plan(OTHER_WS, 'pro');
    const mine = await list(WS, ALICE);
    const theirs = await list(OTHER_WS, CAROL);
    await plan(OTHER_WS, 'free');

    const productsOf = (r: { json: () => { agents: { fingerprints: { product: string }[] }[] } }) =>
      r.json().agents.flatMap((a) => a.fingerprints.map((f) => f.product));

    expect(productsOf(mine)).not.toContain('tenant-b-client');
    expect(productsOf(theirs)).toEqual(['tenant-b-client']);
  });
});

describe('judging a client', () => {
  it('refuses a fingerprint that was never seen, rather than inventing a row', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprints`,
      headers: as(WS, ALICE),
      payload: { fingerprint: `sha256:${'a'.repeat(64)}`, status: 'pinned' },
    });

    expect(res.statusCode).toBe(404);
  });

  it('rejects a malformed digest at the schema, not the query', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprints`,
      headers: as(WS, ALICE),
      payload: { fingerprint: 'not-a-digest', status: 'pinned' },
    });

    expect(res.statusCode).toBe(400);
  });

  it('refuses an unknown field rather than ignoring it', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprints`,
      headers: as(WS, ALICE),
      payload: {
        fingerprint: observeClient(OTHER_CLIENT).fingerprint,
        status: 'pinned',
        agent_id: otherAgentId,
      },
    });

    expect(res.statusCode).toBe(400);
  });

  it('cannot judge another workspace’s fingerprint', async () => {
    await plan(OTHER_WS, 'pro');

    // Carol names Alice's agent. RLS and the explicit workspace both scope the
    // update, so it matches nothing — and nothing is what she is told.
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprints`,
      headers: as(OTHER_WS, CAROL),
      payload: { fingerprint: observeClient(CLAUDE_CODE).fingerprint, status: 'refused' },
    });

    await plan(OTHER_WS, 'free');
    expect(res.statusCode).toBe(404);
  });

  it('records the operator’s verdict in the audit trail', async () => {
    await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprints`,
      headers: as(WS, ALICE),
      payload: { fingerprint: observeClient(OTHER_CLIENT).fingerprint, status: 'refused' },
    });

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ event_type: string }>(
        `select event_type from audit_events
          where workspace_id = $1 and event_type like 'agent.fingerprint%'
          order by seq desc limit 5`,
        [WS],
      ),
    );

    expect(rows.map((r) => r.event_type)).toContain('agent.fingerprint_refused');
  });
});

describe('the mode', () => {
  it('is set and reported back', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprint-mode`,
      headers: as(WS, ALICE),
      payload: { mode: 'challenge' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().fingerprint_mode).toBe('challenge');
  });

  it('rejects a mode nobody implements', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprint-mode`,
      headers: as(WS, ALICE),
      payload: { mode: 'paranoid' },
    });

    expect(res.statusCode).toBe(400);
  });

  it('is refused while the workspace is locked', async () => {
    // Lowering enforcement widens access, and an attacker who has triggered a
    // lock response must not be able to switch a control off while the
    // operator is still dealing with it. One rule for both directions.
    await setEmergencyLock(pool, WS, true);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprint-mode`,
      headers: as(WS, ALICE),
      payload: { mode: 'observe' },
    });
    await setEmergencyLock(pool, WS, false);

    expect(res.statusCode).toBe(423);
  });

  it('still lets a client be refused under a lock, because that only narrows', async () => {
    await setEmergencyLock(pool, WS, true);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprints`,
      headers: as(WS, ALICE),
      payload: { fingerprint: observeClient(CLAUDE_CODE).fingerprint, status: 'refused' },
    });
    await setEmergencyLock(pool, WS, false);

    expect(res.statusCode).toBe(200);
  });

  it('refuses to pin under a lock, because that widens', async () => {
    await setEmergencyLock(pool, WS, true);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/fingerprints`,
      headers: as(WS, ALICE),
      payload: { fingerprint: observeClient(CLAUDE_CODE).fingerprint, status: 'pinned' },
    });
    await setEmergencyLock(pool, WS, false);

    expect(res.statusCode).toBe(423);
  });

  it('404s for an agent that does not exist', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/agt_nosuchagent/fingerprint-mode`,
      headers: as(WS, ALICE),
      payload: { mode: 'deny' },
    });

    expect(res.statusCode).toBe(404);
  });
});
