/**
 * /v1/grants over HTTP.
 *
 * The half of an allow that did not exist. `syncAgent` could create an agent
 * principal and `removeAgent` could delete it, and nothing in between could
 * connect it to a resource — so `permit.check` denied whatever a Veto rule
 * said, and a correctly written policy produced a refusal with nothing pointing
 * at the cause.
 *
 * These assertions are about the boundary: who may be granted, what happens to
 * grants when the agent is revoked, and that one workspace's grants are
 * invisible to another.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import {
  createFakePolicyDecisions,
  createFakePolicyFacts,
  type FakePolicyFacts,
} from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyFacts;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_gr${s}`;
const OTHER_WS = `ws_gr2${s}`;
const ALICE = `usr_alice${s}`;
const CAROL = `usr_carol${s}`;

let agentId: string;
let otherAgentId: string;

const grant = (over: Record<string, unknown> = {}) => ({
  agent_id: agentId,
  resource_type: 'google_folder',
  resource_key: '1WorkFolder_id',
  ...over,
});

const register = async (ws: string, user: string, clientId: string): Promise<string> => {
  const response = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: as(ws, user),
    payload: { provider: 'mcp', client_id: clientId },
  });
  return response.json().id as string;
};

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyFacts();
  await seed(pool, WS, [ALICE]);
  await seed(pool, OTHER_WS, [CAROL]);

  app = createApp({
    pool,
    redis,
    policy,
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    authenticate: headerAuthenticator(),
  });
  await app.ready();

  agentId = await register(WS, ALICE, `client-${s}`);
  otherAgentId = await register(OTHER_WS, CAROL, `client-other-${s}`);
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const post = (body: unknown, ws = WS, user = ALICE) =>
  app.inject({ method: 'POST', url: '/v1/grants', headers: as(ws, user), payload: body as object });

const remove = (body: unknown, ws = WS, user = ALICE) =>
  app.inject({
    method: 'DELETE',
    url: '/v1/grants',
    headers: as(ws, user),
    payload: body as object,
  });

const list = (ws = WS, user = ALICE) =>
  app.inject({ method: 'GET', url: '/v1/grants', headers: as(ws, user) });

describe('granting', () => {
  it('connects an agent to a folder', async () => {
    const response = await post(grant());
    expect(response.statusCode).toBe(201);

    const grants = (await list().then((r) => r.json())).grants as unknown[];
    expect(grants).toContainEqual({
      agent_id: agentId,
      resource_type: 'google_folder',
      resource_key: '1WorkFolder_id',
    });
  });

  it('is idempotent', async () => {
    await post(grant({ resource_key: '1Twice_id' }));
    expect((await post(grant({ resource_key: '1Twice_id' }))).statusCode).toBe(201);

    const grants = (await list().then((r) => r.json())).grants as unknown[];
    const matching = grants.filter(
      (g) => (g as { resource_key: string }).resource_key === '1Twice_id',
    );
    expect(matching).toHaveLength(1);
  });

  it('records the fact in the form the real adapter produces', async () => {
    await post(grant({ resource_key: '1Shape_id' }));
    const facts = await policy.factsFor(WS);
    expect(facts).toContain(`agent:${agentId}#reader@google_folder:1Shape_id`);
  });

  it('writes an audit event naming both ends', async () => {
    await post(grant({ resource_key: '1Audited_id' }));

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ event_type: string; resource_ref: string }>(
        `select event_type, resource_ref from audit_events
          where workspace_id = $1 and event_type = 'grant.created'
            and resource_ref like $2`,
        [WS, '%1Audited_id%'],
      ),
    );

    expect(rows[0]?.resource_ref).toBe(`google_folder:1Audited_id#agent=${agentId}`);
  });
});

describe('what it refuses', () => {
  it('refuses an agent that does not exist here', async () => {
    expect((await post(grant({ agent_id: `agt_nope${s}` }))).statusCode).toBe(404);
  });

  it('refuses another workspace’s agent, as not found', async () => {
    // Not 403: a caller must not learn that an id exists somewhere else
    // (invariant 4). A Permit fact written for a foreign agent would also be
    // one this tenant could never see or clean up.
    expect((await post(grant({ agent_id: otherAgentId }))).statusCode).toBe(404);
    expect(await policy.factsFor(WS)).not.toContain(
      `agent:${otherAgentId}#reader@google_folder:1WorkFolder_id`,
    );
  });

  it('refuses a revoked agent', async () => {
    const doomed = await register(WS, ALICE, `doomed-${s}`);
    await app.inject({
      method: 'DELETE',
      url: `/v1/agents/${doomed}`,
      headers: as(WS, ALICE),
    });

    const response = await post(grant({ agent_id: doomed }));
    // Handing a grant back to something somebody deliberately cut off is the
    // one direction that must never be an accident.
    expect(response.statusCode).toBe(409);
  });

  it('refuses a resource type no tool asks about', async () => {
    for (const type of ['mailbox', 'veto_agent', 'workspace', '*']) {
      expect((await post(grant({ resource_type: type }))).statusCode, type).toBe(400);
    }
  });

  it('refuses a resource key Permit would reject, as a 400 rather than an upstream 422', async () => {
    // Permit validates instance keys against ^[A-Za-z0-9\-_]+$. A path is not
    // a Drive id, and `*` is not a wildcard here — "everything" is expressed by
    // granting the folder that contains it.
    for (const key of ['/Work', '*', 'a b', 'file.txt', '../etc']) {
      expect((await post(grant({ resource_key: key }))).statusCode, key).toBe(400);
    }
  });

  it('accepts a real Drive id', async () => {
    // Google's ids are exactly this alphabet, so nothing legitimate is caught
    // by the rule above.
    expect((await post(grant({ resource_key: '1a2B3c-_9zYx' }))).statusCode).toBe(201);
  });

  it('refuses an unknown field rather than dropping it', async () => {
    expect((await post(grant({ role: 'owner' }))).statusCode).toBe(400);
  });

  it('refuses a sign-in credential', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/grants',
      headers: { ...as(WS, ALICE), 'x-test-scope': 'identity-resolve' },
    });
    expect(response.statusCode).toBe(403);
  });
});

describe('removing', () => {
  it('disconnects, and is safe to repeat', async () => {
    await post(grant({ resource_key: '1Gone_id' }));
    expect((await remove(grant({ resource_key: '1Gone_id' }))).statusCode).toBe(200);
    expect((await remove(grant({ resource_key: '1Gone_id' }))).statusCode).toBe(200);

    expect(await policy.factsFor(WS)).not.toContain(`agent:${agentId}#reader@google_folder:1Gone_id`);
  });

  it('goes with the agent when the agent is revoked', async () => {
    const doomed = await register(WS, ALICE, `sweep-${s}`);
    await post(grant({ agent_id: doomed, resource_key: '1Swept_id' }));
    expect(await policy.factsFor(WS)).toContain(`agent:${doomed}#reader@google_folder:1Swept_id`);

    await app.inject({ method: 'DELETE', url: `/v1/agents/${doomed}`, headers: as(WS, ALICE) });

    // §7.3 privilege accumulation: revocation is not complete until every fact
    // that granted the agent something is gone.
    expect(await policy.factsFor(WS)).not.toContain(`agent:${doomed}#reader@google_folder:1Swept_id`);
  });
});

describe('tenant isolation', () => {
  it('never lists another workspace’s grants', async () => {
    await post(grant({ agent_id: otherAgentId, resource_key: '1Theirs_id' }), OTHER_WS, CAROL);

    const mine = (await list().then((r) => r.json())).grants as Array<{ resource_key: string }>;
    expect(mine.map((g) => g.resource_key)).not.toContain('1Theirs_id');
  });
});

describe('consent grants', () => {
  // The join between a grant and its use is a *string*: `type:key`, written by
  // the pipeline and read here. Nothing errors when it stops matching — every
  // grant simply reports "never used", which looks exactly like a working
  // screen showing an idle workspace. These tests exist because that failure is
  // silent.

  const REPO = 'github_repo';
  const KEY = '524250555';
  let agent: string;

  beforeAll(async () => {
    agent = await register(WS, ALICE, `consent-${suffix()}`);

    await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: as(WS, ALICE),
      payload: { agent_id: agent, resource_type: REPO, resource_key: KEY },
    });
  });

  const consent = (ws: string, user: string) =>
    app.inject({ method: 'GET', url: '/v1/grants/consent', headers: as(ws, user) });

  const rowFor = async (ws: string, user: string, agentId: string) => {
    const body = (await consent(ws, user)).json() as {
      grants: Array<Record<string, unknown>>;
    };
    return body.grants.find((g) => g['agent_id'] === agentId);
  };

  it('never shows a grant from another workspace', async () => {
    // The one that matters. Permit is asked per tenant and the Postgres reads
    // run inside withWorkspace, so a leak would have to cross both.
    const body = (await consent(OTHER_WS, CAROL)).json() as {
      grants: Array<Record<string, unknown>>;
    };
    expect(body.grants.some((g) => g['agent_id'] === agent)).toBe(false);
  });

  it('reports a grant nobody has used as stale, not as used today', async () => {
    const row = await rowFor(WS, ALICE, agent);

    expect(row).toBeDefined();
    expect(row?.['resource_key']).toBe(KEY);
    expect(row?.['last_used_at']).toBeNull();
    expect(row?.['days_since_last_use']).toBeNull();
    // Never used is the case most worth surfacing: granted and then forgotten.
    expect(row?.['stale']).toBe(true);
  });

  it('finds the last use through the shared ref format', async () => {
    // Written the way the pipeline writes it. If `grantRef` and this insert
    // ever disagree, this assertion is what fails.
    await withWorkspace(pool, WS, (db) =>
      db.query(
        `insert into decisions
           (id, workspace_id, request_id, human_id, agent_id, tool, action, resource_ref,
            permit_result, veto_result, reason_code, policy_version, latency_ms)
         values ($1,$2,$3,$4,$5,'github_repo.read_file','read',$6,
                 'allow','allow','ALLOWED_WITHIN_POLICY',null,10)`,
        [`dec_cg${suffix()}`, WS, `req_cg${suffix()}`, ALICE, agent, `${REPO}:${KEY}`],
      ),
    );

    const row = await rowFor(WS, ALICE, agent);

    expect(row?.['last_used_at']).not.toBeNull();
    expect(row?.['days_since_last_use']).toBe(0);
    expect(row?.['stale']).toBe(false);
  });

  it('ignores a denial, because a refusal is not a use', async () => {
    const other = await register(WS, ALICE, `consent2-${suffix()}`);
    await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: as(WS, ALICE),
      payload: { agent_id: other, resource_type: REPO, resource_key: KEY },
    });

    await withWorkspace(pool, WS, (db) =>
      db.query(
        `insert into decisions
           (id, workspace_id, request_id, human_id, agent_id, tool, action, resource_ref,
            permit_result, veto_result, reason_code, policy_version, latency_ms)
         values ($1,$2,$3,$4,$5,'github_repo.read_file','read',$6,
                 'deny','deny','POLICY_DENIED',null,5)`,
        [`dec_cg${suffix()}`, WS, `req_cg${suffix()}`, ALICE, other, `${REPO}:${KEY}`],
      ),
    );

    const row = await rowFor(WS, ALICE, other);
    expect(row?.['last_used_at']).toBeNull();
  });

  it('says when recording started, so "never used" is a bounded claim', async () => {
    const body = (await consent(WS, ALICE)).json() as Record<string, unknown>;

    // "Never used" means "not since this date". Without it the screen would be
    // inviting somebody to revoke on evidence it does not have.
    expect(body['recording_since']).not.toBeNull();
    expect(body['stale_after_days']).toBe(90);
  });

  it('reports a grant that no rule allows as inert', async () => {
    // The reason this column exists. Step 4 denies when no rule matches, before
    // Permit is consulted, so a grant with no rule reaches nothing. A page that
    // listed it as access would be stating a fiction, and somebody revoking it
    // would believe they had removed something.
    const row = await rowFor(WS, ALICE, agent);

    expect(row?.['inert']).toBe(true);
    expect(row?.['effective']).toEqual([]);
  });

  it('reports what a rule actually permits, per action', async () => {
    const ruled = await register(WS, ALICE, `consent4-${suffix()}`);
    await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: as(WS, ALICE),
      payload: { agent_id: ruled, resource_type: REPO, resource_key: KEY },
    });
    await app.inject({
      method: 'POST',
      url: '/v1/policies',
      headers: as(WS, ALICE),
      payload: {
        subject: ruled,
        action: 'read',
        effect: 'allow',
        resource_filter: { type: REPO, ids: [KEY] },
      },
    });

    const row = await rowFor(WS, ALICE, ruled);

    expect(row?.['inert']).toBe(false);
    // Only the action the rule names. `search` is not implied by `read`.
    expect(row?.['effective']).toEqual([{ action: 'read', effect: 'allow' }]);
  });

  it('shows a challenge as a challenge, not as plain access', async () => {
    const stepped = await register(WS, ALICE, `consent5-${suffix()}`);
    await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: as(WS, ALICE),
      payload: { agent_id: stepped, resource_type: REPO, resource_key: KEY },
    });
    await app.inject({
      method: 'POST',
      url: '/v1/policies',
      headers: as(WS, ALICE),
      payload: {
        subject: stepped,
        action: 'read',
        effect: 'challenge',
        resource_filter: { type: REPO, ids: [KEY] },
      },
    });

    const row = await rowFor(WS, ALICE, stepped);

    // Access that needs a passkey every time is not the same as access, and a
    // reader deciding what to revoke should see the difference.
    expect(row?.['effective']).toEqual([{ action: 'read', effect: 'challenge' }]);
    expect(row?.['inert']).toBe(false);
  });

  it('does not treat a rule for another agent as reaching this one', async () => {
    // The rule written above names `ruled`. The original agent still has no
    // rule of its own, so it must still be inert.
    const row = await rowFor(WS, ALICE, agent);
    expect(row?.['inert']).toBe(true);
  });

  it('marks a container grant as reaching more than it names', async () => {
    const third = await register(WS, ALICE, `consent3-${suffix()}`);
    await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: as(WS, ALICE),
      payload: { agent_id: third, resource_type: 'google_folder', resource_key: 'root' },
    });

    const row = await rowFor(WS, ALICE, third);
    // A folder grant reaches everything inside it. A list that looked
    // exhaustive would invite the wrong conclusion about the rest.
    expect(row?.['inherits']).toBe(true);
  });
});
