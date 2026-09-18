import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { withWorkspace } from '@veto/db';
import { createFakePolicyFacts, type FakePolicyFacts } from '@veto/permit';
import {
  AgentNotFoundError,
  DuplicateLiveAgentError,
  findAgent,
  listAgents,
  liveSessionIds,
  recordSession,
  registerAgent,
  revokeAgent,
} from '../src/index.ts';
import { seed, suffix, testPool, testRedis } from './helpers.ts';

const s = suffix();
const WS = `ws_i${s}`;
const OTHER_WS = `ws_o${s}`;
const ALICE = `usr_a${s}`;
const BOB = `usr_b${s}`;
const CAROL = `usr_c${s}`;

let pool: Pool;
let redis: Redis;
let policy: FakePolicyFacts;

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyFacts();
  await seed(pool, WS, [ALICE, BOB]);
  await seed(pool, OTHER_WS, [CAROL]);
});

afterAll(async () => {
  await redis.quit();
  await pool.end();
});

const register = (ws: string, owner: string, clientId = 'claude-desktop') =>
  withWorkspace(pool, ws, (db) =>
    registerAgent(db, policy, {
      workspaceId: ws,
      ownerUserId: owner,
      provider: 'anthropic',
      clientId,
    }),
  );

describe('agent registration', () => {
  it('creates an agent, a Permit fact, and an audit event', async () => {
    const agent = await register(WS, ALICE, `client-${s}-1`);
    expect(agent.id).toMatch(/^agt_/);
    expect(agent.status).toBe('active');

    expect(await policy.factsFor(WS)).toContain(`agent:${agent.id}#owner=${ALICE}`);

    const events = await withWorkspace(pool, WS, (db) =>
      db.query<{ event_type: string; resource_ref: string }>(
        `select event_type, resource_ref from audit_events
          where workspace_id = $1 and resource_ref = $2`,
        [WS, `agent:${agent.id}`],
      ),
    );
    expect(events.rows.map((r) => r.event_type)).toEqual(['agent.registered']);
  });

  // The bug migration 0006 fixed: client_id names the software, not the registration.
  it('lets two users in one workspace register the same client', async () => {
    const client = `client-${s}-shared`;
    const a = await register(WS, ALICE, client);
    const b = await register(WS, BOB, client);
    expect(a.id).not.toBe(b.id);
    expect(b.status).toBe('active');
  });

  it('refuses a second live agent for the same user and client', async () => {
    const client = `client-${s}-dup`;
    await register(WS, ALICE, client);
    await expect(register(WS, ALICE, client)).rejects.toThrow(DuplicateLiveAgentError);
  });
});

describe('agent revocation (FR-08)', () => {
  it('flips status, clears Permit facts, drops sessions, and audits', async () => {
    const agent = await register(WS, BOB, `client-${s}-rev`);
    await recordSession(redis, WS, agent.id, `ses_${s}1`, 300);
    await recordSession(redis, WS, agent.id, `ses_${s}2`, 300);
    expect(await liveSessionIds(redis, WS, agent.id)).toHaveLength(2);

    const result = await revokeAgent(pool, redis, policy, {
      workspaceId: WS,
      agentId: agent.id,
      actorUserId: BOB,
    });

    expect(result).toMatchObject({ revoked: true, alreadyRevoked: false, sessionsDropped: 2 });

    const after = await withWorkspace(pool, WS, (db) => findAgent(db, WS, agent.id));
    expect(after?.status).toBe('revoked');
    expect(after?.revoked_at).toBeInstanceOf(Date);

    expect(await policy.factsFor(WS)).not.toContain(`agent:${agent.id}#owner=${BOB}`);
    expect(await liveSessionIds(redis, WS, agent.id)).toHaveLength(0);

    const events = await withWorkspace(pool, WS, (db) =>
      db.query<{ event_type: string }>(
        `select event_type from audit_events where workspace_id=$1 and resource_ref=$2 order by seq`,
        [WS, `agent:${agent.id}`],
      ),
    );
    expect(events.rows.map((r) => r.event_type)).toEqual(['agent.registered', 'agent.revoked']);
  });

  it('is idempotent — a second revoke reports already-revoked and still converges', async () => {
    const agent = await register(WS, ALICE, `client-${s}-idem`);
    await revokeAgent(pool, redis, policy, { workspaceId: WS, agentId: agent.id, actorUserId: ALICE });
    const second = await revokeAgent(pool, redis, policy, {
      workspaceId: WS,
      agentId: agent.id,
      actorUserId: ALICE,
    });
    expect(second).toMatchObject({ revoked: false, alreadyRevoked: true });
    expect(await policy.factsFor(WS)).not.toContain(`agent:${agent.id}#owner=${ALICE}`);
  });

  it('refuses an unknown agent', async () => {
    await expect(
      revokeAgent(pool, redis, policy, { workspaceId: WS, agentId: `agt_nope${s}`, actorUserId: ALICE }),
    ).rejects.toThrow(AgentNotFoundError);
  });

  // The property that makes re-registration safe, and the reason burning the
  // client_id forever was guarding the wrong door.
  it('gives a re-registered agent a new identity that inherits nothing', async () => {
    const client = `client-${s}-reuse`;
    const first = await register(WS, BOB, client);
    await recordSession(redis, WS, first.id, `ses_${s}old`, 300);
    await revokeAgent(pool, redis, policy, { workspaceId: WS, agentId: first.id, actorUserId: BOB });

    const second = await register(WS, BOB, client);

    expect(second.id).not.toBe(first.id);
    expect(second.status).toBe('active');
    // No session, no Permit fact, nothing carried over from the revoked identity.
    expect(await liveSessionIds(redis, WS, second.id)).toHaveLength(0);
    expect(await liveSessionIds(redis, WS, first.id)).toHaveLength(0);
    const facts = await policy.factsFor(WS);
    expect(facts).toContain(`agent:${second.id}#owner=${BOB}`);
    expect(facts).not.toContain(`agent:${first.id}#owner=${BOB}`);
  });

  it('keeps a revoked agent on record — the audit trail must not lose it', async () => {
    const agents = await withWorkspace(pool, WS, (db) => listAgents(db, WS));
    expect(agents.some((a) => a.status === 'revoked')).toBe(true);
  });
});

describe('cross-tenant isolation (invariant 4)', () => {
  it('does not reveal another workspace\'s agent', async () => {
    const theirs = await register(OTHER_WS, CAROL, `client-${s}-x`);
    const seen = await withWorkspace(pool, WS, (db) => findAgent(db, WS, theirs.id));
    expect(seen).toBeNull();
  });

  it('refuses to revoke another workspace\'s agent', async () => {
    const theirs = await register(OTHER_WS, CAROL, `client-${s}-x2`);
    await expect(
      revokeAgent(pool, redis, policy, {
        workspaceId: WS,
        agentId: theirs.id,
        actorUserId: ALICE,
      }),
    ).rejects.toThrow(AgentNotFoundError);

    // And it is still live in its own workspace.
    const mine = await withWorkspace(pool, OTHER_WS, (db) => findAgent(db, OTHER_WS, theirs.id));
    expect(mine?.status).toBe('active');
  });

  it('scopes Redis session keys by workspace', async () => {
    const a = await register(WS, ALICE, `client-${s}-r1`);
    await recordSession(redis, WS, a.id, `ses_${s}w`, 300);
    // Same agent id looked up under a different workspace yields nothing.
    expect(await liveSessionIds(redis, OTHER_WS, a.id)).toHaveLength(0);
    expect(await liveSessionIds(redis, WS, a.id)).toHaveLength(1);
  });
});

describe('fail-closed behaviour', () => {
  it('surfaces a Permit outage rather than reporting a clean revoke', async () => {
    const agent = await register(WS, ALICE, `client-${s}-fail`);
    policy.breakNext('removeAgent');

    await expect(
      revokeAgent(pool, redis, policy, { workspaceId: WS, agentId: agent.id, actorUserId: ALICE }),
    ).rejects.toThrow(/unavailable/i);

    // The local status change already committed, so the agent is denied here even
    // though Permit still holds its facts: the partial failure left the system
    // more restrictive, not less.
    const after = await withWorkspace(pool, WS, (db) => findAgent(db, WS, agent.id));
    expect(after?.status).toBe('revoked');

    // And a retry converges.
    const retry = await revokeAgent(pool, redis, policy, {
      workspaceId: WS,
      agentId: agent.id,
      actorUserId: ALICE,
    });
    expect(retry.alreadyRevoked).toBe(true);
    expect(await policy.factsFor(WS)).not.toContain(`agent:${agent.id}#owner=${ALICE}`);
  });
});
