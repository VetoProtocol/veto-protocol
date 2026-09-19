/**
 * Stage 4's exit condition, stated as tests: **revocation across all sessions**.
 *
 * Three different things can withdraw authority mid-flight — an emergency lock,
 * an agent revocation, a connection revocation — and each has to reach a
 * session that is already open and already working. §11 sets the target:
 * effective on the next protected request, within five seconds.
 *
 * "The next protected request" is the strong form and the one asserted here.
 * Not "eventually", not "after a cache expires": the very next call refuses.
 * The way that is achieved is by not caching the facts that decide it — the
 * agent row and the lock column are read every time — so these tests are the
 * ones that fail if somebody ever adds a cache for either.
 *
 * §12.1's "emergency lock during an active session" is this file.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { newId } from '@veto/core';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, type FakePolicyDecisions } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { lockWorkspace, redeemApproval, revokeAgentEverywhere } from '@veto/decisions';
import { createFakePolicyFacts } from '@veto/permit';
import {
  createConnection,
  DRIVE_READONLY_SCOPE,
  revokeConnection,
  type DriveFile,
  type DriveReader,
  type UpstreamTokenExchange,
} from '@veto/connections';
import { createGateway } from '../src/app.ts';
import { RPC } from '../src/jsonrpc.ts';
import { SECRET, gatewayToken, rpc, seedAgent, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyDecisions;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_rv${s}`;
const USER = `usr_rv${s}`;
const AGENT = `agt_rv${s}`;
const OTHER_AGENT = `agt_rv2${s}`;
const FILE = 'notes/plan.txt';

/** Five seconds, from §11: "revocation ... targeted within five seconds". */
const REVOCATION_BUDGET_MS = 5_000;

const wrapper = createLocalKeyWrapper(randomBytes(32).toString('base64'));

const exchange: UpstreamTokenExchange = {
  async refresh() {
    return {
      accessToken: 'ya29.fake',
      expiresAt: new Date(Date.now() + 300_000),
      scopes: [DRIVE_READONLY_SCOPE],
    };
  },
  async revoke() {},
};

/** Every upstream read is recorded, so "nothing reached Drive" is checkable. */
const reads: string[] = [];
const drive: DriveReader = {
  async readFile(_token, fileId): Promise<DriveFile> {
    reads.push(fileId);
    return { id: fileId, name: fileId, mimeType: 'text/plain', modifiedTime: null, content: 'ok' };
  },
};

let connectionId: string;

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyDecisions();
  await seedAgent(pool, WS, USER, AGENT, 'claude-desktop');
  await seedAgent(pool, WS, USER, OTHER_AGENT, 'cursor');

  await withWorkspace(pool, WS, async (db) => {
    await db.query(
      `insert into presence (workspace_id,user_id,state,source) values ($1,$2,'active','test')`,
      [WS, USER],
    );
    for (const agent of [AGENT, OTHER_AGENT]) {
      await db.query(
        `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
         values ($1,$2,$3,'read',$4,'{}'::jsonb,'allow','polv_rv')`,
        [`pol_${suffix()}${suffix()}`, WS, agent, JSON.stringify({ type: 'google_file', ids: [FILE] })],
      );
    }
    const connection = await createConnection(db, wrapper, {
      workspaceId: WS,
      userId: USER,
      provider: 'google',
      scopes: [DRIVE_READONLY_SCOPE],
      refreshToken: 'refresh-token-value',
    });
    connectionId = connection.id;
  });

  policy.allow(WS, AGENT, 'read', 'google_file', FILE);
  policy.allow(WS, OTHER_AGENT, 'read', 'google_file', FILE);

  app = createGateway({
    pool,
    redis,
    policy,
    capabilitySecret: SECRET,
    publicUrl: 'https://gateway.veto.example',
    authorizationServer: 'https://app.veto.example',
    execute: { wrapper, exchange, drive },
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const read = (agent = AGENT) =>
  app.inject({
    method: 'POST',
    url: '/mcp',
    headers: { authorization: `Bearer ${gatewayToken(WS, USER, agent)}` },
    payload: rpc('tools/call', {
      name: 'google_drive.read_file',
      arguments: { file_id: FILE, fields: ['name', 'content'] },
    }),
  });

/**
 * A grant that is approved and in date — the dangerous kind.
 *
 * Inserted directly rather than driven through a challenge, because what is
 * under test is what happens to an *outstanding* grant, not how one comes to
 * exist. The decision row is required by the foreign key and is what ties the
 * grant to an agent.
 */
async function liveGrant(agentId: string, digest: string): Promise<string> {
  const decisionId = newId('dec_');
  const approvalId = newId('apr_');

  await withWorkspace(pool, WS, async (db) => {
    await db.query(
      `insert into decisions
         (id,workspace_id,request_id,human_id,agent_id,tool,action,resource_ref,
          permit_result,veto_result,reason_code)
       values ($1,$2,$3,$4,$5,'google_drive.read_file','read',$6,'allow','challenge','APPROVAL_REQUIRED')`,
      [decisionId, WS, newId('req_'), USER, agentId, FILE],
    );
    await db.query(
      `insert into approvals
         (id,workspace_id,decision_id,approver_id,action_digest,challenge,status,expires_at,resolved_at)
       values ($1,$2,$3,$4,$5,$6,'approved',now() + interval '10 minutes',now())`,
      [approvalId, WS, decisionId, USER, digest, randomBytes(32)],
    );
  });

  return approvalId;
}

const statusOf = async (approvalId: string): Promise<string> => {
  const { rows } = await withWorkspace(pool, WS, (db) =>
    db.query<{ status: string }>(`select status from approvals where workspace_id = $1 and id = $2`, [
      WS,
      approvalId,
    ]),
  );
  return rows[0]?.status ?? 'missing';
};

const digest = (n: number): string => `sha256:${String(n).padStart(64, '0')}`;

describe('the emergency lock, during an active session', () => {
  it('lets the session work first, so the test is about the lock and not the setup', async () => {
    const body = (await read()).json();
    expect(body.error).toBeUndefined();
    expect(reads).toContain(FILE);
  });

  it('refuses the very next request, and reaches nothing upstream', async () => {
    const before = reads.length;

    const startedAt = Date.now();
    await lockWorkspace(pool, redis, { workspaceId: WS, locked: true, actorUserId: USER });

    const body = (await read()).json();
    const elapsed = Date.now() - startedAt;

    expect(body.error.code).toBe(RPC.DENIED);
    expect(body.error.data.reason_code).toBe('WORKSPACE_LOCKED');
    // Step 3 of the pipeline, before a credential is minted — so a lock is not
    // merely a refusal to return the answer, it is a refusal to go and get it.
    expect(reads.length).toBe(before);
    // §11. Generous on purpose: what is really being asserted is that the
    // *first* request after the lock already refuses, which the line above
    // covers. This one fails loudly if somebody ever introduces a cache.
    expect(elapsed).toBeLessThan(REVOCATION_BUDGET_MS);
  });

  it('kills every outstanding grant in the workspace, whichever agent earned it', async () => {
    await lockWorkspace(pool, redis, { workspaceId: WS, locked: false, actorUserId: USER });

    const mine = await liveGrant(AGENT, digest(1));
    const theirs = await liveGrant(OTHER_AGENT, digest(2));

    const result = await lockWorkspace(pool, redis, {
      workspaceId: WS,
      locked: true,
      actorUserId: USER,
    });

    expect(result.grantsRevoked).toHaveLength(2);
    expect(await statusOf(mine)).toBe('revoked');
    expect(await statusOf(theirs)).toBe('revoked');
  });

  it('leaves a revoked grant unredeemable, so lifting the lock does not resurrect it', async () => {
    const grant = await liveGrant(AGENT, digest(3));
    await lockWorkspace(pool, redis, { workspaceId: WS, locked: true, actorUserId: USER });
    await lockWorkspace(pool, redis, { workspaceId: WS, locked: false, actorUserId: USER });

    const outcome = await withWorkspace(pool, WS, (db) =>
      redeemApproval(db, {
        workspaceId: WS,
        approvalId: grant,
        humanId: USER,
        actionDigest: digest(3),
      }),
    );

    expect(outcome.ok).toBe(false);
    // Unlocking restores the ability to ask. It does not hand back authority
    // that somebody deliberately withdrew.
    expect(outcome).toMatchObject({ reasonCode: 'APPROVAL_REQUIRED' });
  });

  it('keeps the revoked grant readable, so a lock incident is reconstructable', async () => {
    const grant = await liveGrant(AGENT, digest(4));
    await lockWorkspace(pool, redis, { workspaceId: WS, locked: true, actorUserId: USER });

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ status: string; approver_id: string; resolved_at: Date | null; action_digest: string }>(
        `select status, approver_id, resolved_at, action_digest
           from approvals where workspace_id = $1 and id = $2`,
        [WS, grant],
      ),
    );

    const row = rows[0];
    // Revoked, not deleted, and not folded into 'expired' — which would have
    // required clearing resolved_at and erasing who approved it and when.
    expect(row?.status).toBe('revoked');
    expect(row?.approver_id).toBe(USER);
    expect(row?.resolved_at).not.toBeNull();
    expect(row?.action_digest).toBe(digest(4));

    await lockWorkspace(pool, redis, { workspaceId: WS, locked: false, actorUserId: USER });
  });

  it('is idempotent — locking an already-locked workspace still converges', async () => {
    await lockWorkspace(pool, redis, { workspaceId: WS, locked: true, actorUserId: USER });
    const grant = await liveGrant(AGENT, digest(5));

    // A grant created while locked cannot be acted on — step 3 denies first —
    // but it should not survive the next attempt either. A retry after a
    // partial failure has to reach it.
    const second = await lockWorkspace(pool, redis, {
      workspaceId: WS,
      locked: true,
      actorUserId: USER,
    });

    expect(second.alreadyInThatState).toBe(true);
    expect(await statusOf(grant)).toBe('revoked');

    await lockWorkspace(pool, redis, { workspaceId: WS, locked: false, actorUserId: USER });
  });
});

describe('agent revocation, during an active session', () => {
  it('refuses the very next request from that agent, and no other', async () => {
    const facts = createFakePolicyFacts();
    const grant = await liveGrant(OTHER_AGENT, digest(6));

    const startedAt = Date.now();
    const result = await revokeAgentEverywhere(pool, redis, facts, {
      workspaceId: WS,
      agentId: OTHER_AGENT,
      actorUserId: USER,
    });

    const refused = (await read(OTHER_AGENT)).json();
    const elapsed = Date.now() - startedAt;

    expect(refused.error.code).toBe(RPC.UNAUTHENTICATED);
    expect(elapsed).toBeLessThan(REVOCATION_BUDGET_MS);

    // Its outstanding grant went with it. An approval names a human and an
    // action, not an agent, so nothing about the status flip would have
    // invalidated this on its own.
    expect(result.grantsRevoked).toContain(grant);
    expect(await statusOf(grant)).toBe('revoked');

    // The other agent is untouched. Revocation is targeted, not a blackout.
    const other = (await read(AGENT)).json();
    expect(other.error).toBeUndefined();
  });

  it('leaves another agent’s grant alone', async () => {
    const mine = await liveGrant(AGENT, digest(7));
    const facts = createFakePolicyFacts();

    await revokeAgentEverywhere(pool, redis, facts, {
      workspaceId: WS,
      agentId: OTHER_AGENT,
      actorUserId: USER,
    });

    expect(await statusOf(mine)).toBe('approved');
  });
});

describe('connection revocation, during an active session', () => {
  it('stops the next call reaching Drive, without pretending it succeeded', async () => {
    const before = reads.length;

    await withWorkspace(pool, WS, (db) => revokeConnection(db, WS, connectionId, USER));

    const body = (await read()).json();

    expect(body.error.code).toBe(RPC.DENIED);
    expect(body.error.data.reason_code).toBe('CONNECTION_EXPIRED');
    expect(reads.length).toBe(before);
  });
});
