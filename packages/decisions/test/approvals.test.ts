/**
 * §12.1 — an approved action replayed after expiry, and an approval link
 * opened by a different user.
 *
 * These two scenarios are the reason a challenge is worth anything. If the
 * grant it produces can be reused, forwarded, or stretched to cover a different
 * action, the step-up was theatre.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, type FakePolicyDecisions } from '@veto/permit';
import { evaluate } from '../src/pipeline.ts';
import { redeemApproval, resolveApproval } from '../src/approvals.ts';
import { addPolicy, request, seed, setPresence, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyDecisions;

const s = suffix();
const WS = `ws_ap${s}`;
const ALICE = `usr_alice${s}`;
const MALLORY = `usr_mal${s}`;
const AGENT = `agt_ap${s}`;
const FILE = '/Finance/q3.xlsx';

const deps = () => ({ pool, redis, policy });

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyDecisions();
  await seed(pool, WS, ALICE, AGENT);
  await withWorkspace(pool, WS, (db) =>
    db.query(`insert into users (id,workspace_id,identity_subject) values ($1,$2,$3)`, [
      MALLORY, WS, `oidc|${MALLORY}`,
    ]),
  );
  await setPresence(pool, WS, ALICE, 'active');
  await addPolicy(pool, WS, {
    subject: AGENT, action: 'read', effect: 'challenge',
    resourceFilter: { type: 'google_file' }, version: 'polv_ap',
  });
  policy.allow(WS, AGENT, 'read', 'google_file', FILE);
});

afterAll(async () => {
  await pool.end();
  redis.disconnect();
});

const ask = (over: Record<string, unknown> = {}) =>
  evaluate(deps(), request({
    workspaceId: WS, humanId: ALICE, agentId: AGENT,
    resource: { type: 'google_file', id: FILE },
    ...over,
  }));

const approve = (approvalId: string, approverId = ALICE) =>
  withWorkspace(pool, WS, (db) =>
    resolveApproval(db, { workspaceId: WS, approvalId, approverId, decision: 'approved' }),
  );

describe('§12.1 — an approval link opened by a different user', () => {
  it('refuses a resolver who is not the original delegator', async () => {
    const challenged = await ask();
    expect(challenged.result).toBe('challenge');

    // Mallory is a real member of the same workspace. Membership is not
    // permission to approve somebody else's challenge (invariant 7).
    const outcome = await approve(challenged.approvalId ?? '', MALLORY);

    expect(outcome).toEqual({ ok: false, reasonCode: 'APPROVER_NOT_DELEGATOR' });
  });

  it('leaves the approval untouched after a failed attempt', async () => {
    const challenged = await ask();
    await approve(challenged.approvalId ?? '', MALLORY);

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ status: string }>(`select status from approvals where id=$1`, [challenged.approvalId]),
    );
    // A failed attempt must not burn the grant — otherwise anyone who can open
    // the link can deny the real user their approval.
    expect(rows[0]?.status).toBe('pending');
  });

  it('gives the same answer for an approval that does not exist', async () => {
    // Otherwise a forwarded link tells the holder that it is real.
    const outcome = await approve(`apr_${suffix()}${suffix()}`, MALLORY);
    expect(outcome).toEqual({ ok: false, reasonCode: 'APPROVER_NOT_DELEGATOR' });
  });

  it('will not let the wrong user redeem a grant the right user approved', async () => {
    const challenged = await ask();
    await approve(challenged.approvalId ?? '');

    const stolen = await withWorkspace(pool, WS, (db) =>
      redeemApproval(db, {
        workspaceId: WS,
        approvalId: challenged.approvalId ?? '',
        humanId: MALLORY,
        actionDigest: challenged.actionDigest,
      }),
    );
    expect(stolen).toEqual({ ok: false, reasonCode: 'APPROVER_NOT_DELEGATOR' });
  });
});

describe('§12.1 — a previously approved action replayed', () => {
  it('allows the retry once, then denies the replay', async () => {
    const challenged = await ask();
    await approve(challenged.approvalId ?? '');

    const first = await ask({ approvalId: challenged.approvalId });
    expect(first.result).toBe('allow');

    // Single use. The second attempt is a replay even though nothing else
    // about it changed.
    const second = await ask({ approvalId: challenged.approvalId });
    expect(second.result).toBe('deny');
    expect(second.reasonCode).toBe('APPROVAL_REPLAYED');
  });

  it('denies a grant whose arguments changed after approval', async () => {
    const challenged = await ask();
    await approve(challenged.approvalId ?? '');

    // Same approval, different action. The digest covers the arguments, so this
    // is not the thing that was approved (invariant 6).
    const widened = await ask({
      approvalId: challenged.approvalId,
      arguments: { fields: ['name', 'content'] },
    });

    expect(widened.result).toBe('deny');
    expect(widened.reasonCode).toBe('APPROVAL_DIGEST_MISMATCH');
  });

  it('denies an expired grant', async () => {
    const challenged = await evaluate(
      { pool, redis, policy, approvalTtlMs: 1000 },
      request({
        workspaceId: WS, humanId: ALICE, agentId: AGENT,
        resource: { type: 'google_file', id: FILE },
      }),
    );
    await approve(challenged.approvalId ?? '');

    await withWorkspace(pool, WS, (db) =>
      db.query(`update approvals set expires_at = created_at + interval '1 millisecond' where id=$1`, [
        challenged.approvalId,
      ]),
    );

    const late = await ask({ approvalId: challenged.approvalId });
    expect(late.result).toBe('deny');
    expect(late.reasonCode).toBe('APPROVAL_EXPIRED');
  });

  it('denies a grant that was never approved', async () => {
    const challenged = await ask();
    // Still pending — nobody said yes.
    const early = await ask({ approvalId: challenged.approvalId });
    expect(early.result).toBe('deny');
    expect(early.reasonCode).toBe('APPROVAL_REQUIRED');
  });

  it('denies a grant the user refused', async () => {
    const challenged = await ask();
    await withWorkspace(pool, WS, (db) =>
      resolveApproval(db, {
        workspaceId: WS, approvalId: challenged.approvalId ?? '',
        approverId: ALICE, decision: 'denied',
      }),
    );

    const after = await ask({ approvalId: challenged.approvalId });
    expect(after.result).toBe('deny');
  });
});

describe('resolving', () => {
  it('cannot be resolved twice', async () => {
    const challenged = await ask();
    expect(await approve(challenged.approvalId ?? '')).toEqual({ ok: true, status: 'approved' });
    expect(await approve(challenged.approvalId ?? '')).toEqual({
      ok: false,
      reasonCode: 'APPROVAL_REPLAYED',
    });
  });

  it('marks a lapsed approval expired rather than leaving it pending', async () => {
    const challenged = await ask();
    await withWorkspace(pool, WS, (db) =>
      db.query(`update approvals set expires_at = created_at + interval '1 millisecond' where id=$1`, [
        challenged.approvalId,
      ]),
    );

    expect(await approve(challenged.approvalId ?? '')).toEqual({
      ok: false,
      reasonCode: 'APPROVAL_EXPIRED',
    });

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ status: string }>(`select status from approvals where id=$1`, [challenged.approvalId]),
    );
    expect(rows[0]?.status).toBe('expired');
  });
});
