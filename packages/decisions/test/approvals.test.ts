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

/**
 * An `ask` bound to one test's own action.
 *
 * The digest covers `arguments`, so a unique argument gives a test a private
 * action that no other test's approval can satisfy. This matters now that an
 * approved, unconsumed grant is found by digest rather than only when a client
 * names it: without this, one test approving something leaves a live grant that
 * the next test's identical call would legitimately spend.
 *
 * That is correct behaviour in the product and unhelpful between tests.
 */
const asker = (tag: string) => {
  const args = { fields: ['name'], tag };
  return (over: Record<string, unknown> = {}) => ask({ arguments: args, ...over });
};

const approve = (approvalId: string, approverId = ALICE) =>
  withWorkspace(pool, WS, (db) =>
    resolveApproval(db, { workspaceId: WS, approvalId, approverId, decision: 'approved' }),
  );

describe('§12.1 — an approval link opened by a different user', () => {
  it('refuses a resolver who is not the original delegator', async () => {
    const ask = asker('refuses-a-resolver');
    const challenged = await ask();
    expect(challenged.result).toBe('challenge');

    // Mallory is a real member of the same workspace. Membership is not
    // permission to approve somebody else's challenge (invariant 7).
    const outcome = await approve(challenged.approvalId ?? '', MALLORY);

    expect(outcome).toEqual({ ok: false, reasonCode: 'APPROVER_NOT_DELEGATOR' });
  });

  it('leaves the approval untouched after a failed attempt', async () => {
    const ask = asker('leaves-the-approva');
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
    const ask = asker('steal');
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
    const ask = asker('replay');
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
    const ask = asker('widen');
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
    // This one builds its own challenge rather than going through `ask`,
    // because it needs a short TTL. Both halves must name the same action, or
    // the retry is a digest mismatch rather than the expiry this is about.
    const args = { fields: ['name'], tag: 'denies-an-expired' };
    const ask = (over: Record<string, unknown> = {}) =>
      evaluate(deps(), request({
        workspaceId: WS, humanId: ALICE, agentId: AGENT,
        resource: { type: 'google_file', id: FILE },
        arguments: args,
        ...over,
      }));
    const challenged = await evaluate(
      { pool, redis, policy, approvalTtlMs: 1000 },
      request({
        workspaceId: WS, humanId: ALICE, agentId: AGENT,
        resource: { type: 'google_file', id: FILE },
        arguments: args,
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
    const ask = asker('denies-a-grant-tha');
    const challenged = await ask();
    // Still pending — nobody said yes.
    const early = await ask({ approvalId: challenged.approvalId });
    expect(early.result).toBe('deny');
    expect(early.reasonCode).toBe('APPROVAL_REQUIRED');
  });

  it('denies a grant the user refused', async () => {
    const ask = asker('denies-a-grant-the');
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
    const ask = asker('cannot-be-resolved');
    const challenged = await ask();
    expect(await approve(challenged.approvalId ?? '')).toEqual({ ok: true, status: 'approved' });
    expect(await approve(challenged.approvalId ?? '')).toEqual({
      ok: false,
      reasonCode: 'APPROVAL_REPLAYED',
    });
  });

  it('marks a lapsed approval expired rather than leaving it pending', async () => {
    const ask = asker('marks-a-lapsed-app');
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

describe('resuming without the client echoing an approval id', () => {
  // The case the product actually meets. A challenge names an `approval_id` and
  // expects it back on the retry, but that parameter is ours and no ordinary
  // MCP client sends it — so before this, a human could approve with a passkey
  // and the agent would be challenged again on every retry, forever.

  it('allows the identical call once the human has approved it', async () => {
    const ask = asker('resume');
    const challenged = await ask();
    expect(challenged.result).toBe('challenge');
    await approve(challenged.approvalId ?? '');

    // No approvalId. The digest is what binds the grant to the action.
    const resumed = await ask();
    expect(resumed.result).toBe('allow');
  });

  it('is still single use — the next identical call is challenged again', async () => {
    const ask = asker('once');
    const challenged = await ask();
    await approve(challenged.approvalId ?? '');

    expect((await ask()).result).toBe('allow');
    // Consumed. A second free pass would make one approval a standing licence.
    expect((await ask()).result).toBe('challenge');
  });

  it('does not carry over to a different action', async () => {
    const ask = asker('other');
    const challenged = await ask();
    await approve(challenged.approvalId ?? '');

    // Same tool, different arguments: a different digest, so the grant this
    // human gave does not apply to it (invariant 6).
    const other = await ask({ arguments: { fields: ['name', 'content'] } });
    expect(other.result).toBe('challenge');

    // And the original grant is still there, unspent, for the call it was for.
    expect((await ask()).result).toBe('allow');
  });

  it('never hands one person the grant another person gave', async () => {
    const ask = asker('mine');
    const challenged = await ask();
    await approve(challenged.approvalId ?? '');

    // Mallory asking for the same thing finds nothing: the lookup is scoped to
    // the approver, so this is the same refusal as a forwarded link.
    const mallory = await evaluate(deps(), request({
      workspaceId: WS, humanId: MALLORY, agentId: AGENT,
      resource: { type: 'google_file', id: FILE },
    }));
    expect(mallory.result).not.toBe('allow');

    expect((await ask()).result).toBe('allow');
  });

  it('ignores an approval that has expired', async () => {
    const ask = asker('stale');
    const challenged = await ask();
    await approve(challenged.approvalId ?? '');
    await withWorkspace(pool, WS, (db) =>
      db.query(`update approvals set expires_at = created_at + interval '1 millisecond' where id=$1`, [
        challenged.approvalId,
      ]),
    );

    expect((await ask()).result).toBe('challenge');
  });

  it('ignores one that was denied rather than approved', async () => {
    const ask = asker('nope');
    const challenged = await ask();
    await withWorkspace(pool, WS, (db) =>
      resolveApproval(db, {
        workspaceId: WS, approvalId: challenged.approvalId ?? '',
        approverId: ALICE, decision: 'denied',
      }),
    );

    expect((await ask()).result).toBe('challenge');
  });

  it('still honours an explicitly presented approval id', async () => {
    const ask = asker('named');
    const challenged = await ask();
    await approve(challenged.approvalId ?? '');
    const resumed = await ask({ approvalId: challenged.approvalId });
    expect(resumed.result).toBe('allow');
  });
});

describe('being challenged again for something nobody answered', () => {
  // A pending approval that lapsed keeps `status = 'pending'`, so it still
  // occupies the partial unique index while being invisible to the reuse
  // lookup, which requires an unexpired row. The next challenge for the same
  // action collided with it and the duplicate-key error escaped as a bare
  // internal error — so letting one challenge time out made that action
  // permanently unaskable.

  it('challenges again rather than failing, once the first has lapsed', async () => {
    const ask = asker('lapsed');
    const first = await ask();
    expect(first.result).toBe('challenge');

    await withWorkspace(pool, WS, (db) =>
      db.query(`update approvals set expires_at = created_at + interval '1 millisecond' where id=$1`, [
        first.approvalId,
      ]),
    );

    // This is the call that used to throw.
    const second = await ask();
    expect(second.result).toBe('challenge');
    expect(second.approvalId).toBeTruthy();
    expect(second.approvalId).not.toBe(first.approvalId);
  });

  it('marks the lapsed one expired rather than leaving it pending forever', async () => {
    const ask = asker('lapsed-status');
    const first = await ask();
    await withWorkspace(pool, WS, (db) =>
      db.query(`update approvals set expires_at = created_at + interval '1 millisecond' where id=$1`, [
        first.approvalId,
      ]),
    );
    await ask();

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ status: string }>(`select status from approvals where id=$1`, [first.approvalId]),
    );
    expect(rows[0]?.status).toBe('expired');
  });

  it('still reuses a live one instead of opening a rival', async () => {
    const ask = asker('still-live');
    const first = await ask();
    const second = await ask();

    // Unexpired and unanswered: the same grant, so approving once is enough.
    expect(second.approvalId).toBe(first.approvalId);
  });

  it('a lapsed grant cannot be approved into a working one', async () => {
    const ask = asker('lapsed-noapprove');
    const first = await ask();
    await withWorkspace(pool, WS, (db) =>
      db.query(`update approvals set expires_at = created_at + interval '1 millisecond' where id=$1`, [
        first.approvalId,
      ]),
    );
    await ask();

    // The sweep moved it to `expired`, so resolving it is refused and it can
    // never become a grant that resumes anything.
    const outcome = await approve(first.approvalId ?? '');
    expect(outcome.ok).toBe(false);
    expect((await ask({ approvalId: first.approvalId })).result).not.toBe('allow');
  });
});
