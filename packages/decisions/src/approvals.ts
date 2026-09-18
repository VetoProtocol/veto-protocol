/**
 * The approval state machine (spec §7.1, invariants 6 and 7).
 *
 * A challenge is only worth something if the grant it produces is hard to
 * misuse. Four separate refusals, each its own reason code, each its own test:
 *
 *  * **Only the original delegating user may resolve it.** Not an admin, not a
 *    colleague, not whoever opened the link. §12.1's "approval link opened by a
 *    different user" is this, and it is the one an attacker reaches by
 *    forwarding a message.
 *  * **Single use.** Approved becomes consumed exactly once. A second attempt
 *    is a replay even when everything else about it is valid.
 *  * **Time bound.** An expired grant is refused whatever its status says.
 *  * **Bound to the exact action.** Consuming requires the same action digest
 *    the approval was created with, so changing any argument after approval
 *    produces a different digest and finds nothing to consume.
 *
 * The ceremony that proves *who* resolved it — WebAuthn against the stored
 * challenge — is stage 3. What is here is the state machine those signatures
 * will gate, built first so the ceremony has something correct to protect.
 */

import type { Db } from '@veto/db';

export type ApprovalDecision = 'approved' | 'denied';

export interface ApprovalRow {
  readonly id: string;
  readonly decision_id: string;
  readonly approver_id: string;
  readonly action_digest: string;
  readonly status: 'pending' | 'approved' | 'denied' | 'expired' | 'consumed';
  readonly expires_at: Date;
}

export type ResolveOutcome =
  | { readonly ok: true; readonly status: ApprovalDecision }
  | { readonly ok: false; readonly reasonCode: string };

export interface ResolveInput {
  readonly workspaceId: string;
  readonly approvalId: string;
  /** Who is trying to resolve it. Compared against the original delegator. */
  readonly approverId: string;
  readonly decision: ApprovalDecision;
}

export async function resolveApproval(db: Db, input: ResolveInput): Promise<ResolveOutcome> {
  // Locked for the length of the transaction so two concurrent resolutions
  // cannot both see 'pending'.
  const { rows } = await db.query<ApprovalRow>(
    `select id, decision_id, approver_id, action_digest, status, expires_at
       from approvals
      where workspace_id = $1 and id = $2
      for update`,
    [input.workspaceId, input.approvalId],
  );

  const approval = rows[0];
  // Not found and not-yours are the same answer. Distinguishing them would let
  // someone with a forwarded link learn that an approval exists.
  if (!approval) return { ok: false, reasonCode: 'APPROVER_NOT_DELEGATOR' };

  if (approval.approver_id !== input.approverId) {
    return { ok: false, reasonCode: 'APPROVER_NOT_DELEGATOR' };
  }

  // Expiry is checked before status, so an expired approval reads as expired
  // rather than as whatever it was before it lapsed.
  if (approval.expires_at.getTime() <= Date.now()) {
    if (approval.status === 'pending') {
      await db.query(`update approvals set status = 'expired' where workspace_id = $1 and id = $2`, [
        input.workspaceId,
        approval.id,
      ]);
    }
    return { ok: false, reasonCode: 'APPROVAL_EXPIRED' };
  }

  if (approval.status !== 'pending') {
    return { ok: false, reasonCode: 'APPROVAL_REPLAYED' };
  }

  await db.query(
    `update approvals set status = $3, resolved_at = now()
      where workspace_id = $1 and id = $2 and status = 'pending'`,
    [input.workspaceId, approval.id, input.decision],
  );

  return { ok: true, status: input.decision };
}

export type RedeemOutcome =
  | { readonly ok: true; readonly approvalId: string }
  | { readonly ok: false; readonly reasonCode: string };

/**
 * Spend a named grant, once, against this exact action.
 *
 * The caller presents the approval id — §5.3 says a challenge resumes only with
 * an unexpired, single-use grant, so the grant is something the client holds
 * and shows, not something the server goes looking for. That also makes the
 * replay attack explicit: the same id offered twice, or offered against changed
 * arguments, is a distinct refusal rather than a silent miss.
 *
 * Order of checks matters. Ownership is verified before anything else is
 * revealed; the digest is compared before the status, so an attacker who
 * changed an argument learns "wrong action", not "already used".
 *
 * The flip to consumed is one statement matching on status, so two concurrent
 * retries cannot both succeed — the second updates zero rows. Read-then-write
 * would leave a window in which a replay is a legitimate read.
 */
export async function redeemApproval(
  db: Db,
  input: {
    readonly workspaceId: string;
    readonly approvalId: string;
    readonly humanId: string;
    readonly actionDigest: string;
  },
): Promise<RedeemOutcome> {
  const { rows } = await db.query<ApprovalRow>(
    `select id, decision_id, approver_id, action_digest, status, expires_at
       from approvals
      where workspace_id = $1 and id = $2
      for update`,
    [input.workspaceId, input.approvalId],
  );

  const approval = rows[0];
  // Not found and not-yours give the same answer: a forwarded link must not
  // reveal that an approval exists (invariant 7).
  if (!approval || approval.approver_id !== input.humanId) {
    return { ok: false, reasonCode: 'APPROVER_NOT_DELEGATOR' };
  }

  if (approval.action_digest !== input.actionDigest) {
    // The grant was for a different action. A changed argument set is a
    // different action, and needs its own approval (invariant 6).
    return { ok: false, reasonCode: 'APPROVAL_DIGEST_MISMATCH' };
  }

  if (approval.expires_at.getTime() <= Date.now()) {
    return { ok: false, reasonCode: 'APPROVAL_EXPIRED' };
  }

  if (approval.status === 'consumed') return { ok: false, reasonCode: 'APPROVAL_REPLAYED' };
  if (approval.status === 'denied') return { ok: false, reasonCode: 'POLICY_DENIED' };
  if (approval.status !== 'approved') return { ok: false, reasonCode: 'APPROVAL_REQUIRED' };

  const spent = await db.query<{ id: string }>(
    `update approvals
        set status = 'consumed', consumed_at = now()
      where workspace_id = $1 and id = $2 and status = 'approved' and expires_at > now()
      returning id`,
    [input.workspaceId, approval.id],
  );

  // Lost the race with a concurrent redemption of the same grant.
  if (spent.rows.length === 0) return { ok: false, reasonCode: 'APPROVAL_REPLAYED' };

  return { ok: true, approvalId: approval.id };
}
