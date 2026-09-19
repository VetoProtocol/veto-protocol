/**
 * Self-service signup — a person creating their own workspace (spec §1.3).
 *
 * §1.3's first persona is the individual professional, whose first release is a
 * "self-service dashboard and personal policies", and §4.2 says a tenant is an
 * organization *or a personal workspace*. The schema has carried
 * `type in ('personal','organization')` since migration 0001 and nothing has
 * ever created the first kind. This is that.
 *
 * ## The distinction this file exists to hold
 *
 * Two things get confused, and only one of them is dangerous:
 *
 *   * **Creating your own new workspace.** Safe. A verified identity gets an
 *     empty tenant of their own and reaches nothing that existed before.
 *   * **Joining somebody else's workspace.** Must never be automatic. That is
 *     what `inviteSubject` is for, and it stays an operator action.
 *
 * So the refusal below is the important line in this file: a subject that is
 * already a member *anywhere* cannot self-provision. Without it, "sign up"
 * would be a way to acquire a second membership, and the sign-in lookup —
 * which returns every workspace a subject belongs to — would start handing
 * people a choice that included a workspace nobody let them into.
 *
 * ## What the caller has to have done first
 *
 * Verified the id token. This function takes a subject string and believes it.
 * The only caller is the control-plane route behind the identity-resolve scope,
 * which the dashboard reaches only after `openid-client` has checked the
 * token's signature, issuer, audience, nonce and expiry. Same trust boundary as
 * `/v1/auth/resolve`; this one just writes.
 */

import type { Pool } from 'pg';
import { newId } from '@veto/core';
import { withWorkspace } from '@veto/db';
import { inviteSubject } from './invite.ts';
import { resolveIdentitySubject } from './identity-resolution.ts';

export interface ProvisionInput {
  readonly subject: string;
  /** What the person called it. Shown back to them and to nobody else. */
  readonly workspaceName: string;
}

export interface ProvisionResult {
  readonly workspaceId: string;
  readonly userId: string;
}

/**
 * Raised when the subject is already a member of something.
 *
 * Not an error the person caused — it means sign-in should have found them, and
 * the caller should send them through the normal path instead of creating a
 * second identity for the same human.
 */
export class SubjectAlreadyKnownError extends Error {
  constructor() {
    super('That account already belongs to a workspace');
    this.name = 'SubjectAlreadyKnownError';
  }
}

export async function provisionPersonalWorkspace(
  pool: Pool,
  input: ProvisionInput,
): Promise<ProvisionResult> {
  const subject = input.subject.trim();
  const name = input.workspaceName.trim();

  if (subject === '' || subject.length > 255) {
    throw new Error('subject must be between 1 and 255 characters');
  }
  if (name === '' || name.length > 120) {
    throw new Error('workspace name must be between 1 and 120 characters');
  }

  const workspaceId = newId('ws_');

  // Check and insert in **one** transaction, behind a lock keyed on the
  // subject.
  //
  // The obvious shape — look the subject up, then create — has a race, and the
  // database does not close it: uniqueness on `users` is
  // `(workspace_id, identity_subject)`, not the subject alone, so two
  // simultaneous signups would create two *different* workspaces and both
  // inserts would succeed. The result is one person with two personal
  // workspaces and a picker that offers the same thing twice. Nothing unsafe,
  // and nothing anybody could explain either.
  //
  // `hashtext` collides, as any 32-bit hash does. A collision here costs one
  // signup a short wait behind an unrelated one; it never lets a second through.
  // The namespace argument keeps this lock space apart from the audit chain's,
  // which locks on `hashtext(workspace_id)` in migration 0004.
  const result = await withWorkspace(pool, workspaceId, async (db) => {
    await db.query(`select pg_advisory_xact_lock(hashtext('veto.signup'), hashtext($1))`, [subject]);

    // The check that makes signup safe. Reads across tenants through the one
    // SECURITY DEFINER function allowed to (migration 0007), for one exact
    // subject, and refuses if anything comes back. Being inside this
    // transaction is what makes it mean something a moment later.
    const existing = await resolveIdentitySubject(db, subject);
    if (existing.length > 0) throw new SubjectAlreadyKnownError();

    return inviteSubject(db, {
      workspaceId,
      workspaceName: name,
      subject,
      // The whole point. An organization workspace is something an operator
      // sets up; this is one person's own.
      workspaceType: 'personal',
    });
  });

  return { workspaceId: result.workspaceId, userId: result.userId };
}
