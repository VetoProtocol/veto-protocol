/**
 * Workspace membership, created by hand.
 *
 * This is how somebody joins a workspace that already exists, and it stays an
 * operator action: there is no invitation UI, and a subject cannot talk its way
 * in. `provisionPersonalWorkspace` is the other door — a verified stranger
 * creating a workspace *of their own*, which reaches nothing that existed
 * before. The two are deliberately not the same function.
 *
 * Also used by signup, with `workspaceType: 'personal'`, because the insert is
 * identical once the decision has been made.
 *
 * Idempotent on the subject. Running it twice returns the existing membership
 * rather than creating a second user for the same person, so a retry after a
 * typo elsewhere cannot silently fork an identity.
 */

import { newId } from '@veto/core';
import type { Db } from '@veto/db';
import { writeAuditEvent } from './audit.ts';

export interface InviteInput {
  readonly workspaceId: string;
  readonly workspaceName: string;
  readonly subject: string;
  readonly workspaceType?: 'personal' | 'organization';
}

export interface InviteResult {
  readonly workspaceId: string;
  readonly userId: string;
  readonly created: boolean;
  readonly workspaceCreated: boolean;
}

export async function inviteSubject(db: Db, input: InviteInput): Promise<InviteResult> {
  const { workspaceId, subject } = input;

  if (subject.trim() === '' || subject.length > 255) {
    throw new Error('subject must be between 1 and 255 characters');
  }

  const workspace = await db.query(
    `insert into workspaces (id, name, type)
     values ($1, $2, $3)
     on conflict (id) do nothing
     returning id`,
    [workspaceId, input.workspaceName, input.workspaceType ?? 'organization'],
  );

  const existing = await db.query<{ id: string }>(
    `select id from users where workspace_id = $1 and identity_subject = $2`,
    [workspaceId, subject],
  );

  const already = existing.rows[0];
  if (already) {
    return {
      workspaceId,
      userId: already.id,
      created: false,
      workspaceCreated: workspace.rows.length > 0,
    };
  }

  const userId = newId('usr_');
  await db.query(
    `insert into users (id, workspace_id, identity_subject) values ($1, $2, $3)`,
    [userId, workspaceId, subject],
  );

  // The membership itself is auditable. The subject is a reference, not content
  // or a secret, so it is safe to record (invariant 5).
  await writeAuditEvent(db, {
    workspaceId,
    actor: userId,
    eventType: 'user.invited',
    resourceRef: `subject:${subject}`,
    outcome: 'lifecycle',
  });

  return { workspaceId, userId, created: true, workspaceCreated: workspace.rows.length > 0 };
}
