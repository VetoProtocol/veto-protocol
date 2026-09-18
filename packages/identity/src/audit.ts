import { newId } from '@veto/core';
import type { Db } from '@veto/db';

/**
 * Append one audit event. Spec FR-09: every decision and lifecycle change gets
 * one. The hash chain is computed by the database trigger, not here.
 *
 * `resourceRef` is a reference, never content (invariant 5, §11). Nothing in
 * this signature can carry a document body, a token or a challenge, which is
 * deliberate — the type is the control.
 */
export interface AuditEventInput {
  readonly workspaceId: string;
  readonly actor: string;
  readonly eventType: string;
  readonly resourceRef?: string | null;
  readonly outcome: 'allow' | 'deny' | 'challenge' | 'lifecycle';
  readonly correlationId?: string | null;
}

export async function writeAuditEvent(db: Db, event: AuditEventInput): Promise<string> {
  const id = newId('aud_');
  await db.query(
    `insert into audit_events
       (id, workspace_id, actor, event_type, resource_ref, outcome, correlation_id)
     values ($1, $2, $3, $4, $5, $6, $7)`,
    [
      id,
      event.workspaceId,
      event.actor,
      event.eventType,
      event.resourceRef ?? null,
      event.outcome,
      event.correlationId ?? null,
    ],
  );
  return id;
}
