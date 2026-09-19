/**
 * POST /v1/approvals/{id}/resolve (spec §5).
 *
 * Where a human says yes or no to a challenge. Two rules do the work, and both
 * live in the domain rather than here:
 *
 *  * Only the original delegating user may resolve it (invariant 7). A
 *    workspace admin cannot; nor can whoever was forwarded the link.
 *  * A resolution happens once. A second attempt is a replay.
 *
 * The approver is the authenticated principal and never a body field. Accepting
 * one would make the entire control an honour system.
 *
 * ## The signature is what makes this real
 *
 * Resolving requires a WebAuthn assertion over the challenge **already stored
 * on the approval row**. Not a challenge the client asked for, and not a fresh
 * one — that exact approval's bytes. So a valid signature proves three things
 * at once: a human was present, they hold the delegator's enrolled credential,
 * and what they agreed to was this approval.
 *
 * A user with no enrolled passkey cannot resolve anything. That is a refusal,
 * not a fallback: an approval that can be granted without proof is the control
 * §13 asks for, minus the control.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import { resolveApproval } from '@veto/decisions';
import { writeAuditEvent } from '@veto/identity';
import {
  CeremonyError,
  buildAuthenticationOptions,
  claimedCredentialId,
  findByCredentialId,
  listPasskeys,
  recordUse,
  verifyAssertion,
  type WebAuthnConfig,
} from '@veto/passkeys';
import { setPresence } from '@veto/presence';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

const PARAMS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['approvalId'],
  properties: { approvalId: { type: 'string', pattern: '^apr_[A-Za-z0-9_-]{1,64}$' } },
} as const;

const BODY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['decision', 'assertion'],
  properties: {
    decision: { type: 'string', enum: ['approved', 'denied'] },
    // Required for both answers. A refusal that needed no proof would let
    // anyone holding the link deny an approval the real user wanted.
    assertion: { type: 'object' },
  },
} as const;

interface Params {
  approvalId: string;
}
interface Body {
  decision: 'approved' | 'denied';
  assertion: Record<string, unknown>;
}

export interface ApprovalRoutesDeps {
  readonly pool: Pool;
  readonly webauthn: WebAuthnConfig | null;
}

export function registerApprovalRoutes(app: FastifyInstance, deps: ApprovalRoutesDeps): void {
  /**
   * The challenge to sign, for one approval.
   *
   * Only the approver gets it, and only while the approval is still open —
   * otherwise this endpoint would confirm to anyone holding a forwarded link
   * that the approval exists.
   */
  app.get(
    '/v1/approvals/:approvalId/challenge',
    { schema: { params: PARAMS_SCHEMA, response: { '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA } } },
    async (request: FastifyRequest<{ Params: Params }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      if (!deps.webauthn) {
        throw new HttpError(503, 'IDENTITY_UNRESOLVED', 'Passkeys are not configured on this server');
      }

      const found = await withWorkspace(deps.pool, workspaceId, async (db) => {
        const { rows } = await db.query<{ challenge: Buffer; approver_id: string; status: string }>(
          `select challenge, approver_id, status from approvals
            where workspace_id = $1 and id = $2`,
          [workspaceId, request.params.approvalId],
        );
        const row = rows[0];
        // Not found, not yours, and already resolved are one answer.
        if (!row || row.approver_id !== userId || row.status !== 'pending') return null;
        return { challenge: row.challenge, passkeys: await listPasskeys(db, workspaceId, userId) };
      });

      if (!found) {
        throw new HttpError(403, 'APPROVER_NOT_DELEGATOR', 'That approval cannot be resolved.');
      }
      if (found.passkeys.length === 0) {
        throw new HttpError(403, 'APPROVER_NOT_DELEGATOR', 'Enrol a passkey before approving.');
      }

      return buildAuthenticationOptions(deps.webauthn, found.challenge, found.passkeys);
    },
  );

  app.post(
    '/v1/approvals/:approvalId/resolve',
    {
      schema: {
        params: PARAMS_SCHEMA,
        body: BODY_SCHEMA,
        response: {
          200: {
            type: 'object',
            properties: { approval_id: { type: 'string' }, status: { type: 'string' } },
            required: ['approval_id', 'status'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Params: Params; Body: Body }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const { approvalId } = request.params;

      if (!deps.webauthn) {
        throw new HttpError(503, 'IDENTITY_UNRESOLVED', 'Passkeys are not configured on this server');
      }
      const webauthn = deps.webauthn;

      const outcome = await withWorkspace(deps.pool, workspaceId, async (db) => {
        // The challenge comes from the row, so the signature is over *this*
        // approval. Locked for the transaction alongside the resolution.
        const { rows } = await db.query<{ challenge: Buffer; approver_id: string; status: string }>(
          `select challenge, approver_id, status from approvals
            where workspace_id = $1 and id = $2 for update`,
          [workspaceId, approvalId],
        );

        const row = rows[0];
        if (!row || row.approver_id !== userId) {
          return { ok: false as const, reasonCode: 'APPROVER_NOT_DELEGATOR' };
        }

        const claimed = claimedCredentialId(request.body.assertion);
        if (!claimed) return { ok: false as const, reasonCode: 'APPROVER_NOT_DELEGATOR' };

        const passkey = await findByCredentialId(db, workspaceId, claimed);
        // The credential must belong to the approver, not merely to somebody in
        // this workspace (invariant 7).
        if (!passkey || passkey.userId !== userId) {
          return { ok: false as const, reasonCode: 'APPROVER_NOT_DELEGATOR' };
        }

        let assertion;
        try {
          assertion = await verifyAssertion(
            webauthn,
            request.body.assertion as never,
            row.challenge,
            passkey,
          );
        } catch (error) {
          if (error instanceof CeremonyError) {
            return { ok: false as const, reasonCode: 'APPROVER_NOT_DELEGATOR' };
          }
          throw error;
        }

        // A counter that did not move forward means a cloned credential or a
        // replayed response.
        const advanced = await recordUse(db, workspaceId, passkey.id, assertion.signCount);
        if (!advanced) return { ok: false as const, reasonCode: 'APPROVAL_REPLAYED' };

        const result = await resolveApproval(db, {
          workspaceId,
          approvalId,
          approverId: userId,
          decision: request.body.decision,
        });

        if (result.ok) {
          await writeAuditEvent(db, {
            workspaceId,
            actor: userId,
            // The audit records that an approval was resolved with a verified
            // passkey. It never records the challenge or the signature.
            eventType: 'approval.resolved',
            resourceRef: `approval:${approvalId}`,
            outcome: result.status === 'approved' ? 'allow' : 'deny',
            correlationId: null,
          });

          // A verified assertion is the strongest presence signal there is: a
          // human demonstrably did something only they could do, just now.
          await setPresence(db, {
            workspaceId,
            userId,
            state: 'active',
            source: 'passkey',
            assurance: 'high',
          }).catch(() => {
            // A locked user resolving an approval is a legal thing to refuse
            // here; it must not undo the resolution that already succeeded.
          });
        }
        return result;
      });

      if (!outcome.ok) {
        // 403 for every refusal, with the reason code carrying the detail. A
        // 404 for "not yours" would confirm the id is real to whoever holds a
        // forwarded link.
        throw new HttpError(403, outcome.reasonCode, 'That approval cannot be resolved.');
      }

      return { approval_id: approvalId, status: outcome.status };
    },
  );
}
