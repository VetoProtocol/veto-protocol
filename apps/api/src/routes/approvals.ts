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
 * **No passkey yet.** Stage 3 adds the WebAuthn ceremony that proves the person
 * resolving is really there. This endpoint is the state machine those
 * signatures will gate — built first so the ceremony has something correct to
 * protect.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import { resolveApproval } from '@veto/decisions';
import { writeAuditEvent } from '@veto/identity';
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
  required: ['decision'],
  properties: { decision: { type: 'string', enum: ['approved', 'denied'] } },
} as const;

interface Params {
  approvalId: string;
}
interface Body {
  decision: 'approved' | 'denied';
}

export function registerApprovalRoutes(app: FastifyInstance, deps: { pool: Pool }): void {
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

      const outcome = await withWorkspace(deps.pool, workspaceId, async (db) => {
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
            eventType: 'approval.resolved',
            resourceRef: `approval:${approvalId}`,
            outcome: result.status === 'approved' ? 'allow' : 'deny',
            correlationId: null,
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
