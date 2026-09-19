/**
 * POST /v1/auth/resolve — sign-in support.
 *
 * The dashboard verifies an OIDC id token itself and then needs the one thing
 * it cannot work out alone: which user and workspace that subject belongs to.
 * It asks here rather than reaching into the database, so the API stays the
 * only thing that touches identity storage (invariant 8).
 *
 * Guarded by a dedicated scope. A credential minted for sign-in resolution
 * cannot register or revoke an agent, and a dashboard session credential cannot
 * call this — so a leak in either direction stays contained.
 *
 * The response deliberately carries no user detail beyond ids. It is a lookup,
 * not a profile endpoint, and an empty result is a normal answer rather than an
 * error: an unknown subject is somebody with no workspace yet, and the dashboard
 * offers to make them one.
 *
 * `POST /v1/auth/provision` is that offer. It creates a **personal** workspace
 * for a verified subject that belongs to nothing — §1.3's individual
 * professional. Joining an *existing* workspace is a different thing entirely
 * and stays an operator action; see `provisionPersonalWorkspace` for the line
 * between them.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withoutTenant } from '@veto/db';
import {
  provisionPersonalWorkspace,
  resolveIdentitySubject,
  SubjectAlreadyKnownError,
} from '@veto/identity';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_IDENTITY_RESOLVE } from '../scope.ts';

const BODY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['subject'],
  properties: { subject: { type: 'string', minLength: 1, maxLength: 255 } },
} as const;

const PROVISION_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['subject', 'workspace_name'],
  properties: {
    subject: { type: 'string', minLength: 1, maxLength: 255 },
    // Shown back to its owner and to nobody else. Bounded because it is the one
    // free-text field a stranger can write before they have a workspace.
    workspace_name: { type: 'string', minLength: 1, maxLength: 120 },
  },
} as const;

interface ResolveBody {
  subject: string;
}

interface ProvisionBody {
  subject: string;
  workspace_name: string;
}

export function registerAuthRoutes(app: FastifyInstance, deps: { pool: Pool }): void {
  app.post(
    '/v1/auth/resolve',
    {
      schema: {
        body: BODY_SCHEMA,
        response: {
          200: {
            type: 'object',
            properties: {
              identities: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: { user_id: { type: 'string' }, workspace_id: { type: 'string' } },
                  required: ['user_id', 'workspace_id'],
                },
              },
            },
            required: ['identities'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Body: ResolveBody }>) => {
      requireScope(request, SCOPE_IDENTITY_RESOLVE);

      // No tenant is set: finding the tenant is the point. The SQL function is
      // the only thing that can read across workspaces, and only for one exact
      // subject.
      const identities = await withoutTenant(deps.pool, (db) =>
        resolveIdentitySubject(db, request.body.subject),
      );

      return {
        identities: identities.map((i) => ({ user_id: i.userId, workspace_id: i.workspaceId })),
      };
    },
  );

  app.post(
    '/v1/auth/provision',
    {
      schema: {
        body: PROVISION_SCHEMA,
        response: {
          201: {
            type: 'object',
            properties: { user_id: { type: 'string' }, workspace_id: { type: 'string' } },
            required: ['user_id', 'workspace_id'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Body: ProvisionBody }>, reply) => {
      // Same scope as the lookup, and the same trust boundary: the caller has
      // already verified an id token. Note what the body cannot contain — no
      // workspace id, no user id, no workspace *type*. A caller cannot ask to
      // join an existing tenant here, because there is no field in which to
      // name one.
      requireScope(request, SCOPE_IDENTITY_RESOLVE);

      try {
        const created = await provisionPersonalWorkspace(deps.pool, {
          subject: request.body.subject,
          workspaceName: request.body.workspace_name,
        });

        return reply.code(201).send({
          user_id: created.userId,
          workspace_id: created.workspaceId,
        });
      } catch (error) {
        if (error instanceof SubjectAlreadyKnownError) {
          // 409, not 403: nothing was refused on authorization grounds. Sign-in
          // should have found them, and the dashboard sends them back through
          // it rather than creating a second identity for one human.
          throw new HttpError(409, 'IDENTITY_UNRESOLVED', error.message);
        }
        throw error;
      }
    },
  );
}
