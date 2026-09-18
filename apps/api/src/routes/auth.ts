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
 * error: an unknown subject is somebody who has not been invited, and the
 * dashboard says exactly that.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withoutTenant } from '@veto/db';
import { resolveIdentitySubject } from '@veto/identity';
import { ERROR_SCHEMA } from '../errors.ts';
import { requireScope, SCOPE_IDENTITY_RESOLVE } from '../scope.ts';

const BODY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['subject'],
  properties: { subject: { type: 'string', minLength: 1, maxLength: 255 } },
} as const;

interface ResolveBody {
  subject: string;
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
}
