/**
 * What the dashboard needs to know about the workspace it is rendering.
 *
 * Only the tier, for now. It is its own route rather than a field bolted onto
 * the legal-acceptance response because the two answer different questions and
 * one will outlive the other.
 *
 * Read on every render rather than sealed into the session cookie. A plan in a
 * signed cookie is a plan the server cannot revoke until the cookie expires,
 * and an upgrade should be visible on the next page rather than the next
 * sign-in.
 *
 * There is no billing here and none is implied. `plan` is a flag somebody sets;
 * what sets it is a question for whenever this is actually sold.
 */

import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import { ERROR_SCHEMA } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';
import { workspacePlan } from '../workspace.ts';

export interface WorkspaceRoutesDeps {
  readonly pool: Pool;
}

export function registerWorkspaceRoutes(app: FastifyInstance, deps: WorkspaceRoutesDeps): void {
  app.get(
    '/v1/workspace',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              workspace_id: { type: 'string' },
              plan: { type: 'string', enum: ['free', 'pro'] },
            },
            required: ['workspace_id', 'plan'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      // The tenant comes from the credential, never from the request. There is
      // no parameter here somebody could put another workspace's id in.
      const plan = await withWorkspace(deps.pool, workspaceId, (db) =>
        workspacePlan(db, workspaceId),
      );

      return { workspace_id: workspaceId, plan };
    },
  );
}
