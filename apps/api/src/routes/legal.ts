/**
 * /v1/legal/acceptance — who has agreed to which published document.
 *
 * Two routes, and the interesting decision is in what the caller is *not*
 * allowed to say.
 *
 * ## The server owns the version numbers
 *
 * `CURRENT` below is the authority on which text is in force. A caller posts
 * *that it agrees*, not *what it is agreeing to* — if the version came from the
 * request body, a client could satisfy the check by claiming to have accepted a
 * version nobody ever published, and the record would say something untrue.
 *
 * So the POST body carries no version at all. There is nothing to forge.
 *
 * ## The user comes from the principal
 *
 * Never from the body, for the same reason presence does not take a user id:
 * agreeing on somebody else's behalf is not agreement.
 */

import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { CURRENT_LEGAL_VERSIONS, LEGAL_DOCUMENTS, newId } from '@veto/core';
import { withWorkspace } from '@veto/db';
import { ERROR_SCHEMA } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

/** Re-exported so callers of this route keep importing it from here. */
export const CURRENT = CURRENT_LEGAL_VERSIONS;

const DOCUMENTS = LEGAL_DOCUMENTS;

const ACCEPTANCE_RESPONSE = {
  type: 'object',
  additionalProperties: false,
  properties: {
    /** The versions in force right now. */
    current: {
      type: 'object',
      additionalProperties: false,
      properties: { terms: { type: 'string' }, privacy: { type: 'string' } },
      required: ['terms', 'privacy'],
    },
    /** Documents whose current version this user has not accepted. Empty means settled. */
    outstanding: { type: 'array', items: { type: 'string' } },
  },
  required: ['current', 'outstanding'],
} as const;

export function registerLegalRoutes(app: FastifyInstance, deps: { pool: Pool }): void {
  /** What this user still owes. Cheap, and read on every dashboard render. */
  app.get(
    '/v1/legal/acceptance',
    { schema: { response: { 200: ACCEPTANCE_RESPONSE, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA } } },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      const { rows } = await withWorkspace(deps.pool, workspaceId, (db) =>
        db.query<{ document: string }>(
          `select document from legal_acceptances
            where workspace_id = $1 and user_id = $2
              and (document, version) in (($3, $4), ($5, $6))`,
          [
            workspaceId,
            userId,
            'terms',
            CURRENT.terms,
            'privacy',
            CURRENT.privacy,
          ],
        ),
      );

      const accepted = new Set(rows.map((r) => r.document));
      return { current: CURRENT, outstanding: DOCUMENTS.filter((d) => !accepted.has(d)) };
    },
  );

  /**
   * Agree to everything currently in force.
   *
   * All or nothing: there is no partial state worth modelling, because the
   * product is unusable without both and offering "accept the terms but not the
   * privacy policy" would imply a mode that does not exist.
   *
   * `on conflict do nothing` — a second submission of the same version is the
   * same agreement, not a new one.
   */
  app.post(
    '/v1/legal/acceptance',
    {
      schema: {
        body: { type: 'object', additionalProperties: false, properties: {} },
        response: { 200: ACCEPTANCE_RESPONSE, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      await withWorkspace(deps.pool, workspaceId, async (db) => {
        for (const document of DOCUMENTS) {
          await db.query(
            `insert into legal_acceptances (id, workspace_id, user_id, document, version)
             values ($1,$2,$3,$4,$5)
             on conflict (workspace_id, user_id, document, version) do nothing`,
            [newId('lac_'), workspaceId, userId, document, CURRENT[document]],
          );
        }
      });

      return { current: CURRENT, outstanding: [] };
    },
  );
}
