/**
 * Storage for the §8 authorization server.
 *
 * ## Why these live here and the flow lives in the dashboard
 *
 * The dashboard is the authorization server: `/authorize` needs the human's
 * browser session, and that session is the whole point of the screen. But the
 * dashboard has no database — it talks to this service for every object it
 * shows, and that boundary is worth keeping for a table that holds a standing
 * credential.
 *
 * So the browser-facing half is there and the storage half is here. Both are
 * first-party, both hold the capability signing key, and the split follows the
 * one the product already has rather than inventing a second one.
 *
 * Every route here asserts `SCOPE_OAUTH_SERVER`, so a credential minted to
 * register a client cannot reach the agent routes.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { findClient, registerClient, validateRegistration } from '@veto/oauth';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_OAUTH_SERVER } from '../scope.ts';

const CLIENT_SCHEMA = {
  type: 'object',
  properties: {
    client_id: { type: 'string' },
    client_name: { type: 'string' },
    redirect_uris: { type: 'array', items: { type: 'string' } },
  },
  required: ['client_id', 'client_name', 'redirect_uris'],
} as const;

const REGISTER_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['client_name', 'redirect_uris'],
  properties: {
    client_name: { type: 'string', minLength: 1, maxLength: 200 },
    redirect_uris: {
      type: 'array',
      minItems: 1,
      maxItems: 10,
      items: { type: 'string', minLength: 1, maxLength: 2048 },
    },
  },
} as const;

interface RegisterBody {
  client_name: string;
  redirect_uris: string[];
}

/**
 * Client rows are read and written on the pool, not inside `withWorkspace`.
 *
 * That helper refuses any id that is not a real workspace, which is correct and
 * not something to weaken for this: `oauth_clients` has no `workspace_id` and no
 * row-level security, so there is no tenant to scope to and nothing for the
 * scope to enforce (migration 0015 argues why that is safe).
 *
 * Each operation here is a single statement, so it is atomic without a
 * transaction. Anything that grows to two statements needs a transaction and a
 * fresh think about what it is isolating from.
 */

export interface OAuthRoutesDeps {
  readonly pool: Pool;
}

export function registerOAuthRoutes(app: FastifyInstance, deps: OAuthRoutesDeps): void {
  app.post(
    '/v1/oauth/clients',
    {
      schema: {
        body: REGISTER_BODY,
        response: { 201: CLIENT_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: RegisterBody }>, reply) => {
      requireScope(request, SCOPE_OAUTH_SERVER);
      const body = request.body;

      // Checked here as well as in the schema: the schema knows a redirect URI
      // is a string of a sane length, and only this knows that cleartext to a
      // remote host is a code somebody else also receives.
      const invalid = validateRegistration(body.client_name, body.redirect_uris);
      if (invalid !== null) {
        throw new HttpError(
          400,
          invalid,
          invalid === 'REDIRECT_URI_INVALID'
            ? 'A redirect URI must be https, a loopback address, or a private-use scheme'
            : 'Client name and at least one redirect URI are required',
        );
      }

      const client = await registerClient(deps.pool, {
        clientName: body.client_name,
        redirectUris: body.redirect_uris,
      });

      return reply.code(201).send({
        client_id: client.id,
        client_name: client.clientName,
        redirect_uris: client.redirectUris,
      });
    },
  );

  app.get(
    '/v1/oauth/clients/:clientId',
    {
      schema: {
        response: { 200: CLIENT_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Params: { clientId: string } }>) => {
      requireScope(request, SCOPE_OAUTH_SERVER);

      const client = await findClient(deps.pool, request.params.clientId);
      if (!client) throw new HttpError(404, 'CLIENT_UNKNOWN', 'No such client');

      return {
        client_id: client.id,
        client_name: client.clientName,
        redirect_uris: client.redirectUris,
      };
    },
  );
}
