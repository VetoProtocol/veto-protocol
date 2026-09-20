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
import type Redis from 'ioredis';
import { findAgent } from '@veto/identity';
import { withWorkspace } from '@veto/db';
import {
  findClient,
  issueCode,
  redeemCode,
  registerClient,
  validateRegistration,
  type CodeGrant,
} from '@veto/oauth';
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
  readonly redis: Redis;
}

const GRANT_BODY = {
  type: 'object',
  additionalProperties: false,
  required: [
    'workspace_id',
    'user_id',
    'agent_id',
    'client_id',
    'redirect_uri',
    'code_challenge',
    'resource',
  ],
  properties: {
    workspace_id: { type: 'string', pattern: '^ws_[A-Za-z0-9_-]{1,64}$' },
    user_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{1,64}$' },
    agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{1,64}$' },
    client_id: { type: 'string', pattern: '^oac_[A-Za-z0-9_-]{1,64}$' },
    redirect_uri: { type: 'string', minLength: 1, maxLength: 2048 },
    code_challenge: { type: 'string', pattern: '^[A-Za-z0-9\\-_]{43}$' },
    resource: { type: 'string', minLength: 1, maxLength: 2048 },
  },
} as const;

interface GrantBody {
  workspace_id: string;
  user_id: string;
  agent_id: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  resource: string;
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

  /**
   * Mint an authorization code for a grant a human has just approved.
   *
   * The agent is re-checked here rather than trusted from the caller. The
   * dashboard has already shown a consent screen naming it, but between that
   * screen and this call somebody may have revoked it, and an authorization
   * server that mints a code for a revoked agent has undone a revocation
   * (FR-08).
   */
  app.post(
    '/v1/oauth/codes',
    {
      schema: {
        body: GRANT_BODY,
        response: {
          201: {
            type: 'object',
            required: ['code'],
            properties: { code: { type: 'string' } },
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Body: GrantBody }>, reply) => {
      requireScope(request, SCOPE_OAUTH_SERVER);
      const body = request.body;

      const client = await findClient(deps.pool, body.client_id);
      if (!client) throw new HttpError(404, 'CLIENT_UNKNOWN', 'No such client');

      const agent = await withWorkspace(deps.pool, body.workspace_id, (db) =>
        findAgent(db, body.workspace_id, body.agent_id),
      );
      if (!agent) throw new HttpError(404, 'AGENT_UNKNOWN', 'No such agent in this workspace');
      if (agent.status !== 'active') {
        throw new HttpError(409, 'AGENT_REVOKED', 'That agent is not active');
      }
      // §7.1: the delegator is the human this token will act for, and the
      // agent must already belong to them. A consent screen cannot grant an
      // agent to somebody who does not own it.
      if (agent.owner_user_id !== body.user_id) {
        throw new HttpError(403, 'IDENTITY_UNRESOLVED', 'That agent belongs to another user');
      }

      const grant: CodeGrant = {
        workspaceId: body.workspace_id,
        userId: body.user_id,
        agentId: body.agent_id,
        clientId: body.client_id,
        redirectUri: body.redirect_uri,
        codeChallenge: body.code_challenge,
        resource: body.resource,
      };

      return reply.code(201).send({ code: await issueCode(deps.redis, grant) });
    },
  );

  /**
   * Spend a code, once.
   *
   * Returns the grant exactly as it was approved. Nothing here is re-derived
   * from what the client sent, because the client is precisely who must not get
   * to change it between approval and exchange.
   */
  app.post(
    '/v1/oauth/codes/redeem',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['code'],
          properties: { code: { type: 'string', minLength: 1, maxLength: 200 } },
        },
        response: { 200: GRANT_BODY, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: { code: string } }>) => {
      requireScope(request, SCOPE_OAUTH_SERVER);

      const grant = await redeemCode(deps.redis, request.body.code);
      // Unknown, expired and already spent are one answer. Telling them apart
      // would say whether a code was ever real.
      if (!grant) throw new HttpError(400, 'APPROVAL_EXPIRED', 'That code is not redeemable');

      return {
        workspace_id: grant.workspaceId,
        user_id: grant.userId,
        agent_id: grant.agentId,
        client_id: grant.clientId,
        redirect_uri: grant.redirectUri,
        code_challenge: grant.codeChallenge,
        resource: grant.resource,
      };
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
