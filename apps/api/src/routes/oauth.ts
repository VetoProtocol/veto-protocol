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
import { GATEWAY_AUDIENCE, GATEWAY_SCOPE, mintCapability } from '@veto/tokens';
import {
  checkVerifier,
  findClient,
  issueCode,
  issueRefresh,
  redeemCode,
  registerClient,
  rotateRefresh,
  validateRegistration,
  workspaceOf,
  type CodeGrant,
  type RefreshGrant,
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
  /** Signs the access tokens the gateway accepts. */
  readonly capabilitySecret: string;
}

/**
 * How long an access token lives.
 *
 * Ten minutes, inside `MAX_TTL_MS`. Short because the gateway re-reads the
 * agent's row on every request anyway — the token's lifetime is the window in
 * which a *leaked* one works, not the window in which a revocation takes
 * effect.
 */
const ACCESS_TTL_MS = 10 * 60 * 1000;

const TOKEN_RESPONSE = {
  type: 'object',
  required: ['access_token', 'token_type', 'expires_in', 'refresh_token'],
  properties: {
    access_token: { type: 'string' },
    token_type: { type: 'string' },
    expires_in: { type: 'integer' },
    refresh_token: { type: 'string' },
  },
} as const;

const TOKEN_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['grant_type', 'client_id'],
  properties: {
    grant_type: { type: 'string', enum: ['authorization_code', 'refresh_token'] },
    client_id: { type: 'string', pattern: '^oac_[A-Za-z0-9_-]{1,64}$' },
    code: { type: 'string', minLength: 1, maxLength: 200 },
    code_verifier: { type: 'string', minLength: 1, maxLength: 256 },
    redirect_uri: { type: 'string', minLength: 1, maxLength: 2048 },
    refresh_token: { type: 'string', minLength: 1, maxLength: 200 },
    resource: { type: 'string', minLength: 1, maxLength: 2048 },
  },
} as const;

interface TokenBody {
  grant_type: 'authorization_code' | 'refresh_token';
  client_id: string;
  code?: string;
  code_verifier?: string;
  redirect_uri?: string;
  refresh_token?: string;
  resource?: string;
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

  /**
   * The token endpoint.
   *
   * Every check lives here rather than in the dashboard that fronts it: this is
   * the service holding the code, the refresh row and the signing key, and
   * splitting the checks across a network hop would mean each half trusting the
   * other to have done its share.
   *
   * The access token it mints is the ordinary capability token the gateway
   * already accepts. A token obtained through OAuth is indistinguishable from
   * one the bridge made, which is the point — the gateway did not have to
   * change for any of this.
   */
  app.post(
    '/v1/oauth/token',
    {
      schema: {
        body: TOKEN_BODY,
        response: { 200: TOKEN_RESPONSE, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: TokenBody }>) => {
      requireScope(request, SCOPE_OAUTH_SERVER);
      const body = request.body;

      // Refuse rather than mint with a key too weak to sign with. A token
      // endpoint that issued something the gateway then rejected would look
      // like a broken client and be a broken deployment.
      if (deps.capabilitySecret.length < 32) {
        throw new HttpError(503, 'POLICY_UNAVAILABLE', 'This server cannot issue tokens');
      }

      const client = await findClient(deps.pool, body.client_id);
      if (!client) throw new HttpError(401, 'CLIENT_UNKNOWN', 'No such client');

      const issue = (grant: RefreshGrant, refreshToken: string) => ({
        access_token: mintCapability(deps.capabilitySecret, {
          aud: GATEWAY_AUDIENCE,
          workspaceId: grant.workspaceId,
          humanId: grant.userId,
          agentId: grant.agentId,
          action: GATEWAY_SCOPE,
          resource: 'mcp',
          ttlMs: ACCESS_TTL_MS,
        }),
        token_type: 'Bearer',
        expires_in: Math.floor(ACCESS_TTL_MS / 1000),
        refresh_token: refreshToken,
      });

      if (body.grant_type === 'authorization_code') {
        const code = body.code ?? '';
        const verifier = body.code_verifier ?? '';
        if (code === '' || verifier === '') {
          throw new HttpError(400, 'ARGUMENT_SCHEMA_INVALID', 'code and code_verifier are required');
        }

        // Spent here, once. Everything after this point fails without the code
        // being reusable — a failed exchange must not leave a live code behind
        // for a second attempt to guess its way through.
        const grant = await redeemCode(deps.redis, code);
        if (!grant) throw new HttpError(400, 'APPROVAL_EXPIRED', 'That code is not redeemable');

        // The code was issued to one client. Another presenting it is either a
        // mix-up or a theft, and neither gets a token.
        if (grant.clientId !== client.id) {
          throw new HttpError(400, 'IDENTITY_UNRESOLVED', 'That code was issued to another client');
        }

        // RFC 6749 §4.1.3: the redirect URI at exchange must equal the one the
        // code was issued for. Compared whole, like everywhere else.
        if ((body.redirect_uri ?? '') !== grant.redirectUri) {
          throw new HttpError(400, 'ARGUMENT_SCHEMA_INVALID', 'redirect_uri does not match');
        }

        // A resource narrower or different from the approved one is not a
        // token this server issues. Omitted means "as approved".
        const asked = (body.resource ?? grant.resource).replace(/\/$/, '');
        if (asked !== grant.resource) {
          throw new HttpError(400, 'RESOURCE_OUT_OF_SCOPE', 'resource does not match the approval');
        }

        const pkce = checkVerifier(verifier, grant.codeChallenge);
        if (pkce !== null) {
          // The intercepted-code case: whoever has the code does not have the
          // verifier, and this is where that stops being enough.
          throw new HttpError(400, 'ARGUMENT_SCHEMA_INVALID', 'code_verifier does not match');
        }

        const refresh = await withWorkspace(deps.pool, grant.workspaceId, (db) =>
          issueRefresh(db, {
            workspaceId: grant.workspaceId,
            userId: grant.userId,
            agentId: grant.agentId,
            clientId: grant.clientId,
          }),
        );

        return issue(refresh, refresh.token);
      }

      const presented = body.refresh_token ?? '';
      if (presented === '') {
        throw new HttpError(400, 'ARGUMENT_SCHEMA_INVALID', 'refresh_token is required');
      }

      // The workspace comes from the token's own prefix, because the row cannot
      // be found without it: `oauth_refresh_tokens` has FORCEd row-level
      // security and a lookup outside a workspace returns nothing. The prefix
      // is a routing hint and grants nothing — the hash covers it, so a token
      // wearing another tenant's prefix hashes to something that exists nowhere.
      const workspaceId = workspaceOf(presented);
      if (workspaceId === null) {
        throw new HttpError(400, 'APPROVAL_EXPIRED', 'That refresh token is not usable');
      }

      // Rotation locks the row, so two concurrent refreshes cannot both spend
      // the same token and fork the chain.
      const rotated = await withWorkspace(deps.pool, workspaceId, (db) =>
        rotateRefresh(db, presented, client.id),
      );

      if (!rotated.ok) {
        throw new HttpError(
          400,
          rotated.reason === 'REFRESH_REUSED' ? 'APPROVAL_REPLAYED' : 'APPROVAL_EXPIRED',
          rotated.reason === 'REFRESH_REUSED'
            ? 'That refresh token was already used; the session has been revoked'
            : 'That refresh token is not usable',
        );
      }

      return issue(rotated.issued, rotated.issued.token);
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
