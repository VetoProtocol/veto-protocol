/**
 * /v1/connections — the Google Workspace connection (spec §5, §9).
 *
 * The consent URL is built **here** and the authorization code is exchanged
 * **here**, not in the dashboard. The dashboard owns the browser round trip
 * because it owns the session, but it posts the code across and never sees what
 * comes back: the refresh token exists in exactly one process and one column.
 * The code itself is single-use and worthless without the client secret, which
 * only this service holds.
 *
 * Both halves living in one process is what makes `redirect_uri` correct by
 * construction. Google compares it byte for byte at consent time and again at
 * exchange time, so a second copy in a second service is a mismatch waiting to
 * happen — and the dashboard has no copy to get wrong.
 *
 * Nothing on these routes returns a credential. `Connection` has no field that
 * could carry one.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import {
  buildConsentUrl,
  buildInstallUrl,
  readInstallation,
  createConnection,
  exchangeAuthorizationCode,
  GOOGLE_SERVICES,
  GOOGLE_SERVICE_NAMES,
  listConnections,
  findConnection,
  revealRefreshTokenForBroker,
  revokeConnection,
  revokeUpstream,
  type GitHubAppConfig,
  type GoogleOAuthConfig,
  type UpstreamTokenExchange,
} from '@veto/connections';
import type { KeyWrapper } from '@veto/vault';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

export interface ConnectionRoutesDeps {
  readonly pool: Pool;
  readonly wrapper: KeyWrapper;
  readonly google: GoogleOAuthConfig | null;
  readonly exchange: UpstreamTokenExchange | null;
  /** Null until the GitHub App is configured; the routes then 503 rather than half-work. */
  readonly github: GitHubAppConfig | null;
  /**
   * Revocation has to reach the provider the connection actually belongs to.
   * Handing an installation id to Google's revoke endpoint fails quietly and
   * leaves the installation live, which is the worst shape a revocation can
   * take: the operator believes access is gone and it is not.
   */
  readonly githubExchange: UpstreamTokenExchange | null;
}

const CONNECTION_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    provider: { type: 'string' },
    scopes: { type: 'array', items: { type: 'string' } },
    status: { type: 'string' },
    expires_at: { type: 'string', nullable: true },
    created_at: { type: 'string' },
  },
  required: ['id', 'provider', 'scopes', 'status'],
} as const;

const CONNECT_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['code', 'code_verifier'],
  properties: {
    code: { type: 'string', minLength: 1, maxLength: 2048 },
    // PKCE verifiers are 43–128 characters of unreserved alphabet (RFC 7636).
    code_verifier: { type: 'string', minLength: 43, maxLength: 128, pattern: '^[A-Za-z0-9._~-]+$' },
  },
} as const;

/**
 * The consent URL is built here, not in the browser.
 *
 * `redirect_uri` and the scope list have to be identical at consent time and at
 * exchange time, or Google refuses the code — and the exchange happens in this
 * process. Having one process own both halves means there is no second copy of
 * the redirect URI to drift out of step with the one registered with Google.
 *
 * The caller supplies `state` and `code_challenge` because it is the caller who
 * must recognise its own callback later; both are public values, and both are
 * shape-checked before they are interpolated into a URL that a browser follows.
 */
const INSTALL_QUERY = {
  type: 'object',
  additionalProperties: false,
  required: ['state'],
  properties: {
    state: { type: 'string', minLength: 16, maxLength: 128, pattern: '^[A-Za-z0-9._~-]+$' },
  },
} as const;

const INSTALL_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['installation_id'],
  properties: {
    // Digits only, so nothing can be smuggled into the path this builds.
    installation_id: { type: 'string', minLength: 1, maxLength: 20, pattern: '^[0-9]+$' },
  },
} as const;

const AUTHORIZE_QUERY = {
  type: 'object',
  additionalProperties: false,
  required: ['state', 'code_challenge'],
  properties: {
    state: { type: 'string', minLength: 16, maxLength: 128, pattern: '^[A-Za-z0-9._~-]+$' },
    code_challenge: {
      type: 'string',
      minLength: 43,
      maxLength: 128,
      pattern: '^[A-Za-z0-9._~-]+$',
    },
    // One service per consent screen (§9.1). A closed set, so a caller cannot
    // name a scope — only a feature this product actually enforces rules on.
    service: { type: 'string', enum: [...GOOGLE_SERVICE_NAMES] },
  },
} as const;

interface AuthorizeQuery {
  state: string;
  code_challenge: string;
  service?: string;
}

interface ConnectBody {
  code: string;
  code_verifier: string;
}
interface IdParams {
  connectionId: string;
}

/** The fields a connection is allowed to expose. No token field exists to omit. */
type Serializable = {
  id: string;
  provider: string;
  scopes: readonly string[];
  status: string;
  expiresAt: Date | null;
  createdAt: Date;
};

const serialize = (c: Serializable) => ({
  id: c.id,
  provider: c.provider,
  scopes: [...c.scopes],
  status: c.status,
  expires_at: c.expiresAt === null ? null : c.expiresAt.toISOString(),
  created_at: c.createdAt.toISOString(),
});

export function registerConnectionRoutes(app: FastifyInstance, deps: ConnectionRoutesDeps): void {
  app.get(
    '/v1/connections',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: { connections: { type: 'array', items: CONNECTION_SCHEMA } },
            required: ['connections'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;
      const rows = await withWorkspace(deps.pool, workspaceId, (db) =>
        listConnections(db, workspaceId),
      );
      return { connections: rows.map(serialize) };
    },
  );

  app.get(
    '/v1/connections/google/authorize-url',
    {
      schema: {
        querystring: AUTHORIZE_QUERY,
        response: {
          200: {
            type: 'object',
            properties: {
              url: { type: 'string' },
              scopes: { type: 'array', items: { type: 'string' } },
            },
            required: ['url', 'scopes'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Querystring: AuthorizeQuery }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);

      if (!deps.google) {
        throw new HttpError(503, 'CONNECTION_EXPIRED', 'Google is not configured on this server');
      }

      // Exactly one service's scopes (§9.1). Drive, Gmail and Calendar are all
      // present in GOOGLE_SERVICES now that each has tools behind it; an
      // earlier note here said Calendar was deliberately absent, which stopped
      // being true when the Calendar tools shipped.
      const service = request.query.service ?? 'drive';
      const scopes = [...(GOOGLE_SERVICES[service as keyof typeof GOOGLE_SERVICES] ?? [])];

      return {
        url: buildConsentUrl(deps.google, {
          state: request.query.state,
          codeChallenge: request.query.code_challenge,
          scopes,
        }),
        scopes,
      };
    },
  );

  app.post(
    '/v1/connections/google',
    {
      schema: {
        body: CONNECT_BODY,
        response: { 201: CONNECTION_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: ConnectBody }>, reply) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      if (!deps.google) {
        throw new HttpError(503, 'CONNECTION_EXPIRED', 'Google is not configured on this server');
      }

      let exchanged;
      try {
        exchanged = await exchangeAuthorizationCode(
          deps.google,
          request.body.code,
          request.body.code_verifier,
        );
      } catch {
        // Google's error text is not propagated: it echoes the request, which
        // carried the code, and it is written for a developer's console.
        throw new HttpError(400, 'ARGUMENT_SCHEMA_INVALID', 'That authorization could not be completed');
      }

      const connection = await withWorkspace(deps.pool, workspaceId, (db) =>
        createConnection(db, deps.wrapper, {
          workspaceId,
          userId,
          provider: 'google',
          // What Google actually granted, not what was asked for. A partial
          // grant must not be recorded as a full one (§9.1 granular permissions).
          scopes: exchanged.scopes,
          refreshToken: exchanged.refreshToken,
          correlationId: String(request.id),
        }),
      );

      return reply.code(201).send(serialize(connection));
    },
  );

  app.get(
    '/v1/connections/github/install-url',
    {
      schema: {
        querystring: INSTALL_QUERY,
        response: {
          200: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Querystring: { state: string } }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);

      if (!deps.github) {
        throw new HttpError(503, 'CONNECTION_EXPIRED', 'GitHub is not configured on this server');
      }

      // No PKCE and no scope list. Unlike an OAuth consent screen there is
      // nothing here to narrow: what an installation may reach is chosen on
      // GitHub's own screen by the person installing it, and cannot be widened
      // from this side. `state` still round-trips so the callback can be tied
      // to the request that started it (§12.1 OAuth CSRF).
      //
      // Only the slug crosses this line, never the private key — the same
      // narrowing `ConsentConfig` does for the Google client secret.
      return {
        url: buildInstallUrl({ appSlug: deps.github.appSlug }, { state: request.query.state }),
      };
    },
  );

  app.post(
    '/v1/connections/github',
    {
      schema: {
        body: INSTALL_BODY,
        response: { 201: CONNECTION_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: { installation_id: string } }>, reply) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      if (!deps.github) {
        throw new HttpError(503, 'CONNECTION_EXPIRED', 'GitHub is not configured on this server');
      }

      // The callback handed us a number. It is not trusted: GitHub is asked
      // what that installation is, and the answer is what gets stored. A
      // crafted redirect that could assert its own installation id would be
      // choosing whose repositories this workspace reaches.
      let installation;
      try {
        installation = await readInstallation(deps.github, request.body.installation_id);
      } catch {
        // GitHub's error text is not propagated: it is written for a console
        // and can echo the request.
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          'That installation could not be confirmed',
        );
      }

      const connection = await withWorkspace(deps.pool, workspaceId, (db) =>
        createConnection(db, deps.wrapper, {
          workspaceId,
          userId,
          provider: 'github',
          // What the installation actually holds, not what we hoped for. An
          // installer who granted only issues must not be recorded as having
          // granted code.
          scopes: installation.scopes,
          // The installation id sits where a refresh token sits. It is not a
          // bearer credential on its own — the App private key is the secret —
          // but it is tenant data and is encrypted like everything else here.
          refreshToken: installation.installationId,
          correlationId: String(request.id),
        }),
      );

      return reply.code(201).send(serialize(connection));
    },
  );

  app.delete(
    '/v1/connections/:connectionId',
    {
      schema: {
        params: {
          type: 'object',
          additionalProperties: false,
          required: ['connectionId'],
          properties: { connectionId: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{1,64}$' } },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              connection_id: { type: 'string' },
              revoked: { type: 'boolean' },
              already_revoked: { type: 'boolean' },
              provider_revoked: { type: 'boolean' },
            },
            required: ['connection_id', 'revoked', 'already_revoked', 'provider_revoked'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Params: IdParams }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const { connectionId } = request.params;

      // Which provider this connection belongs to, read before the row is
      // destroyed. Revoking at the wrong provider is a silent no-op.
      const existing = await withWorkspace(deps.pool, workspaceId, (db) =>
        findConnection(db, workspaceId, connectionId).catch(() => null),
      );

      // Read the credential before destroying it, so there is something left to
      // revoke at the provider. Held only for the length of this request.
      const token = await withWorkspace(deps.pool, workspaceId, (db) =>
        revealRefreshTokenForBroker(db, deps.wrapper, workspaceId, connectionId).catch(() => null),
      );

      const result = await withWorkspace(deps.pool, workspaceId, (db) =>
        revokeConnection(db, workspaceId, connectionId, userId),
      );

      if (!result.revoked && !result.alreadyRevoked) {
        throw new HttpError(404, 'CONNECTION_EXPIRED', 'No such connection in this workspace');
      }

      // Provider revocation runs after the local delete has committed, so an
      // outage at Google leaves the credential already unusable here (§9.1).
      const exchange =
        existing?.provider === 'github' ? deps.githubExchange : deps.exchange;
      const providerRevoked =
        token !== null && exchange !== null && exchange !== undefined
          ? await revokeUpstream(exchange, token)
          : false;

      return {
        connection_id: connectionId,
        revoked: result.revoked,
        already_revoked: result.alreadyRevoked,
        provider_revoked: providerRevoked,
      };
    },
  );
}
