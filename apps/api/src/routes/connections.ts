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
import type Redis from 'ioredis';
import { randomBytes } from 'node:crypto';
import { withWorkspace } from '@veto/db';
import {
  GOOGLE_SERVICES,
  GOOGLE_SERVICE_NAMES,
  MICROSOFT_SERVICES,
  MICROSOFT_SERVICE_NAMES,
  SLACK_SERVICES,
  SLACK_SERVICE_NAMES,
  buildConsentUrl,
  buildInstallUrl,
  buildMicrosoftConsentUrl,
  buildSlackInstallUrl,
  createConnection,
  exchangeAuthorizationCode,
  exchangeMicrosoftCode,
  exchangeSlackCode,
  findConnection,
  listConnections,
  readInstallation,
  revealRefreshTokenForBroker,
  revokeConnection,
  revokeUpstream,
  type GitHubAppConfig,
  type GitHubUserAuthConfig,
  type GoogleOAuthConfig,
  type MicrosoftOAuthConfig,
  type SlackAppConfig,
  type SlackService,
  type UpstreamTokenExchange,
  userControlsInstallation,
} from '@veto/connections';
import type { KeyWrapper } from '@veto/vault';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

export interface ConnectionRoutesDeps {
  readonly pool: Pool;
  /**
   * Holds the single-use install state, which ties the callback to the browser
   * round trip that began it — CSRF protection, and only that.
   *
   * An earlier comment here said the GitHub flow "has no authorization code to
   * prove with", and treated this state as the proof instead. It never was: it
   * says a flow started, not which installation it ended at. The proof is the
   * `code` on the callback.
   */
  readonly redis: Redis;
  readonly wrapper: KeyWrapper;
  readonly google: GoogleOAuthConfig | null;
  readonly exchange: UpstreamTokenExchange | null;
  /** Null until the GitHub App is configured; the routes then 503 rather than half-work. */
  readonly github: GitHubAppConfig | null;
  /**
   * The App's user-authorization credentials, held by the control plane alone.
   *
   * Absent means the install flow cannot prove who owns an installation, and
   * the flow refuses to start rather than falling back to taking the caller's
   * word for it. Existing connections are unaffected: minting tokens for an
   * installation already on file needs only the private key, which lives on
   * `github` and is what the gateway holds.
   */
  readonly githubUserAuth: GitHubUserAuthConfig | null;
  /** Slack app credentials. Absent means every Slack route refuses. */
  readonly slack: SlackAppConfig | null;
  /**
   * Microsoft 365 app registration. Absent means every Microsoft route
   * refuses rather than half-working.
   *
   * Revocation for this provider is **local only** — Microsoft exposes no way
   * to invalidate one refresh token, and the only broader mechanism would sign
   * the person out of every application they use. There is deliberately no
   * `microsoftExchange` beside this for the revoke path to reach for, because
   * there is nothing honest for it to call. See `docs/microsoft-setup.md`.
   */
  readonly microsoft: MicrosoftOAuthConfig | null;
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
/**
 * Nothing. The caller no longer chooses the state.
 *
 * It used to supply one, which made `state` a value an attacker could pick and
 * then redeem at the moment of their choosing. It is CSRF protection, and CSRF
 * protection the client mints is a token the client can replay against itself.
 * The server issues it and hands it back.
 */
const INSTALL_QUERY = {
  type: 'object',
  additionalProperties: false,
  properties: {},
} as const;

const INSTALL_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['installation_id', 'state', 'code'],
  properties: {
    // Digits only, so nothing can be smuggled into the path this builds.
    installation_id: { type: 'string', minLength: 1, maxLength: 20, pattern: '^[0-9]+$' },
    // The state this server minted for this workspace. It proves the flow
    // began here; it proves nothing about *which* installation.
    state: { type: 'string', minLength: 16, maxLength: 128, pattern: '^[A-Za-z0-9._~-]+$' },
    // The thing that actually proves ownership. GitHub issues it to the person
    // who just completed the install, it exchanges for a user token, and that
    // token's `/user/installations` is the only answer to "is this yours".
    // Required, not optional: an optional proof is not a proof.
    code: { type: 'string', minLength: 8, maxLength: 512, pattern: '^[A-Za-z0-9._~-]+$' },
  },
} as const;

/**
 * Where a pending install state lives.
 *
 * Scoped by workspace, so one tenant cannot consume another's state even if it
 * learns the value. The stored value is the user who began the flow.
 *
 * Fifteen minutes, because installing means choosing repositories on GitHub's
 * screen and that is a real decision, not a click.
 */
const installKey = (workspaceId: string, state: string): string =>
  `veto:${workspaceId}:ghinst:${state}`;

const INSTALL_STATE_TTL_SECONDS = 900;

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

/**
 * The same shape as Google's, with its own closed service set.
 *
 * Its own constant rather than a shared one with a wider enum: a single schema
 * covering both would accept `drive` on the Microsoft route and `mail` on the
 * Google one, and the fallback service would then quietly decide what the
 * person actually consented to. That is exactly how "connect Calendar" once
 * opened a consent screen for Drive.
 */
const MICROSOFT_AUTHORIZE_QUERY = {
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
    service: { type: 'string', enum: [...MICROSOFT_SERVICE_NAMES] },
  },
} as const;

type MicrosoftAuthorizeQuery = AuthorizeQuery;

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


  /**
   * The Microsoft consent URL, built here for the reason Google's is.
   *
   * `redirect_uri` has to be identical at consent time and at exchange time,
   * and the exchange happens in this process — so there is exactly one copy of
   * it and the dashboard has none to get wrong.
   *
   * `state` and `code_challenge` come from the caller, as they do for Google
   * and unlike Slack's server-minted state. That is not the F-01 shape: the
   * caller here is the dashboard, which seals both into a signed five-minute
   * cookie and compares them on the way back, so the value is checked against
   * something the client cannot forge. Slack needed a server-minted state
   * because its install flow has no PKCE and no verifier to bind.
   */
  app.get(
    '/v1/connections/microsoft/authorize-url',
    {
      schema: {
        querystring: MICROSOFT_AUTHORIZE_QUERY,
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
    async (request: FastifyRequest<{ Querystring: MicrosoftAuthorizeQuery }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);

      if (!deps.microsoft) {
        throw new HttpError(
          503,
          'CONNECTION_EXPIRED',
          'Microsoft 365 is not configured on this server',
        );
      }

      // Exactly one service's scopes (§9.1). A closed set, so a caller names a
      // feature this product enforces rules on and never a scope.
      const service = request.query.service ?? 'mail';
      const scopes = [...(MICROSOFT_SERVICES[service as keyof typeof MICROSOFT_SERVICES] ?? [])];

      return {
        url: buildMicrosoftConsentUrl(deps.microsoft, {
          state: request.query.state,
          codeChallenge: request.query.code_challenge,
          scopes,
        }),
        scopes,
      };
    },
  );

  app.post(
    '/v1/connections/microsoft',
    {
      schema: {
        body: CONNECT_BODY,
        response: { 201: CONNECTION_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: ConnectBody }>, reply) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      if (!deps.microsoft) {
        throw new HttpError(
          503,
          'CONNECTION_EXPIRED',
          'Microsoft 365 is not configured on this server',
        );
      }

      let exchanged;
      try {
        exchanged = await exchangeMicrosoftCode(
          deps.microsoft,
          request.body.code,
          request.body.code_verifier,
        );
      } catch (error) {
        // Logged, not propagated. Microsoft's error text echoes the request —
        // which carried the code — and is written for a developer's console.
        // But the code behind it decides what the operator should do, and
        // `consent_required` versus `invalid_client` need opposite responses.
        // Swallowing it bare is what cost a round trip on GitHub's secret.
        request.log.warn({ err: error }, 'microsoft connection could not be completed');
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          'That authorization could not be completed. Start again, and make sure offline access is granted.',
        );
      }

      const connection = await withWorkspace(deps.pool, workspaceId, (db) =>
        createConnection(db, deps.wrapper, {
          workspaceId,
          userId,
          provider: 'microsoft',
          // What Microsoft actually granted, normalised to the long scope
          // spelling the broker compares against. A partial grant must not be
          // recorded as a full one (§9.1).
          scopes: exchanged.scopes,
          refreshToken: exchanged.refreshToken,
          correlationId: String(request.id),
        }),
      );

      return reply.code(201).send(serialize(connection));
    },
  );

  /**
   * Begin a Slack install.
   *
   * The state is minted here, never accepted from the caller — the F-01
   * lesson, applied before it could be repeated. CSRF protection the client
   * chooses is a token the client can replay against itself, and the side that
   * checks a value should be the side that issues it.
   *
   * One service per call, like Google's consent URL: "read our public
   * channels" and "read our private channels" are different conversations, and
   * a flow that took a list could ask for both while appearing to ask for one.
   */
  app.get(
    '/v1/connections/slack/install-url',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: false,
          required: ['service'],
          properties: { service: { type: 'string', enum: [...SLACK_SERVICE_NAMES] } },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              url: { type: 'string' },
              state: { type: 'string' },
              scopes: { type: 'array', items: { type: 'string' } },
            },
            required: ['url', 'state', 'scopes'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Querystring: { service: SlackService } }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      if (!deps.slack) {
        throw new HttpError(503, 'CONNECTION_EXPIRED', 'Slack is not configured on this server');
      }

      const state = randomBytes(32).toString('base64url');
      await deps.redis.set(installKey(workspaceId, state), userId, 'EX', INSTALL_STATE_TTL_SECONDS);

      // Only the client id and redirect cross this line, never the secret —
      // the same narrowing `ConsentConfig` does for Google.
      return {
        url: buildSlackInstallUrl(
          { clientId: deps.slack.clientId, redirectUri: deps.slack.redirectUri },
          { service: request.query.service, state },
        ),
        state,
        scopes: [...SLACK_SERVICES[request.query.service]],
      };
    },
  );

  /**
   * Finish one.
   *
   * No equivalent of F-01 here, and worth saying why: Slack returns an
   * authorization *code*, which cannot be forged, and exchanging it with the
   * client secret is itself the proof that whoever completed this flow holds
   * the workspace. GitHub was the odd provider — an installation id is a small
   * integer anybody can type, so it needed a separate ownership check. The
   * state below is CSRF protection and nothing more, which is all it ever was.
   */
  app.post(
    '/v1/connections/slack',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['code', 'state'],
          properties: {
            code: { type: 'string', minLength: 8, maxLength: 512, pattern: '^[A-Za-z0-9._~-]+$' },
            state: {
              type: 'string',
              minLength: 16,
              maxLength: 128,
              pattern: '^[A-Za-z0-9._~-]+$',
            },
          },
        },
        response: { 201: CONNECTION_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: { code: string; state: string } }>, reply) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      // Redeemed first, and single-use: a replayed callback is refused as
      // firmly as an invented one.
      const began = await deps.redis.getdel(installKey(workspaceId, request.body.state));
      if (began !== userId) {
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          'That install was not started from this account',
        );
      }

      if (!deps.slack) {
        throw new HttpError(503, 'CONNECTION_EXPIRED', 'Slack is not configured on this server');
      }

      let installed;
      try {
        installed = await exchangeSlackCode(deps.slack, request.body.code);
      } catch (error) {
        // The caller learns nothing; the operator learns everything. Slack's
        // own code names the cause — `invalid_code`, `bad_redirect_uri`, or
        // the missing-rotation refusal — and the three have three different
        // fixes. The first version of the GitHub equivalent swallowed this and
        // cost two round trips to diagnose.
        request.log.warn({ err: error }, 'slack install could not be completed');
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          'That authorization could not be completed',
        );
      }

      const connection = await withWorkspace(deps.pool, workspaceId, (db) =>
        createConnection(db, deps.wrapper, {
          workspaceId,
          userId,
          provider: 'slack',
          // What Slack actually granted, not what was asked for.
          scopes: installed.scopes,
          // The rotating refresh token. The broker replaces it on every use.
          refreshToken: installed.refreshToken,
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
          200: {
            type: 'object',
            properties: { url: { type: 'string' }, state: { type: 'string' } },
            required: ['url', 'state'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      if (!deps.github) {
        throw new HttpError(503, 'CONNECTION_EXPIRED', 'GitHub is not configured on this server');
      }

      // Refused here rather than at the callback, so somebody does not pick
      // repositories on GitHub's screen and only then discover this server
      // cannot finish. Without user authorization there is no way to prove an
      // installation belongs to the person claiming it, and the honest answer
      // to that is to not begin.
      if (!deps.githubUserAuth) {
        throw new HttpError(
          503,
          'CONNECTION_EXPIRED',
          'GitHub user authorization is not configured on this server',
        );
      }

      // No PKCE and no scope list. Unlike an OAuth consent screen there is
      // nothing here to narrow: what an installation may reach is chosen on
      // GitHub's own screen by the person installing it, and cannot be widened
      // from this side. `state` still round-trips so the callback can be tied
      // to the request that started it (§12.1 OAuth CSRF).
      //
      // Only the slug crosses this line, never the private key — the same
      // narrowing `ConsentConfig` does for the Google client secret.
      // Minted here, not accepted from the caller. 32 bytes of CSPRNG, base64url
      // — the same shape the dashboard used to generate, moved to the side that
      // is going to check it.
      const state = randomBytes(32).toString('base64url');

      // Remembered before the URL is handed out, so only a state this server
      // issued for this workspace can later be redeemed. The value is the user
      // who began it, which is what the connect route compares against.
      await deps.redis.set(installKey(workspaceId, state), userId, 'EX', INSTALL_STATE_TTL_SECONDS);

      return { url: buildInstallUrl({ appSlug: deps.github.appSlug }, { state }), state };
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
    async (
      request: FastifyRequest<{ Body: { installation_id: string; state: string; code: string } }>,
      reply,
    ) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      // Redeemed before anything else, including the configuration check.
      // An unknown state is untrusted input and should be refused on its own
      // terms, not after the server has revealed whether GitHub is set up.
      //
      // Asking GitHub what an installation *is* was never a check on who may
      // claim it. Without this, any control-plane credential could post any
      // installation id — ids are small sequential integers — and attach a
      // stranger's repositories to its own workspace, which this server would
      // then mint real tokens for with the App private key it holds.
      //
      // The Google route has no equivalent hole because an authorization code
      // cannot be forged. This restores the same property by proof rather than
      // by assertion. `getdel` makes it single-use, so a replayed callback is
      // refused as firmly as an invented one.
      const began = await deps.redis.getdel(installKey(workspaceId, request.body.state));
      if (began !== userId) {
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          'That installation was not started from this account',
        );
      }

      if (!deps.github || !deps.githubUserAuth) {
        throw new HttpError(503, 'CONNECTION_EXPIRED', 'GitHub is not configured on this server');
      }

      // **The check that makes an installation id mean something.**
      //
      // Everything above proves a flow began here. None of it proves this
      // installation is the caller's: `readInstallation` below authenticates
      // with the App JWT, which can read any installation of this App, so it
      // answers "does this exist" and never "is this yours".
      //
      // Without this, an authenticated caller could start a flow, never visit
      // GitHub, and post a stranger's installation id — they are small
      // sequential integers — attaching somebody else's repositories to their
      // own workspace, which this server would then mint real tokens for with
      // the App private key. The whole of §12.1's IDOR shape, over a number.
      //
      // The `code` is GitHub's own evidence about the human who just finished
      // the install. It exchanges for a user token, and that token's
      // `/user/installations` lists what that person can actually reach. An id
      // absent from it was claimed rather than owned.
      let owned: boolean;
      try {
        owned = await userControlsInstallation(deps.githubUserAuth, {
          code: request.body.code,
          installationId: request.body.installation_id,
        });
      } catch (error) {
        // The caller is told nothing; the operator is told everything.
        //
        // The response has to stay opaque so somebody probing installation ids
        // cannot tell "not yours" from "does not exist" — but the first version
        // of this swallowed the cause entirely, and a refusal nobody can
        // diagnose is its own kind of outage. `bad_verification_code`,
        // `incorrect_client_credentials` and an unreachable GitHub are three
        // very different problems with three different fixes.
        request.log.warn(
          { err: error, installation_id: request.body.installation_id },
          'github installation ownership could not be confirmed',
        );

        // A failed exchange is a refusal, never a pass. GitHub being
        // unreachable must not become a way to skip the check (invariant 1).
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          'That installation could not be confirmed',
        );
      }

      if (!owned) {
        // Said plainly in the log, because this one is a real refusal rather
        // than a fault and an operator should be able to see the difference.
        request.log.warn(
          { installation_id: request.body.installation_id },
          'github installation is not reachable by the authorizing user',
        );

        // Deliberately the same message as a failed confirmation. Somebody
        // probing installation ids learns only that it did not work, not
        // whether the id exists and belongs to somebody else.
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          'That installation could not be confirmed',
        );
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
