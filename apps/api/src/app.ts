/**
 * The Veto control-plane HTTP app (spec §5).
 *
 * This is *not* the MCP gateway. The gateway is the enforcement point for
 * protected actions (invariant 8) and arrives in stage 2. This app manages the
 * objects that enforcement later reads: agents now, connections and policies
 * next. Keeping them apart matters — the gateway's rules about tool calls and
 * action digests do not apply to a registration form, and conflating the two
 * would invite exactly the "authorize once, act forever" shape the product
 * exists to prevent.
 */

import Fastify, { type FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { PolicyUnavailableError, type PolicyFacts } from '@veto/permit';
import { DuplicateLiveAgentError } from '@veto/identity';
import { errorBody, HttpError } from './errors.ts';
import type { Authenticator } from './principal.ts';
import { registerAgentRoutes } from './routes/agents.ts';

export interface AppDeps {
  readonly pool: Pool;
  readonly redis: Redis;
  readonly policy: PolicyFacts;
  /** Required. See principal.ts — there is no unauthenticated configuration. */
  readonly authenticate: Authenticator;
  readonly logger?: boolean;
}

/** Postgres foreign-key violation. */
const FOREIGN_KEY_VIOLATION = '23503';

export function createApp(deps: AppDeps): FastifyInstance {
  if (typeof deps.authenticate !== 'function') {
    throw new Error('createApp requires an authenticate function (fail closed, invariant 1)');
  }

  const app = Fastify({
    logger: deps.logger ?? false,
    // 64 KiB. Registration bodies are three short strings; anything larger is
    // not a mistake worth parsing.
    bodyLimit: 64 * 1024,
    ajv: {
      customOptions: {
        // Fastify defaults this to true, which *deletes* unknown properties and
        // lets the request through. Combined with `additionalProperties: false`
        // that turns a rejection into a silent edit of the caller's input —
        // the opposite of the strict validation invariant 9 asks for.
        removeAdditional: false,
        // Also on by default. Coercion would accept `{"client_id": 123}` as the
        // string "123"; a type error should be a 400, not a guess.
        coerceTypes: false,
        allErrors: false,
      },
    },
  });

  // Identity first, for every route (spec §3.3 step 1). No route opts out, so a
  // handler added later cannot forget to authenticate.
  app.addHook('onRequest', async (request, reply) => {
    const principal = await deps.authenticate(request);
    if (!principal) {
      return reply
        .code(401)
        .send(errorBody('IDENTITY_UNRESOLVED', 'Authentication required'));
    }
    request.principal = principal;
    return undefined;
  });

  app.setErrorHandler((error, request, reply) => {
    const mapped = mapError(error);

    // Log the code and route, never the body or headers: a registration body
    // can carry a fingerprint and an Authorization header is always present
    // (invariant 5). `request.id` is the correlation id that also reaches the
    // audit event, so a 500 can still be traced without the payload.
    request.log.error(
      { code: mapped.code, status: mapped.status, url: request.url, err: error },
      'request failed',
    );

    return reply.code(mapped.status).send(errorBody(mapped.code, mapped.message));
  });

  app.setNotFoundHandler((_request, reply) =>
    reply.code(404).send(errorBody('NOT_FOUND', 'No such route')),
  );

  registerAgentRoutes(app, { pool: deps.pool, redis: deps.redis, policy: deps.policy });

  return app;
}

interface MappedError {
  status: number;
  code: string;
  message: string;
}

function mapError(error: unknown): MappedError {
  if (error instanceof HttpError) {
    return { status: error.status, code: error.code, message: error.message };
  }

  if (error instanceof DuplicateLiveAgentError) {
    return {
      status: 409,
      code: 'AGENT_ALREADY_REGISTERED',
      message: 'This user already has a live agent for that client',
    };
  }

  // Permit being unreachable is a denial, never a degraded success
  // (invariant 1). Registration is refused and nothing was written: syncAgent
  // runs inside the transaction, so the rollback removes the agent row too.
  if (error instanceof PolicyUnavailableError) {
    return {
      status: 503,
      code: 'POLICY_UNAVAILABLE',
      message: 'Policy engine unavailable; request denied',
    };
  }

  const candidate = error as { validation?: unknown; statusCode?: number; code?: string };

  if (candidate.validation) {
    // The validation detail is deliberately dropped. Echoing which property
    // failed is fine here, but the value that failed is caller-controlled and
    // would land in a response that may be logged downstream.
    return {
      status: 400,
      code: 'ARGUMENT_SCHEMA_INVALID',
      message: 'Request body or parameters failed validation',
    };
  }

  // The principal named a user that no longer exists in this workspace. The
  // composite FK on (workspace_id, owner_user_id) catches it. Treat a stale
  // identity as unresolved rather than as a server fault.
  if (candidate.code === FOREIGN_KEY_VIOLATION) {
    return { status: 401, code: 'IDENTITY_UNRESOLVED', message: 'Authentication required' };
  }

  if (candidate.code === 'FST_ERR_CTP_BODY_TOO_LARGE' || candidate.statusCode === 413) {
    return { status: 413, code: 'ARGUMENT_SCHEMA_INVALID', message: 'Request body too large' };
  }

  if (candidate.statusCode === 400 || candidate.code === 'FST_ERR_CTP_INVALID_MEDIA_TYPE') {
    return { status: 400, code: 'ARGUMENT_SCHEMA_INVALID', message: 'Malformed request' };
  }

  // Anything unrecognised is a 500 with no detail. An unexpected error is the
  // case where leaking internals is most likely and least useful.
  return { status: 500, code: 'INTERNAL_ERROR', message: 'Request failed' };
}
