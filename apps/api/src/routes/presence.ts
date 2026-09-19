/**
 * /v1/presence and /v1/emergency-lock (spec §5, §7.2).
 *
 * Presence is a signal, never proof of intent, and these routes are shaped so
 * it cannot become one:
 *
 *  * **A user sets their own presence.** The user id comes from the principal,
 *    never from the body. Somebody else marking you `active` would be somebody
 *    else weakening your policy.
 *  * **There is no field for an IP address or a location.** §7.2 forbids
 *    inferring presence from either, and the way to keep that true is to have
 *    nowhere to put one.
 *  * **The source is a closed set**, and cannot claim more assurance than it is
 *    capable of witnessing — checked in the state machine, not here.
 *
 * The emergency lock is workspace-wide and separate. It denies everything for
 * everyone, and the pipeline reads it at step 3 before policy is consulted.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import {
  ASSURANCE_LEVELS,
  PRESENCE_SOURCES,
  PRESENCE_STATES,
  PresenceTransitionError,
  readPresence,
  setEmergencyLock,
  setPresence,
} from '@veto/presence';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

const PRESENCE_RESPONSE = {
  type: 'object',
  properties: {
    state: { type: 'string' },
    assurance: { type: 'string' },
    source: { type: 'string' },
    changed_at: { type: 'string' },
    expires_at: { type: 'string', nullable: true },
  },
  required: ['state', 'assurance', 'source'],
} as const;

const SET_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['state', 'source', 'assurance'],
  properties: {
    state: { type: 'string', enum: [...PRESENCE_STATES] },
    source: { type: 'string', enum: [...PRESENCE_SOURCES] },
    assurance: { type: 'string', enum: [...ASSURANCE_LEVELS] },
    // Bounded: a window measured in days is a standing grant with a timer on it.
    ttl_ms: { type: 'integer', minimum: 1000, maximum: 12 * 60 * 60 * 1000 },
  },
} as const;

interface SetBody {
  state: (typeof PRESENCE_STATES)[number];
  source: (typeof PRESENCE_SOURCES)[number];
  assurance: (typeof ASSURANCE_LEVELS)[number];
  ttl_ms?: number;
}

interface LockBody {
  locked: boolean;
}

export function registerPresenceRoutes(app: FastifyInstance, deps: { pool: Pool }): void {
  app.get(
    '/v1/presence',
    { schema: { response: { 200: PRESENCE_RESPONSE, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA } } },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      const presence = await withWorkspace(deps.pool, workspaceId, (db) =>
        readPresence(db, workspaceId, userId),
      );

      return {
        state: presence.state,
        assurance: presence.assurance,
        source: presence.source,
        changed_at: presence.changedAt.toISOString(),
        expires_at: presence.expiresAt === null ? null : presence.expiresAt.toISOString(),
      };
    },
  );

  app.put(
    '/v1/presence',
    { schema: { body: SET_BODY, response: { 200: PRESENCE_RESPONSE, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA } } },
    async (request: FastifyRequest<{ Body: SetBody }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      try {
        const presence = await withWorkspace(deps.pool, workspaceId, (db) =>
          setPresence(db, {
            workspaceId,
            // Always the caller. There is no body field for a user id.
            userId,
            state: request.body.state,
            source: request.body.source,
            assurance: request.body.assurance,
            ttlMs: request.body.ttl_ms ?? null,
            correlationId: String(request.id),
          }),
        );

        return {
          state: presence.state,
          assurance: presence.assurance,
          source: presence.source,
          changed_at: presence.changedAt.toISOString(),
          expires_at: presence.expiresAt === null ? null : presence.expiresAt.toISOString(),
        };
      } catch (error) {
        if (error instanceof PresenceTransitionError) {
          // 409: the request is well formed, the current state refuses it.
          throw new HttpError(409, 'AUTOMATION_WINDOW_VIOLATION', error.reason);
        }
        throw error;
      }
    },
  );

  app.post(
    '/v1/emergency-lock',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['locked'],
          properties: { locked: { type: 'boolean' } },
        },
        response: {
          200: {
            type: 'object',
            properties: { locked: { type: 'boolean' } },
            required: ['locked'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Body: LockBody }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      const result = await withWorkspace(deps.pool, workspaceId, (db) =>
        setEmergencyLock(db, workspaceId, request.body.locked, userId),
      );

      return { locked: result.locked };
    },
  );
}
