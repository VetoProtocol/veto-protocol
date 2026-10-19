/**
 * /v1/webhooks — alerts (spec §5.4).
 *
 * Registering an endpoint is the one place in this API where a caller hands
 * over a URL that the server will later fetch. That is §12.1's SSRF scenario,
 * so the same `checkDestination` the decision pipeline uses runs here before
 * anything is stored — and again on every delivery attempt, because a name that
 * resolved to the public internet at registration can resolve to the metadata
 * service an hour later.
 *
 * The signing secret is generated server-side and returned exactly once. There
 * is no route that reads it back: a secret a caller can re-read is a secret that
 * lives in every log of every client that ever asked. Losing it means creating
 * a new endpoint, which is the honest cost.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import { checkDestination } from '@veto/decisions';
import type { KeyWrapper } from '@veto/vault';
import {
  createEndpoint,
  disableEndpoint,
  drainDeliveries,
  listDeliveries,
  listEndpoints,
  WEBHOOK_EVENTS,
  type WebhookEventType,
} from '@veto/webhooks';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

const ENDPOINT_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    url: { type: 'string' },
    events: { type: 'array', items: { type: 'string' } },
    status: { type: 'string' },
    route_to_user_id: { type: 'string', nullable: true },
    created_at: { type: 'string' },
    disabled_at: { type: 'string', nullable: true },
  },
  required: ['id', 'url', 'events', 'status', 'created_at'],
} as const;

const CREATE_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['url', 'events'],
  properties: {
    url: { type: 'string', minLength: 9, maxLength: 2048 },
    events: {
      type: 'array',
      minItems: 1,
      maxItems: WEBHOOK_EVENTS.length,
      // A closed set. An endpoint that subscribed to a typo would receive
      // nothing and look like a delivery bug for as long as nobody checked.
      items: { type: 'string', enum: [...WEBHOOK_EVENTS] },
    },
    /**
     * Narrow this endpoint to one person's events.
     *
     * `"me"` rather than a user id, and deliberately so. A caller naming an
     * arbitrary id would be asking to receive somebody else's alerts, and the
     * only safe answer to that is a refusal — so the field has no way to say
     * it. The server substitutes the authenticated user. An operator setting
     * one up for a colleague is a different feature with a different check.
     */
    route_to: { type: 'string', enum: ['me'] },
  },
} as const;

interface CreateBody {
  url: string;
  events: WebhookEventType[];
  route_to?: 'me';
}

/** Digits as a string: `coerceTypes` is off app-wide. See routes/audit.ts. */
const LIMIT_QUERY = {
  type: 'object',
  additionalProperties: false,
  properties: { limit: { type: 'string', pattern: '^[0-9]{1,3}$' } },
} as const;

export interface WebhookRoutesDeps {
  readonly pool: Pool;
  readonly wrapper: KeyWrapper;
}

export function registerWebhookRoutes(app: FastifyInstance, deps: WebhookRoutesDeps): void {
  app.get(
    '/v1/webhooks',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: { endpoints: { type: 'array', items: ENDPOINT_SCHEMA } },
            required: ['endpoints'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      const endpoints = await withWorkspace(deps.pool, workspaceId, (db) =>
        listEndpoints(db, workspaceId),
      );

      return {
        endpoints: endpoints.map((e) => ({
          id: e.id,
          url: e.url,
          events: [...e.events],
          status: e.status,
          route_to_user_id: e.routeToUserId,
          created_at: e.createdAt.toISOString(),
          disabled_at: e.disabledAt === null ? null : e.disabledAt.toISOString(),
        })),
      };
    },
  );

  app.post(
    '/v1/webhooks',
    {
      schema: {
        body: CREATE_BODY,
        response: {
          201: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              url: { type: 'string' },
              events: { type: 'array', items: { type: 'string' } },
              status: { type: 'string' },
              route_to_user_id: { type: 'string', nullable: true },
              created_at: { type: 'string' },
              // Returned here and never again. The response schema is the only
              // place in this API where a secret appears, deliberately marked.
              secret: { type: 'string' },
            },
            required: ['id', 'url', 'events', 'status', 'created_at', 'secret'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Body: CreateBody }>, reply) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      // Before anything is stored. An endpoint pointing at 169.254.169.254 that
      // is rejected only at delivery time is a row that keeps trying.
      const destination = await checkDestination(request.body.url);
      if (!destination.ok) {
        throw new HttpError(
          400,
          'DESTINATION_NOT_PERMITTED',
          // `why` is generated here from a closed set of phrases, not echoed
          // from the caller's input.
          `That URL cannot be used: ${destination.why}`,
        );
      }

      const created = await withWorkspace(deps.pool, workspaceId, (db) =>
        createEndpoint(db, deps.wrapper, {
          workspaceId,
          url: request.body.url,
          events: request.body.events,
          createdBy: userId,
          // The authenticated user, never a value from the body. `route_to`
          // can only say "me", so there is no field an attacker could put
          // somebody else's id in — the same shape as a mailbox tool taking
          // its resource from the session rather than an argument.
          routeToUserId: request.body.route_to === 'me' ? userId : null,
        }),
      );

      return reply.code(201).send({
        id: created.endpoint.id,
        url: created.endpoint.url,
        events: [...created.endpoint.events],
        status: created.endpoint.status,
        route_to_user_id: created.endpoint.routeToUserId,
        created_at: created.endpoint.createdAt.toISOString(),
        secret: created.secret,
      });
    },
  );

  app.delete(
    '/v1/webhooks/:endpointId',
    {
      schema: {
        params: {
          type: 'object',
          additionalProperties: false,
          required: ['endpointId'],
          properties: { endpointId: { type: 'string', pattern: '^whe_[A-Za-z0-9_-]{1,64}$' } },
        },
        response: {
          200: {
            type: 'object',
            properties: { endpoint_id: { type: 'string' }, disabled: { type: 'boolean' } },
            required: ['endpoint_id', 'disabled'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Params: { endpointId: string } }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      const disabled = await withWorkspace(deps.pool, workspaceId, (db) =>
        disableEndpoint(db, workspaceId, request.params.endpointId),
      );

      if (!disabled) {
        throw new HttpError(404, 'RESOURCE_OUT_OF_SCOPE', 'No such active endpoint here');
      }

      return { endpoint_id: request.params.endpointId, disabled: true };
    },
  );

  app.get(
    '/v1/webhooks/deliveries',
    {
      schema: {
        querystring: LIMIT_QUERY,
        response: {
          200: {
            type: 'object',
            properties: {
              deliveries: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    endpoint_id: { type: 'string' },
                    event_id: { type: 'string' },
                    event_type: { type: 'string' },
                    status: { type: 'string' },
                    attempts: { type: 'integer' },
                    next_attempt_at: { type: 'string' },
                    last_status: { type: 'integer', nullable: true },
                    last_error: { type: 'string', nullable: true },
                    delivered_at: { type: 'string', nullable: true },
                    occurred_at: { type: 'string' },
                  },
                  required: ['id', 'endpoint_id', 'event_id', 'event_type', 'status', 'attempts'],
                },
              },
            },
            required: ['deliveries'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Querystring: { limit?: string } }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      const limit = Math.min(Number(request.query.limit ?? '50'), 200);

      const rows = await withWorkspace(deps.pool, workspaceId, (db) =>
        listDeliveries(db, workspaceId, limit),
      );

      // The payload is not returned. It is already in the audit trail in a
      // form an auditor can verify, and a delivery list is an operations view:
      // did it arrive, how many times did we try, what did they say.
      return {
        deliveries: rows.map((d) => ({
          id: d.id,
          endpoint_id: d.endpoint_id,
          event_id: d.event_id,
          event_type: d.event_type,
          status: d.status,
          attempts: d.attempts,
          next_attempt_at: d.next_attempt_at.toISOString(),
          last_status: d.last_status,
          last_error: d.last_error,
          delivered_at: d.delivered_at === null ? null : d.delivered_at.toISOString(),
          occurred_at: d.occurred_at.toISOString(),
        })),
      };
    },
  );

  app.post(
    '/v1/webhooks/drain',
    {
      schema: {
        body: { type: 'object', additionalProperties: false, properties: {} },
        response: {
          200: {
            type: 'object',
            properties: {
              attempted: { type: 'integer' },
              delivered: { type: 'integer' },
              retrying: { type: 'integer' },
              failed: { type: 'integer' },
            },
            required: ['attempted', 'delivered', 'retrying', 'failed'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      // An explicit trigger, for a deployment with no scheduler and for tests.
      // It is scoped to the caller's workspace like everything else here, so it
      // cannot be used to drive another tenant's queue.
      return withWorkspace(deps.pool, workspaceId, (db) =>
        drainDeliveries(
          db,
          {
            wrapper: deps.wrapper,
            // The port adapter. `checkDestination` returns `why` on refusal;
            // the worker wants a `reason`, and the shapes are kept apart so the
            // worker does not depend on the pipeline's type.
            checkDestination: async (url) => {
              const verdict = await checkDestination(url);
              return verdict.ok ? { ok: true } : { ok: false, reason: verdict.why };
            },
          },
          workspaceId,
        ),
      );
    },
  );
}
