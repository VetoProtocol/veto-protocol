/**
 * /v1/audit-events (spec §5, §11).
 *
 * Read-only, tenant-scoped, and paginated on `seq` so no event can be skipped
 * or repeated between pages. There is no write route and there never will be:
 * the table is append-only, with triggers refusing every modification (§7.3),
 * and an HTTP route able to change it would be a way around them.
 *
 * The hashes go out with every event. A chain only the server can check is a
 * promise; returning the links lets a customer export the timeline and verify
 * it independently, which is what §11's portability requirement is for.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import { AUDIT_PAGE_MAX, readAuditEvents, verifyAuditChain } from '@veto/identity';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

const EVENT_SCHEMA = {
  type: 'object',
  properties: {
    seq: { type: 'integer' },
    id: { type: 'string' },
    actor: { type: 'string' },
    event_type: { type: 'string' },
    resource_ref: { type: 'string', nullable: true },
    outcome: { type: 'string' },
    correlation_id: { type: 'string', nullable: true },
    prev_hash: { type: 'string', nullable: true },
    hash: { type: 'string' },
    occurred_at: { type: 'string' },
  },
  required: ['seq', 'id', 'actor', 'event_type', 'outcome', 'hash', 'occurred_at'],
} as const;

/**
 * Query parameters are strings, and stay strings.
 *
 * `createApp` disables AJV's `coerceTypes` because a body that says `12345`
 * should not quietly become `"12345"`. That rule applies here too — a query
 * string genuinely *is* text — so numeric parameters are declared as digits and
 * converted in the handler, where the bounds are visible. Turning coercion back
 * on for this one route would weaken every body schema in the app.
 */
const QUERY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    before: { type: 'string', pattern: '^[0-9]{1,18}$' },
    limit: { type: 'string', pattern: '^[0-9]{1,3}$' },
    event_type: { type: 'string', maxLength: 100 },
    actor: { type: 'string', maxLength: 100 },
    outcome: { type: 'string', enum: ['allow', 'deny', 'challenge', 'lifecycle'] },
    correlation_id: { type: 'string', maxLength: 100 },
  },
} as const;

interface Query {
  before?: string;
  limit?: string;
  event_type?: string;
  actor?: string;
  outcome?: 'allow' | 'deny' | 'challenge' | 'lifecycle';
  correlation_id?: string;
}

export function registerAuditRoutes(app: FastifyInstance, deps: { pool: Pool }): void {
  app.get(
    '/v1/audit-events',
    {
      schema: {
        querystring: QUERY_SCHEMA,
        response: {
          200: {
            type: 'object',
            properties: {
              events: { type: 'array', items: EVENT_SCHEMA },
              next_cursor: { type: 'integer', nullable: true },
            },
            required: ['events'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Querystring: Query }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;
      const q = request.query;

      const limit = q.limit === undefined ? 50 : Number(q.limit);
      if (limit < 1 || limit > AUDIT_PAGE_MAX) {
        throw new HttpError(400, 'ARGUMENT_SCHEMA_INVALID', `limit must be 1..${AUDIT_PAGE_MAX}`);
      }

      const page = await withWorkspace(deps.pool, workspaceId, (db) =>
        readAuditEvents(db, workspaceId, {
          before: q.before === undefined ? null : Number(q.before),
          limit,
          eventType: q.event_type ?? null,
          actor: q.actor ?? null,
          outcome: q.outcome ?? null,
          correlationId: q.correlation_id ?? null,
        }),
      );

      return {
        events: page.events.map((e) => ({
          seq: e.seq,
          id: e.id,
          actor: e.actor,
          event_type: e.eventType,
          resource_ref: e.resourceRef,
          outcome: e.outcome,
          correlation_id: e.correlationId,
          prev_hash: e.prevHash,
          hash: e.hash,
          occurred_at: e.occurredAt.toISOString(),
        })),
        next_cursor: page.nextCursor,
      };
    },
  );

  app.get(
    '/v1/audit-events/verify',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              verified: { type: 'boolean' },
              broken_at: { type: 'integer', nullable: true },
              event_id: { type: 'string', nullable: true },
            },
            required: ['verified'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      const result = await withWorkspace(deps.pool, workspaceId, (db) =>
        verifyAuditChain(db, workspaceId),
      );

      // A break is reported, not hidden. The whole value of the chain is that
      // tampering becomes visible, and a verification endpoint that only ever
      // answered "fine" would be worse than none.
      return { verified: result.verified, broken_at: result.brokenAt, event_id: result.eventId };
    },
  );
}
