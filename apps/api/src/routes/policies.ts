/**
 * /v1/policies — the rules that decide (spec §5, §3.3 step 4).
 *
 * These are **Veto's own** deterministic rules, not Permit's. They run before
 * the relationship question and can only refuse (invariant 3). Two consequences
 * a caller has to understand, and which the dashboard states out loud:
 *
 *  1. **A rule is necessary for an allow and is not sufficient for one.** After
 *     step 4 comes `permit.check`, and after that the risk checks. A rule saying
 *     `allow` means "this layer has no objection", never "this will happen".
 *  2. **No rule means denied.** An empty policy list is not an unconfigured
 *     system waiting to be told what to refuse; it is a system that refuses
 *     everything, which is the correct starting state (invariant 2).
 *
 * Rules are created and deleted, never edited — see `createPolicy` for why the
 * recorded `policy_version` makes in-place editing a lie.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import {
  createPolicy,
  deletePolicy,
  isValidSchedule,
  loadPolicies,
  POLICY_ACTIONS,
} from '@veto/decisions';
import { PRESENCE_STATES } from '@veto/presence';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

const POLICY_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    version: { type: 'string' },
    subject: { type: 'string' },
    action: { type: 'string' },
    effect: { type: 'string' },
    resource_filter: {
      type: 'object',
      properties: {
        type: { type: 'string' },
        ids: { type: 'array', items: { type: 'string' } },
        prefix: { type: 'string' },
      },
    },
    conditions: {
      type: 'object',
      properties: {
        presence: { type: 'array', items: { type: 'string' } },
        maxPerDay: { type: 'integer' },
        requireIntent: { type: 'boolean' },
        // Listed here as well as on the request. Fastify serialises a response
        // against this schema and drops what it does not name — so a rule with
        // a window would have been stored, and then invisible everywhere that
        // reads one back, including the screen that has to show it.
        schedule: {
          type: 'object',
          properties: {
            from: { type: 'string' },
            to: { type: 'string' },
            days: { type: 'array', items: { type: 'integer' } },
          },
        },
      },
    },
  },
  required: ['id', 'version', 'subject', 'action', 'effect'],
} as const;

const CREATE_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['subject', 'action', 'effect', 'resource_filter'],
  properties: {
    // An agent id, or the wildcard. Not a free string: a typo'd agent id would
    // produce a rule that matches nothing and looks like a policy bug.
    subject: { type: 'string', pattern: '^(\\*|agt_[A-Za-z0-9_-]{1,64})$' },
    action: { type: 'string', enum: [...POLICY_ACTIONS] },
    effect: { type: 'string', enum: ['allow', 'deny', 'challenge'] },
    resource_filter: {
      type: 'object',
      additionalProperties: false,
      // `type` is required even though the matcher treats it as optional. A
      // rule with no resource type would match a resource type invented later,
      // which is the one kind of rule nobody can review today.
      required: ['type'],
      properties: {
        type: { type: 'string', minLength: 1, maxLength: 60 },
        ids: {
          type: 'array',
          minItems: 1,
          maxItems: 200,
          items: { type: 'string', minLength: 1, maxLength: 512 },
        },
        prefix: { type: 'string', minLength: 1, maxLength: 512 },
      },
    },
    conditions: {
      type: 'object',
      additionalProperties: false,
      properties: {
        presence: {
          type: 'array',
          minItems: 1,
          maxItems: PRESENCE_STATES.length,
          items: { type: 'string', enum: [...PRESENCE_STATES] },
        },
        // A cumulative authorization limit, never a rate limit (§7.1).
        maxPerDay: { type: 'integer', minimum: 1, maximum: 100000 },
        requireIntent: { type: 'boolean' },
        // FR-06's time dimension. Read in the workspace's own zone, so "09:00"
        // means nine where the people are — see packages/decisions/schedule.ts.
        schedule: {
          type: 'object',
          additionalProperties: false,
          required: ['from', 'to'],
          properties: {
            from: { type: 'string', pattern: '^([01][0-9]|2[0-3]):[0-5][0-9]$' },
            to: { type: 'string', pattern: '^([01][0-9]|2[0-3]):[0-5][0-9]$' },
            // 0 is Sunday. Omitted means every day; naming "weekdays" here
            // would bake in an assumption about which days those are.
            days: {
              type: 'array',
              minItems: 1,
              maxItems: 7,
              items: { type: 'integer', minimum: 0, maximum: 6 },
            },
          },
        },
      },
    },
  },
} as const;

interface CreateBody {
  subject: string;
  action: string;
  effect: 'allow' | 'deny' | 'challenge';
  resource_filter: { type: string; ids?: string[]; prefix?: string };
  conditions?: {
    presence?: string[];
    maxPerDay?: number;
    requireIntent?: boolean;
    schedule?: { from: string; to: string; days?: number[] };
  };
}

export function registerPolicyRoutes(app: FastifyInstance, deps: { pool: Pool }): void {
  app.get(
    '/v1/policies',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: { policies: { type: 'array', items: POLICY_SCHEMA } },
            required: ['policies'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      const rules = await withWorkspace(deps.pool, workspaceId, (db) =>
        loadPolicies(db, workspaceId),
      );

      return {
        policies: rules.map((rule) => ({
          id: rule.id,
          version: rule.version,
          subject: rule.subject,
          action: rule.action,
          effect: rule.effect,
          resource_filter: rule.resourceFilter,
          conditions: rule.conditions,
        })),
      };
    },
  );

  app.post(
    '/v1/policies',
    {
      schema: {
        body: CREATE_BODY,
        response: { 201: POLICY_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: CreateBody }>, reply) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const body = request.body;

      if (body.resource_filter.ids !== undefined && body.resource_filter.prefix !== undefined) {
        // Both would mean "in this list AND under this path", which is almost
        // never what somebody means and reads as "or" at a glance. Refusing is
        // kinder than silently intersecting them.
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          'Give either a list of ids or a prefix, not both',
        );
      }

      // Shape is the schema's job; meaning is this one's. A window whose start
      // equals its end passes every pattern above and matches nothing ever —
      // an operator would have written a rule that silently does nothing, and
      // found out as a denial somewhere else entirely.
      const schedule = body.conditions?.schedule;
      if (schedule !== undefined && !isValidSchedule(schedule)) {
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          'A schedule needs a start and end that differ, and days between 0 and 6',
        );
      }

      const rule = await withWorkspace(deps.pool, workspaceId, (db) =>
        createPolicy(db, {
          workspaceId,
          subject: body.subject,
          action: body.action,
          effect: body.effect,
          resourceFilter: body.resource_filter,
          conditions: body.conditions ?? {},
          actorUserId: userId,
          correlationId: String(request.id),
        }),
      );

      return reply.code(201).send({
        id: rule.id,
        version: rule.version,
        subject: rule.subject,
        action: rule.action,
        effect: rule.effect,
        resource_filter: rule.resourceFilter,
        conditions: rule.conditions,
      });
    },
  );

  app.delete(
    '/v1/policies/:policyId',
    {
      schema: {
        params: {
          type: 'object',
          additionalProperties: false,
          required: ['policyId'],
          properties: { policyId: { type: 'string', pattern: '^pol_[A-Za-z0-9_-]{1,64}$' } },
        },
        response: {
          200: {
            type: 'object',
            properties: { policy_id: { type: 'string' }, removed: { type: 'boolean' } },
            required: ['policy_id', 'removed'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Params: { policyId: string } }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      const removed = await withWorkspace(deps.pool, workspaceId, (db) =>
        deletePolicy(db, workspaceId, request.params.policyId, userId, String(request.id)),
      );

      if (!removed) {
        throw new HttpError(404, 'RESOURCE_OUT_OF_SCOPE', 'No such policy in this workspace');
      }

      return { policy_id: request.params.policyId, removed: true };
    },
  );
}
