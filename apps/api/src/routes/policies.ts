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
  findTemplate,
  isValidSchedule,
  loadPolicies,
  POLICY_ACTIONS,
  POLICY_TEMPLATES,
  sameRule,
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


  /**
   * The starter rules on offer.
   *
   * A constant catalogue, not tenant data, so this reads nothing and is the
   * same for every workspace. It exists as a route rather than a copy in the
   * dashboard because two hand-kept copies of a list is how the tool
   * catalogue, the label map and the policy form each drifted.
   */
  app.get(
    '/v1/policies/templates',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              templates: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    title: { type: 'string' },
                    summary: { type: 'string' },
                    requires: { type: 'string' },
                    rules: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          action: { type: 'string' },
                          effect: { type: 'string' },
                          resource_type: { type: 'string' },
                          explains: { type: 'string' },
                        },
                        required: ['action', 'effect', 'resource_type', 'explains'],
                      },
                    },
                  },
                  required: ['id', 'title', 'summary', 'requires', 'rules'],
                },
              },
            },
            required: ['templates'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);

      return {
        templates: POLICY_TEMPLATES.map((template) => ({
          id: template.id,
          title: template.title,
          summary: template.summary,
          requires: template.requires,
          rules: template.rules.map((rule) => ({
            action: rule.action,
            effect: rule.effect,
            resource_type: rule.resourceFilter.type ?? '',
            explains: rule.explains,
          })),
        })),
      };
    },
  );

  /**
   * Apply one, to one agent.
   *
   * The subject is named by the caller and never defaulted. A template that
   * quietly applied to `*` would hand every agent in the workspace the same
   * access on one click, which is the opposite of what an authorization
   * product should make easy — and `*` remains available to somebody who types
   * it, because that is a decision worth making deliberately.
   *
   * Applying twice is a no-op: a rule the workspace already has, meaning for
   * meaning, is skipped rather than duplicated. Rules are created and deleted
   * and never edited, so a duplicate would be a second row with a second
   * version and no second effect — clutter that makes a policy list harder to
   * read and tells nobody anything.
   */
  app.post(
    '/v1/policies/templates',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['template_id', 'subject'],
          properties: {
            template_id: { type: 'string', minLength: 1, maxLength: 60 },
            subject: { type: 'string', pattern: '^(\\*|agt_[A-Za-z0-9_-]{1,64})$' },
          },
        },
        response: {
          201: {
            type: 'object',
            properties: {
              template_id: { type: 'string' },
              subject: { type: 'string' },
              created: { type: 'array', items: { type: 'string' } },
              skipped: { type: 'integer' },
            },
            required: ['template_id', 'subject', 'created', 'skipped'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (
      request: FastifyRequest<{ Body: { template_id: string; subject: string } }>,
      reply,
    ) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      const template = findTemplate(request.body.template_id);
      if (!template) throw new HttpError(404, 'NOT_FOUND', 'No such template');

      const result = await withWorkspace(deps.pool, workspaceId, async (db) => {
        // Read once, compare in memory. The alternative is a query per rule,
        // and a workspace's rule list is small enough that one read is both
        // faster and easier to reason about.
        const existing = await loadPolicies(db, workspaceId);

        const created: string[] = [];
        let skipped = 0;

        for (const rule of template.rules) {
          const candidate = {
            subject: request.body.subject,
            action: rule.action,
            effect: rule.effect,
            resourceFilter: rule.resourceFilter,
            conditions: rule.conditions,
          };

          if (existing.some((have) => sameRule(have, candidate))) {
            skipped += 1;
            continue;
          }

          // One rule at a time, through the same function the create route
          // uses: each gets its own version, and each writes its own audit
          // event. A bulk path would be a second way to make a rule, and the
          // two would drift.
          const made = await createPolicy(db, {
            workspaceId,
            ...candidate,
            actorUserId: userId,
            correlationId: String(request.id),
          });
          created.push(made.id);
        }

        return { created, skipped };
      });

      return reply.code(201).send({
        template_id: template.id,
        subject: request.body.subject,
        ...result,
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
