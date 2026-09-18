/**
 * /v1/agents — agent identity control plane (spec §5, FR-07, FR-08).
 *
 * A thin layer over the identity domain. Three rules shape every handler:
 *
 *  * The tenant is never an input. `workspace_id` comes from the authenticated
 *    principal and nowhere else, so there is no request a caller can compose
 *    that reaches another workspace (invariant 4). The IDOR test asserts that a
 *    real id from workspace B is a 404 for a caller in workspace A.
 *
 *  * The owner is never an input either. An agent is always registered to the
 *    caller. Accepting `owner_user_id` from the body would let any member mint
 *    an agent owned by someone else, and §7.1 puts the delegating user at the
 *    centre of approvals — a misattributed owner would route a colleague's
 *    challenge to the attacker.
 *
 *  * Validation runs before anything else, against a closed schema. Invariant 9
 *    demands this of tool arguments; a registration body is no different.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { withWorkspace } from '@veto/db';
import type { PolicyFacts } from '@veto/permit';
import {
  AgentNotFoundError,
  findAgent,
  listAgents,
  registerAgent,
  revokeAgent,
  type Agent,
} from '@veto/identity';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';
import { assertWorkspaceUnlocked } from '../workspace.ts';

export interface AgentRoutesDeps {
  readonly pool: Pool;
  readonly redis: Redis;
  readonly policy: PolicyFacts;
}

/**
 * The public view of an agent.
 *
 * `fingerprint` is absent by design. It is a client-binding value, and a bearer
 * of it is closer to holding a credential than to reading a label; the owner
 * supplied it and does not need it echoed. Only its presence is reported.
 *
 * This shape is also the response schema below, which means fast-json-stringify
 * drops anything not listed. A column added to `agents` later cannot leak into
 * a response by being picked up by `select *`.
 */
function serializeAgent(agent: Agent) {
  return {
    id: agent.id,
    workspace_id: agent.workspace_id,
    provider: agent.provider,
    client_id: agent.client_id,
    owner_user_id: agent.owner_user_id,
    status: agent.status,
    has_fingerprint: agent.fingerprint !== null,
    created_at: agent.created_at.toISOString(),
    revoked_at: agent.revoked_at === null ? null : agent.revoked_at.toISOString(),
  };
}

const AGENT_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    workspace_id: { type: 'string' },
    provider: { type: 'string' },
    client_id: { type: 'string' },
    owner_user_id: { type: 'string' },
    status: { type: 'string' },
    has_fingerprint: { type: 'boolean' },
    created_at: { type: 'string' },
    revoked_at: { type: 'string', nullable: true },
  },
  required: [
    'id',
    'workspace_id',
    'provider',
    'client_id',
    'owner_user_id',
    'status',
    'has_fingerprint',
    'created_at',
  ],
} as const;

// Bounds mirror the CHECK constraints on `agents`, so a too-long value is a 400
// from the schema rather than a 500 from Postgres. `additionalProperties: false`
// is the point of the whole block: an unknown key is a rejected request, not a
// silently ignored one.
const REGISTER_BODY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['provider', 'client_id'],
  properties: {
    provider: { type: 'string', minLength: 1, maxLength: 100 },
    client_id: { type: 'string', minLength: 1, maxLength: 200 },
    fingerprint: { type: 'string', minLength: 1, maxLength: 512 },
  },
} as const;

const AGENT_ID_PARAMS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['agentId'],
  properties: {
    // Same alphabet as the id factory and the table's CHECK constraint, so a
    // malformed id never reaches a query.
    agentId: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{1,64}$' },
  },
} as const;

interface RegisterBody {
  provider: string;
  client_id: string;
  fingerprint?: string;
}

interface AgentIdParams {
  agentId: string;
}

export function registerAgentRoutes(app: FastifyInstance, deps: AgentRoutesDeps): void {
  const { pool, redis, policy } = deps;

  app.post(
    '/v1/agents',
    {
      schema: {
        body: REGISTER_BODY_SCHEMA,
        response: { 201: AGENT_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: RegisterBody }>, reply) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const body = request.body;

      const agent = await withWorkspace(pool, workspaceId, async (db) => {
        await assertWorkspaceUnlocked(db, workspaceId);
        return registerAgent(db, policy, {
          workspaceId,
          ownerUserId: userId,
          provider: body.provider,
          clientId: body.client_id,
          fingerprint: body.fingerprint ?? null,
          correlationId: request.id,
        });
      });

      return reply.code(201).send(serializeAgent(agent));
    },
  );

  app.get(
    '/v1/agents',
    {
      schema: {
        response: {
          200: { type: 'object', properties: { agents: { type: 'array', items: AGENT_SCHEMA } }, required: ['agents'] },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;
      const agents = await withWorkspace(pool, workspaceId, (db) => listAgents(db, workspaceId));
      return { agents: agents.map(serializeAgent) };
    },
  );

  app.get(
    '/v1/agents/:agentId',
    {
      schema: {
        params: AGENT_ID_PARAMS_SCHEMA,
        response: { 200: AGENT_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Params: AgentIdParams }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;
      const agent = await withWorkspace(pool, workspaceId, (db) =>
        findAgent(db, workspaceId, request.params.agentId),
      );

      // findAgent returns null for "another tenant's id" and for "no such id"
      // alike, and both surface as this one 404. Nothing here distinguishes them.
      if (!agent) throw new HttpError(404, 'AGENT_UNKNOWN', 'No such agent in this workspace');
      return serializeAgent(agent);
    },
  );

  // DELETE revokes; it does not remove. Agent rows are referenced by decisions
  // and audit events, and deleting one would break the audit trail (§7.3). The
  // verb matches the spec's own DELETE /v1/connections/{id}.
  //
  // Not guarded by the emergency lock: revocation only narrows access, and a
  // locked workspace is when it is needed most.
  app.delete(
    '/v1/agents/:agentId',
    {
      schema: {
        params: AGENT_ID_PARAMS_SCHEMA,
        response: {
          200: {
            type: 'object',
            properties: {
              agent_id: { type: 'string' },
              revoked: { type: 'boolean' },
              already_revoked: { type: 'boolean' },
              sessions_dropped: { type: 'integer' },
            },
            required: ['agent_id', 'revoked', 'already_revoked', 'sessions_dropped'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Params: AgentIdParams }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const { agentId } = request.params;

      try {
        const result = await revokeAgent(pool, redis, policy, {
          workspaceId,
          agentId,
          actorUserId: userId,
          correlationId: request.id,
        });

        return {
          agent_id: agentId,
          revoked: result.revoked,
          already_revoked: result.alreadyRevoked,
          sessions_dropped: result.sessionsDropped,
        };
      } catch (error) {
        if (error instanceof AgentNotFoundError) {
          throw new HttpError(404, 'AGENT_UNKNOWN', 'No such agent in this workspace');
        }
        throw error;
      }
    },
  );
}
