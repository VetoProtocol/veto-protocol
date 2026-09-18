/**
 * POST /v1/decisions/evaluate (spec §5.1, §5.2).
 *
 * Runs the §3.3 pipeline and returns the decision. It **decides and never
 * executes** — no upstream service is contacted from here, on any result.
 *
 * ## This is not a second enforcement point
 *
 * The gateway calls the pipeline in-process; it does not come through here.
 * That matters for invariant 8: if the gateway asked this endpoint over HTTP,
 * anything else holding a credential could ask too, and "the gateway is the
 * only enforcement point" would become "the gateway is one of the callers".
 * This endpoint exists so a decision can be explained, simulated and tested —
 * the dashboard's "why was this denied?" view, and the §12.1 scenarios.
 *
 * Because it only ever decides, exposing it cannot widen access: the worst a
 * caller learns is what would have happened, scoped to its own workspace.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { evaluate, type EvaluateInput } from '@veto/decisions';
import type { PolicyDecisions } from '@veto/permit';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

const BODY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['agent_id', 'tool', 'action', 'resource'],
  properties: {
    request_id: { type: 'string', pattern: '^req_[A-Za-z0-9_-]{1,64}$' },
    agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{1,64}$' },
    client_id: { type: 'string', minLength: 1, maxLength: 200 },
    tool: { type: 'string', minLength: 1, maxLength: 200 },
    action: { type: 'string', minLength: 1, maxLength: 40 },
    resource: {
      type: 'object',
      additionalProperties: false,
      required: ['type', 'id'],
      properties: {
        type: { type: 'string', minLength: 1, maxLength: 60 },
        id: { type: 'string', minLength: 1, maxLength: 512 },
      },
    },
    arguments: { type: 'object' },
    declared_intent: { type: 'string', maxLength: 500, nullable: true },
    destination: { type: 'string', maxLength: 2048, nullable: true },
  },
} as const;

interface Body {
  request_id?: string;
  agent_id: string;
  client_id?: string;
  tool: string;
  action: string;
  resource: { type: string; id: string };
  arguments?: Record<string, unknown>;
  declared_intent?: string | null;
  destination?: string | null;
}

export interface DecisionRoutesDeps {
  readonly pool: Pool;
  readonly redis: Redis;
  readonly decisions: PolicyDecisions;
}

export function registerDecisionRoutes(app: FastifyInstance, deps: DecisionRoutesDeps): void {
  app.post(
    '/v1/decisions/evaluate',
    {
      schema: {
        body: BODY_SCHEMA,
        response: {
          200: {
            type: 'object',
            properties: {
              decision_id: { type: 'string' },
              result: { type: 'string' },
              reason_code: { type: 'string' },
              human_message: { type: 'string' },
              approval_id: { type: 'string', nullable: true },
              expires_at: { type: 'string', nullable: true },
              policy_version: { type: 'string', nullable: true },
              permit_result: { type: 'string' },
              action_digest: { type: 'string' },
              latency_ms: { type: 'number' },
            },
            required: ['decision_id', 'result', 'reason_code', 'human_message', 'permit_result'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Body: Body }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const body = request.body;

      // The human is the authenticated principal, never a body field. A caller
      // that could name someone else would be asking "what would *they* be
      // allowed to do", which is a different question from the one this answers.
      const input: EvaluateInput = {
        requestId: body.request_id ?? `req_${String(request.id).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 40) || 'anon'}`,
        workspaceId,
        humanId: userId,
        agentId: body.agent_id,
        clientId: body.client_id ?? 'unknown',
        tool: body.tool,
        action: body.action,
        resource: body.resource,
        arguments: body.arguments ?? {},
        declaredIntent: body.declared_intent ?? null,
        destination: body.destination ?? null,
        occurredAt: new Date().toISOString(),
      };

      let decision;
      try {
        decision = await evaluate(
          { pool: deps.pool, redis: deps.redis, policy: deps.decisions },
          input,
        );
      } catch (error) {
        // The digest refuses argument sets it cannot represent unambiguously.
        // That is a malformed request, not a server fault.
        if (error instanceof TypeError || (error as Error).name === 'ActionDigestError') {
          throw new HttpError(400, 'ARGUMENT_SCHEMA_INVALID', 'Arguments could not be normalized');
        }
        throw error;
      }

      return {
        decision_id: decision.decisionId,
        result: decision.result,
        reason_code: decision.reasonCode,
        human_message: decision.humanMessage,
        approval_id: decision.approvalId,
        expires_at: decision.expiresAt,
        policy_version: decision.policyVersion,
        permit_result: decision.permitResult,
        action_digest: decision.actionDigest,
        latency_ms: decision.latencyMs,
      };
    },
  );
}
