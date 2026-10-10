/**
 * Which software has been connecting as each agent, and what to do about it.
 *
 * The screen behind these routes answers one question an audit timeline cannot:
 * *has the thing using this credential changed?* The timeline records every
 * decision; this records who was asking.
 *
 * ## What it is honestly worth
 *
 * Everything here derives from a `User-Agent`, which is a string the client
 * chose to send. A thief holding a gateway token can send the same one. This is
 * change detection, not authentication, and the dashboard copy says so — a
 * screen that implied a check it is not performing would be worse than no
 * screen, which is the same lesson the GitHub installation comment taught.
 *
 * ## Why this is a paid screen, and where the gate sits
 *
 * Like `/v1/grants/consent`, the refusal happens **before** any work: 402, then
 * nothing. The sidebar hiding a link is not a control, because anybody can type
 * a URL, and a gate applied after the queries have run has already spent them.
 */

import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import {
  listAgents,
  listFingerprints,
  setFingerprintMode,
  setFingerprintStatus,
  writeAuditEvent,
  type FingerprintMode,
  type FingerprintStatus,
} from '@veto/identity';
import { grantRef } from '@veto/core';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';
import { assertWorkspaceUnlocked, workspacePlan } from '../workspace.ts';

export interface FingerprintRoutesDeps {
  readonly pool: Pool;
}

const MODES: readonly FingerprintMode[] = ['observe', 'challenge', 'deny'];
const STATUSES: readonly FingerprintStatus[] = ['pinned', 'seen', 'refused'];

const AGENT_ID_PARAMS = {
  type: 'object',
  additionalProperties: false,
  required: ['agentId'],
  properties: {
    agentId: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{1,64}$' },
  },
} as const;

const FINGERPRINT_SCHEMA = {
  type: 'object',
  properties: {
    fingerprint: { type: 'string' },
    product: { type: 'string' },
    channel: { type: 'string', nullable: true },
    first_version: { type: 'string', nullable: true },
    last_version: { type: 'string', nullable: true },
    client_title: { type: 'string', nullable: true },
    protocol_version: { type: 'string', nullable: true },
    status: { type: 'string' },
    first_seen_at: { type: 'string' },
    last_seen_at: { type: 'string' },
    sightings: { type: 'integer' },
  },
  required: ['fingerprint', 'product', 'status', 'first_seen_at', 'last_seen_at', 'sightings'],
} as const;

const LIST_SCHEMA = {
  type: 'object',
  properties: {
    agents: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          agent_id: { type: 'string' },
          client_id: { type: 'string' },
          provider: { type: 'string' },
          status: { type: 'string' },
          fingerprint_mode: { type: 'string' },
          fingerprints: { type: 'array', items: FINGERPRINT_SCHEMA },
        },
        required: ['agent_id', 'client_id', 'provider', 'status', 'fingerprint_mode', 'fingerprints'],
      },
    },
  },
  required: ['agents'],
} as const;

export function registerFingerprintRoutes(app: FastifyInstance, deps: FingerprintRoutesDeps): void {
  /** Refuse before doing anything, and say which tier answers. */
  async function requirePro(workspaceId: string): Promise<void> {
    const plan = await withWorkspace(deps.pool, workspaceId, (db) => workspacePlan(db, workspaceId));
    if (plan !== 'pro') {
      throw new HttpError(
        402,
        'PLAN_REQUIRED',
        'Agent Fingerprints is part of the Pro plan for this workspace',
      );
    }
  }

  app.get(
    '/v1/agents/fingerprints',
    {
      schema: {
        response: { 200: LIST_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      await requirePro(workspaceId);

      // Revoked agents stay listed. What a now-dead agent was being used by is
      // exactly the question asked after an incident, and dropping the row
      // would delete the evidence along with the access.
      return withWorkspace(deps.pool, workspaceId, async (db) => {
        const agents = await listAgents(db, workspaceId);

        // One query per agent, and bounded: an agent holds at most
        // MAX_FINGERPRINTS_PER_AGENT rows, and a workspace's agent list is
        // small. A single join would be one round trip but would need the
        // grouping unpicked again on this side.
        const rows = await Promise.all(
          agents.map(async (agent) => ({
            agent_id: agent.id,
            client_id: agent.client_id,
            provider: agent.provider,
            status: agent.status,
            fingerprint_mode: agent.fingerprint_mode,
            fingerprints: (await listFingerprints(db, workspaceId, agent.id)).map((f) => ({
              fingerprint: f.fingerprint,
              product: f.product,
              channel: f.channel,
              first_version: f.first_version,
              last_version: f.last_version,
              client_title: f.client_title,
              protocol_version: f.protocol_version,
              status: f.status,
              first_seen_at: f.first_seen_at.toISOString(),
              last_seen_at: f.last_seen_at.toISOString(),
              // `bigint` arrives as a string from pg. Narrowed here so the
              // response schema can promise an integer.
              sightings: Number(f.sightings),
            })),
          })),
        );

        return { agents: rows };
      });
    },
  );

  app.post(
    '/v1/agents/:agentId/fingerprint-mode',
    {
      schema: {
        params: AGENT_ID_PARAMS,
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['mode'],
          properties: { mode: { type: 'string', enum: MODES } },
        },
        response: {
          200: {
            type: 'object',
            properties: { agent_id: { type: 'string' }, fingerprint_mode: { type: 'string' } },
            required: ['agent_id', 'fingerprint_mode'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const { agentId } = request.params as { agentId: string };
      const { mode } = request.body as { mode: FingerprintMode };

      await requirePro(workspaceId);

      return withWorkspace(deps.pool, workspaceId, async (db) => {
        // Raising enforcement narrows and would be safe under a lock; lowering
        // it widens. One rule for both, because an attacker who has triggered
        // a lock response must not be able to turn a control off while the
        // operator is still dealing with it.
        await assertWorkspaceUnlocked(db, workspaceId);

        if (!(await setFingerprintMode(db, workspaceId, agentId, mode))) {
          throw new HttpError(404, 'NOT_FOUND', 'No such agent');
        }

        await writeAuditEvent(db, {
          workspaceId,
          actor: userId,
          eventType: 'agent.fingerprint_mode_set',
          resourceRef: grantRef('agent', agentId),
          outcome: 'lifecycle',
        });

        return { agent_id: agentId, fingerprint_mode: mode };
      });
    },
  );

  app.post(
    '/v1/agents/:agentId/fingerprints',
    {
      schema: {
        params: AGENT_ID_PARAMS,
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['fingerprint', 'status'],
          properties: {
            // The digest's own grammar, so a malformed value is a 400 that
            // explains itself rather than an update matching nothing.
            fingerprint: { type: 'string', pattern: '^sha256:[0-9a-f]{64}$' },
            status: { type: 'string', enum: STATUSES },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: { fingerprint: { type: 'string' }, status: { type: 'string' } },
            required: ['fingerprint', 'status'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const { agentId } = request.params as { agentId: string };
      const body = request.body as { fingerprint: string; status: FingerprintStatus };

      await requirePro(workspaceId);

      return withWorkspace(deps.pool, workspaceId, async (db) => {
        // `pinned` widens — it is what lets a client through an enforcing mode
        // — so it is refused under a lock. `refused` only narrows, and a lock
        // is precisely when an operator needs to cut something off.
        if (body.status !== 'refused') await assertWorkspaceUnlocked(db, workspaceId);

        // Only a fingerprint already on file can be judged. There is no way to
        // pin a digest nobody has seen: that would be a guess, and the value is
        // not one anybody can be expected to type correctly.
        const changed = await setFingerprintStatus(db, {
          workspaceId,
          agentId,
          fingerprint: body.fingerprint,
          status: body.status,
        });
        if (!changed) {
          throw new HttpError(404, 'NOT_FOUND', 'No such fingerprint for this agent');
        }

        await writeAuditEvent(db, {
          workspaceId,
          actor: userId,
          eventType: `agent.fingerprint_${body.status}`,
          resourceRef: grantRef('agent', agentId),
          outcome: 'lifecycle',
        });

        return { fingerprint: body.fingerprint, status: body.status };
      });
    },
  );
}
