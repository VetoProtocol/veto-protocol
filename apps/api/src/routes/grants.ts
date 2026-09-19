/**
 * /v1/grants — connecting an agent to a resource (spec §4.4).
 *
 * The other half of an allow, and the half that was missing. A Veto policy rule
 * says *under what conditions* an agent may act; this says whether the agent is
 * connected to the thing at all. Both must agree, and they are deliberately not
 * derived from each other — see the note on `ResourceGrant` for why deriving
 * one from the other would turn Permit into a mirror of Veto.
 *
 * ## This route writes to Permit and not to Postgres
 *
 * There is no local grants table. A mirror would drift, and the question "what
 * is this agent connected to" would then have two answers that disagree during
 * exactly the incident where it matters. Listing is therefore a Permit call and
 * is slower than a database read; it is a control-plane page, not the hot path.
 *
 * Every failure is a denial (invariant 1). `PolicyUnavailableError` maps to 503
 * in `app.ts`, so an unreachable Permit refuses the grant rather than reporting
 * a success it did not achieve.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import { findAgent, writeAuditEvent } from '@veto/identity';
import {
  CALENDAR_RESOURCE,
  FILE_RESOURCE,
  FOLDER_RESOURCE,
  MAILBOX_RESOURCE,
  type PolicyFacts,
} from '@veto/permit';
import type { KeyWrapper } from '@veto/vault';
import {
  BrokerError,
  DRIVE_READONLY_SCOPE,
  listConnections,
  mintUpstreamToken,
  type DriveReader,
  type UpstreamTokenExchange,
} from '@veto/connections';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { syncFolderHierarchy, MAX_SYNC_DEPTH } from '../hierarchy.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

/** Only what the tool catalogue can actually ask about. */
const GRANTABLE = [FOLDER_RESOURCE, FILE_RESOURCE, MAILBOX_RESOURCE, CALENDAR_RESOURCE] as const;

const GRANT_SCHEMA = {
  type: 'object',
  properties: {
    agent_id: { type: 'string' },
    resource_type: { type: 'string' },
    resource_key: { type: 'string' },
  },
  required: ['agent_id', 'resource_type', 'resource_key'],
} as const;

const BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['agent_id', 'resource_type', 'resource_key'],
  properties: {
    agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{1,64}$' },
    // No wildcard. A grant is a statement about one named thing; "everything"
    // is expressed by granting the folder that contains it, which inherits.
    resource_type: { type: 'string', enum: [...GRANTABLE] },
    // Permit validates resource-instance keys against ^[A-Za-z0-9\-_]+$ and
    // answers 422 for anything else — the same kind of surprise as the colon in
    // user keys (see model.ts). Enforcing it here turns a confusing upstream
    // 422 into a 400 that says which character is the problem.
    //
    // Real Google Drive ids are exactly this alphabet, and so is a Veto user id
    // — which is what a `gmail_mailbox` key is. A *path* like `/Work/plan.txt`
    // is not a Drive id and is refused; see `docs/grants.md`.
    resource_key: { type: 'string', minLength: 1, maxLength: 512, pattern: '^[A-Za-z0-9_-]+$' },
  },
} as const;

interface Body {
  agent_id: string;
  resource_type: string;
  resource_key: string;
}

export interface GrantRoutesDeps {
  readonly pool: Pool;
  readonly policy: PolicyFacts;
  /** Unwraps the stored Google credential so the folder can be walked. */
  readonly wrapper: KeyWrapper;
  /** Null when Google is not configured. The sync route then refuses. */
  readonly exchange: UpstreamTokenExchange | null;
  readonly drive: DriveReader;
}

const SYNC_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['folder_id'],
  properties: {
    // Same grammar as a grant's resource_key, because it names the same thing.
    // `root` is Drive's own alias for the top of a My Drive.
    folder_id: { type: 'string', minLength: 1, maxLength: 512, pattern: '^[A-Za-z0-9_-]+$' },
  },
} as const;

interface SyncBody {
  folder_id: string;
}

export function registerGrantRoutes(app: FastifyInstance, deps: GrantRoutesDeps): void {
  app.get(
    '/v1/grants',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: { grants: { type: 'array', items: GRANT_SCHEMA } },
            required: ['grants'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      const grants = await deps.policy.listGrants(workspaceId);

      return {
        grants: grants.map((g) => ({
          agent_id: g.agentId,
          resource_type: g.resourceType,
          resource_key: g.resourceKey,
        })),
      };
    },
  );

  app.post(
    '/v1/grants',
    {
      schema: {
        body: BODY,
        response: { 201: GRANT_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: Body }>, reply) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const body = request.body;

      // The agent must exist here, and be live. Granting to an id from another
      // workspace would write a Permit fact this tenant can never see and never
      // clean up (invariant 4); granting to a revoked agent would hand back
      // something somebody deliberately took away.
      const agent = await withWorkspace(deps.pool, workspaceId, (db) =>
        findAgent(db, workspaceId, body.agent_id),
      );
      if (!agent) throw new HttpError(404, 'AGENT_UNKNOWN', 'No such agent in this workspace');
      if (agent.status !== 'active') {
        throw new HttpError(409, 'AGENT_REVOKED', 'That agent is not active');
      }

      await deps.policy.grantResource({
        workspaceId,
        agentId: body.agent_id,
        resourceType: body.resource_type,
        resourceKey: body.resource_key,
      });

      // Audited after the grant lands, so the trail never claims access that
      // was not actually written.
      await withWorkspace(deps.pool, workspaceId, (db) =>
        writeAuditEvent(db, {
          workspaceId,
          actor: userId,
          eventType: 'grant.created',
          resourceRef: `${body.resource_type}:${body.resource_key}#agent=${body.agent_id}`,
          outcome: 'lifecycle',
          correlationId: String(request.id),
        }),
      );

      return reply.code(201).send({
        agent_id: body.agent_id,
        resource_type: body.resource_type,
        resource_key: body.resource_key,
      });
    },
  );

  /**
   * Record where the files under a folder actually live.
   *
   * Separate from `POST /v1/grants` on purpose. A grant is a decision somebody
   * made and needs nothing but Permit; this needs Drive to be reachable and a
   * live Google connection. Folding them together would mean a Drive outage
   * blocks a grant that has nothing to do with Drive — and would leave a
   * half-finished walk behind whenever the credential expired mid-sync.
   *
   * It grants nothing. Every edge it writes says where a file is, not who may
   * read it, so running it against a folder nobody was granted changes nobody's
   * access. That is what makes it safe to expose as its own operation.
   */
  app.post(
    '/v1/grants/sync',
    {
      schema: {
        body: SYNC_BODY,
        response: {
          200: {
            type: 'object',
            required: ['folders', 'links', 'truncated', 'depth'],
            properties: {
              folders: { type: 'integer' },
              links: { type: 'integer' },
              truncated: { type: 'boolean' },
              depth: { type: 'integer' },
            },
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Body: SyncBody }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const { folder_id: folderId } = request.body;

      if (deps.exchange === null) {
        throw new HttpError(
          503,
          'GOOGLE_NOT_CONFIGURED',
          'Google is not configured on this control plane',
        );
      }

      // The connection is found inside the workspace, so one tenant cannot walk
      // another tenant's Drive by naming a folder id (invariant 4). Drive ids
      // are globally unique and unguessable, which is not the same as being a
      // boundary.
      const connections = await withWorkspace(deps.pool, workspaceId, (db) =>
        listConnections(db, workspaceId),
      );
      const connection = connections.find(
        (c) => c.provider === 'google' && c.status === 'active',
      );
      if (!connection) {
        throw new HttpError(409, 'CONNECTION_UNKNOWN', 'No active Google connection');
      }

      let accessToken: string;
      try {
        const grant = await withWorkspace(deps.pool, workspaceId, (db) =>
          mintUpstreamToken(db, deps.wrapper, deps.exchange as UpstreamTokenExchange, {
            workspaceId,
            connectionId: connection.id,
            // Read-only, and Drive only. Walking a folder is a read even though
            // what it produces is a policy fact.
            requiredScopes: [DRIVE_READONLY_SCOPE],
          }),
        );
        accessToken = grant.accessToken;
      } catch (error) {
        const reason = error instanceof BrokerError ? error.reason : 'EXCHANGE_FAILED';
        throw new HttpError(409, reason, 'The connected Google account could not be used');
      }

      const report = await syncFolderHierarchy(
        { drive: deps.drive, facts: deps.policy },
        { workspaceId, accessToken, folderId },
      );

      // Counts only. What was found is a map of somebody's Drive, and file
      // names are protected content — invariant 5 keeps them out of the trail
      // as firmly as it keeps out document bodies.
      await withWorkspace(deps.pool, workspaceId, (db) =>
        writeAuditEvent(db, {
          workspaceId,
          actor: userId,
          eventType: 'grant.hierarchy_synced',
          resourceRef: `${FOLDER_RESOURCE}:${folderId}#links=${report.links}`,
          outcome: 'lifecycle',
          correlationId: String(request.id),
        }),
      );

      return { ...report, depth: MAX_SYNC_DEPTH };
    },
  );

  app.delete(
    '/v1/grants',
    {
      schema: {
        // A DELETE with a body, because the thing being deleted is a triple and
        // there is no id to put in a path. The alternative — three query
        // parameters carrying a resource key that can contain slashes — is
        // worse to get right.
        body: BODY,
        response: {
          200: {
            type: 'object',
            properties: { revoked: { type: 'boolean' } },
            required: ['revoked'],
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

      // No existence check. Removing a grant narrows what is possible, so it is
      // safe to run against an agent that is already gone — and a revoked agent
      // whose grants are still attached is exactly the state worth being able
      // to clean up.
      await deps.policy.revokeResource({
        workspaceId,
        agentId: body.agent_id,
        resourceType: body.resource_type,
        resourceKey: body.resource_key,
      });

      await withWorkspace(deps.pool, workspaceId, (db) =>
        writeAuditEvent(db, {
          workspaceId,
          actor: userId,
          eventType: 'grant.revoked',
          resourceRef: `${body.resource_type}:${body.resource_key}#agent=${body.agent_id}`,
          outcome: 'lifecycle',
          correlationId: String(request.id),
        }),
      );

      return { revoked: true };
    },
  );
}
