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
import { newId } from '@veto/core';
import { withWorkspace } from '@veto/db';
import { findAgent, writeAuditEvent } from '@veto/identity';
import {
  CALENDAR_RESOURCE,
  FILE_RESOURCE,
  FOLDER_RESOURCE,
  GITHUB_ACCOUNT_RESOURCE,
  GITHUB_REPO_RESOURCE,
  MAILBOX_RESOURCE,
  type PolicyFacts,
} from '@veto/permit';
import type { KeyWrapper } from '@veto/vault';
import {
  BrokerError,
  DRIVE_READONLY_SCOPE,
  findConnectionForScope,
  mintUpstreamToken,
  type DriveReader,
  type UpstreamTokenExchange,
} from '@veto/connections';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { edgeKey, syncFolderHierarchy, MAX_SYNC_DEPTH } from '../hierarchy.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

/** Only what the tool catalogue can actually ask about. */
/**
 * A folder walk, as a caller sees it.
 *
 * The same shape whether it has just started or finished an hour ago, so a
 * client polls one endpoint and reads one thing. `status` is the only field
 * that decides whether the numbers are final.
 */
const SYNC_JOB_SCHEMA = {
  type: 'object',
  required: ['id', 'status', 'folder_id', 'folders', 'links', 'truncated', 'depth'],
  properties: {
    id: { type: 'string' },
    status: { type: 'string', enum: ['running', 'done', 'failed'] },
    folder_id: { type: 'string' },
    folders: { type: 'integer' },
    links: { type: 'integer' },
    truncated: { type: 'boolean' },
    /** A sentence for whoever pressed the button, or null. */
    error: { type: 'string', nullable: true },
    depth: { type: 'integer' },
    started_at: { type: 'string' },
    finished_at: { type: 'string', nullable: true },
  },
} as const;

interface SyncJobRow {
  id: string;
  status: 'running' | 'done' | 'failed';
  folder_id: string;
  folders: number;
  links: number;
  truncated: boolean;
  error: string | null;
  started_at: Date;
  finished_at: Date | null;
}

const asJob = (row: SyncJobRow) => ({
  id: row.id,
  status: row.status,
  folder_id: row.folder_id,
  folders: row.folders,
  links: row.links,
  truncated: row.truncated,
  error: row.error,
  depth: MAX_SYNC_DEPTH,
  started_at: row.started_at.toISOString(),
  finished_at: row.finished_at?.toISOString() ?? null,
});

const GRANTABLE = [
  FOLDER_RESOURCE,
  FILE_RESOURCE,
  MAILBOX_RESOURCE,
  CALENDAR_RESOURCE,
  GITHUB_ACCOUNT_RESOURCE,
  GITHUB_REPO_RESOURCE,
] as const;

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
          200: SYNC_JOB_SCHEMA,
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
      // Must be a connection that actually carries Drive. Consent is per
      // service, so the newest Google connection is often a Gmail or Calendar
      // one, and a walk asking it for Drive fails as an expired credential.
      const connection = await withWorkspace(deps.pool, workspaceId, (db) =>
        findConnectionForScope(db, workspaceId, 'google', DRIVE_READONLY_SCOPE),
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

      // One walk per workspace. A second request while one is running is
      // answered with the one already going: two walks would write the same
      // facts twice, more slowly, against the same rate limit.
      const running = await withWorkspace(deps.pool, workspaceId, (db) =>
        db.query<SyncJobRow>(
          `select id, status, folder_id, folders, links, truncated, error, started_at, finished_at
             from hierarchy_syncs where workspace_id = $1 and status = 'running' limit 1`,
          [workspaceId],
        ),
      );
      const live = running.rows[0];
      if (live) return asJob(live);

      // Claim the slot. The select above is a courtesy, not the guard — two
      // requests can pass it together, and then the partial unique index is
      // what decides. Losing that race is not an error: it means somebody else
      // started the walk a moment ago, which is the outcome either caller
      // wanted.
      const jobId = newId('hsy_');
      const claimed = await withWorkspace(deps.pool, workspaceId, (db) =>
        db.query<{ id: string }>(
          `insert into hierarchy_syncs (id, workspace_id, started_by, folder_id)
           values ($1,$2,$3,$4)
           on conflict (workspace_id) where status = 'running'
           do nothing
           returning id`,
          [jobId, workspaceId, userId, folderId],
        ),
      );

      if (!claimed.rows[0]) {
        const theirs = await withWorkspace(deps.pool, workspaceId, (db) =>
          db.query<SyncJobRow>(
            `select id, status, folder_id, folders, links, truncated, error, started_at, finished_at
               from hierarchy_syncs where workspace_id = $1 and status = 'running' limit 1`,
            [workspaceId],
          ),
        );
        const row = theirs.rows[0];
        if (row) return asJob(row);

        // It finished between the conflict and this read — a walk fast enough
        // to start and end inside one request. Report the one that just ran
        // rather than starting another: the facts it wrote are the facts this
        // caller asked for.
        const latest = await withWorkspace(deps.pool, workspaceId, (db) =>
          db.query<SyncJobRow>(
            `select id, status, folder_id, folders, links, truncated, error, started_at, finished_at
               from hierarchy_syncs where workspace_id = $1 order by started_at desc limit 1`,
            [workspaceId],
          ),
        );
        const recent = latest.rows[0];
        if (recent) return asJob(recent);
        throw new HttpError(409, 'CONNECTION_UNKNOWN', 'A folder walk is already running');
      }

      // Deliberately not awaited. The walk writes one fact per entry to
      // Permit's cloud API — a minute's work on a large folder even eight at a
      // time — and no browser or proxy waits that long. The request that asked
      // for it is answered now; the job row is where the answer lands.
      //
      // `void` rather than a floating promise: every path inside settles the
      // row, so a rejection here would be a second report of something already
      // recorded.
      // Collected as they succeed, saved whether or not the walk finishes.
      //
      // Declared out here on purpose. When this lived inside the try, a walk
      // that died part-way saved nothing — 384 edges had been accepted by
      // Permit and every one was forgotten, so the next attempt paid for them
      // again and hit the same rate limit at the same point. Progress that is
      // only recorded on success is not progress.
      const fresh: Array<[string, string, string]> = [];

      const remember = async (): Promise<void> => {
        if (fresh.length === 0) return;
        await withWorkspace(deps.pool, workspaceId, (db) =>
          db.query(
            `insert into hierarchy_edges (workspace_id, child_type, child_key, parent_key)
             select $1, * from unnest($2::text[], $3::text[], $4::text[])
             on conflict do nothing`,
            [workspaceId, fresh.map((e) => e[0]), fresh.map((e) => e[1]), fresh.map((e) => e[2])],
          ),
        );
        fresh.length = 0;
      };

      void (async () => {
        try {
          // What Permit has already been told, read once. A repeat walk of an
          // unchanged folder then costs this one query and no upstream calls.
          const cached = await withWorkspace(deps.pool, workspaceId, (db) =>
            db.query<{ child_type: string; child_key: string; parent_key: string }>(
              `select child_type, child_key, parent_key from hierarchy_edges
                where workspace_id = $1`,
              [workspaceId],
            ),
          );
          const known = new Set(
            cached.rows.map((r) => edgeKey(r.child_type, r.child_key, r.parent_key)),
          );

          const report = await syncFolderHierarchy(
            {
              drive: deps.drive,
              facts: deps.policy,
              known,
              onWritten: (childType, childKey, parentKey) => {
                fresh.push([childType, childKey, parentKey]);
              },
            },
            { workspaceId, accessToken, folderId },
          );

          await remember();
          await withWorkspace(deps.pool, workspaceId, async (db) => {
            await db.query(
              `update hierarchy_syncs
                  set status = 'done', folders = $2, links = $3, truncated = $4,
                      finished_at = now()
                where id = $1`,
              [jobId, report.folders, report.links, report.truncated],
            );
            // Counts only. What was found is a map of somebody's Drive, and
            // file names are protected content — invariant 5 keeps them out of
            // the trail as firmly as it keeps out document bodies.
            await writeAuditEvent(db, {
              workspaceId,
              actor: userId,
              eventType: 'grant.hierarchy_synced',
              resourceRef: `${FOLDER_RESOURCE}:${folderId}#links=${report.links}`,
              outcome: 'lifecycle',
              correlationId: String(request.id),
            });
          });
        } catch (error) {
          // Keep what was accepted before it stopped. Rate limits are the
          // common failure here, and a retry that skips everything already
          // written gets further than the one before it — which is the
          // difference between a walk that eventually finishes and one that
          // can never finish at all.
          await remember().catch(() => undefined);

          // A sentence, not a stack: this is read by whoever pressed the
          // button. Upstream errors can echo the request, which carried a
          // token, so the message is ours rather than theirs.
          request.log.error({ err: error, jobId }, 'hierarchy sync failed');
          await withWorkspace(deps.pool, workspaceId, (db) =>
            db.query(
              `update hierarchy_syncs
                  set status = 'failed', error = $2, finished_at = now()
                where id = $1`,
              [jobId, 'The walk could not be completed. Check the connected account and try again.'],
            ),
          ).catch(() => {
            // Nothing left to do: the row stays 'running' and reads as stale.
          });
        }
      })();

      return {
        id: jobId,
        status: 'running' as const,
        folder_id: folderId,
        folders: 0,
        links: 0,
        truncated: false,
        error: null,
        depth: MAX_SYNC_DEPTH,
        started_at: new Date().toISOString(),
        finished_at: null,
      };
    },
  );

  /**
   * How a walk is going, or how it went.
   *
   * No id: the latest walk for this workspace, which is what a screen that just
   * started one wants. There is at most one running at a time, so "the latest"
   * is unambiguous while it matters.
   */
  app.get(
    '/v1/grants/sync',
    {
      schema: {
        response: { 200: SYNC_JOB_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      const { rows } = await withWorkspace(deps.pool, workspaceId, (db) =>
        db.query<SyncJobRow>(
          `select id, status, folder_id, folders, links, truncated, error, started_at, finished_at
             from hierarchy_syncs where workspace_id = $1
            order by started_at desc limit 1`,
          [workspaceId],
        ),
      );

      const row = rows[0];
      if (!row) throw new HttpError(404, 'NOT_FOUND', 'No folder walk has been run yet');
      return asJob(row);
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
