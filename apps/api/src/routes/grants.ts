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
import { grantRef, newId } from '@veto/core';
import { withWorkspace } from '@veto/db';
import { loadPolicies, matchPolicies, type EvaluateInput } from '@veto/decisions';
import { findAgent, writeAuditEvent } from '@veto/identity';
import {
  CALENDAR_RESOURCE,
  FILE_RESOURCE,
  FOLDER_RESOURCE,
  GITHUB_ACCOUNT_RESOURCE,
  GITHUB_REPO_RESOURCE,
  MAILBOX_RESOURCE,
  SLACK_CHANNEL_RESOURCE,
  SLACK_WORKSPACE_RESOURCE,
  OUTLOOK_MAILBOX_RESOURCE,
  OUTLOOK_CALENDAR_RESOURCE,
  type PolicyFacts,
} from '@veto/permit';
import type { KeyWrapper } from '@veto/vault';
import {
  BrokerError,
  DRIVE_READONLY_SCOPE,
  findConnectionForScope,
  GITHUB_METADATA_READ,
  type RepoReader,
  mintUpstreamToken,
  type DriveReader,
  type UpstreamTokenExchange,
} from '@veto/connections';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { edgeKey, syncFolderHierarchy, MAX_SYNC_DEPTH } from '../hierarchy.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';
import { workspacePlan } from '../workspace.ts';

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
  SLACK_WORKSPACE_RESOURCE,
  SLACK_CHANNEL_RESOURCE,
  OUTLOOK_MAILBOX_RESOURCE,
  OUTLOOK_CALENDAR_RESOURCE,
] as const;

const CONSENT_SCHEMA = {
  type: 'object',
  properties: {
    agent_id: { type: 'string' },
    resource_type: { type: 'string' },
    resource_key: { type: 'string' },
    /** Null when the grant predates audit recording, not when nobody granted it. */
    granted_by: { type: 'string', nullable: true },
    granted_at: { type: 'string', nullable: true },
    /** Null means no allowed decision names this grant — see `recording_since`. */
    last_used_at: { type: 'string', nullable: true },
    days_since_last_use: { type: 'integer', nullable: true },
    stale: { type: 'boolean' },
    /** True when the grant reaches more than the named resource. */
    inherits: { type: 'boolean' },
    /**
     * What a rule would actually permit for this grant, per action.
     *
     * A grant is only half of an answer. Step 4 denies when no rule matches,
     * before Permit is consulted at all, so a grant nothing allows reaches
     * nothing — and a page that listed it as access would be stating a fiction.
     */
    effective: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          action: { type: 'string' },
          effect: { type: 'string', enum: ['allow', 'challenge'] },
        },
        required: ['action', 'effect'],
      },
    },
    /** True when no rule matches this grant at all, so it currently grants nothing. */
    inert: { type: 'boolean' },
  },
  required: [
    'agent_id', 'resource_type', 'resource_key',
    'granted_by', 'granted_at', 'last_used_at', 'days_since_last_use', 'stale', 'inherits',
    'effective', 'inert',
  ],
} as const;

/**
 * The actions worth probing for a grant.
 *
 * `POLICY_ACTIONS` also contains `write`, which no tool can perform, and `*`,
 * which is a rule's wildcard rather than something an agent asks for. Probing
 * either would report access that cannot be exercised.
 */
const PROBE_ACTIONS = ['read', 'list', 'search'] as const;

/**
 * Unused for this long and we say so on screen.
 *
 * Not configurable yet, deliberately: one number everybody reads the same way
 * is worth more than a setting nobody changes.
 */
const STALE_AFTER_DAYS = 90;

/**
 * Grants on these reach everything beneath them, through Permit's `parent`
 * relation. The row must say so — a list that looks exhaustive and is not is
 * worse than no list, because it invites someone to conclude the other things
 * are unreachable.
 */
const CONTAINER_TYPES = new Set([FOLDER_RESOURCE, GITHUB_ACCOUNT_RESOURCE]);

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


/**
 * The shape a key must have for its resource type.
 *
 * `^[A-Za-z0-9_-]+$` is what Permit accepts, and it accepts far too much: a
 * `slack_channel` granted the key `usr_abc` passes it, is stored, is listed on
 * the screen as real access, and can never match anything — because the tool
 * asks about `C0CB5PU9SSU`. The result is a `POLICY_DENIED` with a grant
 * sitting right there appearing to permit it, which is the most confusing
 * refusal this system can produce.
 *
 * That happened. So a type whose keys have a knowable shape says so, and an
 * impossible grant is refused at creation with a message naming what was
 * expected, rather than becoming a mystery denial later.
 *
 * Drive ids are deliberately absent: their alphabet is the general one and
 * their length varies, so a pattern here would reject real ids. The four
 * user-keyed types and the two with provider-defined shapes are the ones worth
 * checking, and they are the ones that went wrong.
 */
const KEY_SHAPE: Readonly<Record<string, { readonly pattern: RegExp; readonly expected: string }>> =
  {
    // An agent can only ever reach the account of the person who delegated to
    // it, so these are a Veto user id and nothing else.
    [MAILBOX_RESOURCE]: { pattern: /^usr_[A-Za-z0-9_-]{1,64}$/, expected: 'a Veto user id (usr_…)' },
    [CALENDAR_RESOURCE]: { pattern: /^usr_[A-Za-z0-9_-]{1,64}$/, expected: 'a Veto user id (usr_…)' },
    [GITHUB_ACCOUNT_RESOURCE]: {
      pattern: /^usr_[A-Za-z0-9_-]{1,64}$/,
      expected: 'a Veto user id (usr_…)',
    },
    [SLACK_WORKSPACE_RESOURCE]: {
      pattern: /^usr_[A-Za-z0-9_-]{1,64}$/,
      expected: 'a Veto user id (usr_…)',
    },
    // Provider-defined, and stable enough to check.
    [SLACK_CHANNEL_RESOURCE]: {
      pattern: /^[CGD][A-Z0-9]{1,20}$/,
      expected: 'a Slack channel id (C…)',
    },
    [GITHUB_REPO_RESOURCE]: { pattern: /^[0-9]+$/, expected: "GitHub's numeric repository id" },
    // Microsoft's two, keyed by the delegating person for the reason Google's
    // pair is: an agent reaches the mailbox and calendar of whoever delegated
    // to it, and no argument anywhere can name somebody else's.
    [OUTLOOK_MAILBOX_RESOURCE]: {
      pattern: /^usr_[A-Za-z0-9_-]{1,64}$/,
      expected: 'a Veto user id (usr_\u2026)',
    },
    [OUTLOOK_CALENDAR_RESOURCE]: {
      pattern: /^usr_[A-Za-z0-9_-]{1,64}$/,
      expected: 'a Veto user id (usr_\u2026)',
    },
  };

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
  /** Null when the GitHub App is not configured. Its sync route then refuses. */
  readonly githubExchange?: UpstreamTokenExchange | null;
  readonly repos?: RepoReader | null;
}

/** One page is the whole answer; an installation's list is what the installer picked. */
const GITHUB_SYNC_LIMIT = 100;

/** Permit's Cloud API is slow per write, so these go a few at a time. */
const GITHUB_SYNC_CONCURRENCY = 4;

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

  /**
   * Consent Grants — what every agent may reach, and when it last did.
   *
   * Permit is the authority for what is granted; this adds two facts Permit
   * does not hold. Both already exist in Postgres and neither needed a new
   * table:
   *
   *  - **last use**, from the most recent allowed `decisions` row whose
   *    `resource_ref` matches the grant;
   *  - **provenance**, from the `grant.created` audit event, which records the
   *    actor and the time.
   *
   * The join is a string, which is the fragile part. `grantRef` is the single
   * place that formats it, and the pipeline now uses the same function — a
   * mismatch would not error, it would quietly report every grant as never
   * used, which looks exactly like a working screen.
   *
   * Read-only. Revocation stays on `DELETE /v1/grants`, which already writes
   * its own audit event.
   */
  app.get(
    '/v1/grants/consent',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              grants: { type: 'array', items: CONSENT_SCHEMA },
              stale_after_days: { type: 'integer' },
              /**
               * The oldest decision this workspace still holds. "Never used"
               * means "not since this date", which is a different claim from
               * "never" and the screen has to be able to say which.
               */
              recording_since: { type: 'string', nullable: true },
            },
            required: ['grants', 'stale_after_days', 'recording_since'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      // Checked before any work, and server-side rather than by hiding a link.
      // A badge in a sidebar is a suggestion; this is the control. 402 rather
      // than 403 because the caller is permitted to ask and the workspace is
      // simply not on the tier that answers.
      if ((await withWorkspace(deps.pool, workspaceId, (db) => workspacePlan(db, workspaceId))) !== 'pro') {
        throw new HttpError(
          402,
          'PLAN_REQUIRED',
          'Consent Grants is part of the Pro plan for this workspace',
        );
      }

      const grants = await deps.policy.listGrants(workspaceId);

      // Two queries for the whole page, not two per grant. Permit's grant list
      // is small; the decisions table is not, and a per-row query would make
      // this screen slower the longer a workspace has been running.
      const { lastUse, lineage, since, rules, timeZone } = await withWorkspace(deps.pool, workspaceId, async (db) => {
        const uses = await db.query<{ agent_id: string; resource_ref: string; at: Date }>(
          `select agent_id, resource_ref, max(created_at) as at
             from decisions
            where workspace_id = $1 and veto_result = 'allow' and resource_ref is not null
            group by agent_id, resource_ref`,
          [workspaceId],
        );

        // `<type>:<key>#agent=<id>` is what the grant route writes. The agent
        // is split off here rather than matched in SQL so the format stays
        // owned by one place.
        const created = await db.query<{ actor: string; resource_ref: string; at: Date }>(
          `select distinct on (resource_ref) actor, resource_ref, occurred_at as at
             from audit_events
            where workspace_id = $1 and event_type = 'grant.created' and resource_ref is not null
            order by resource_ref, occurred_at desc`,
          [workspaceId],
        );

        const oldest = await db.query<{ at: Date | null }>(
          `select min(created_at) as at from decisions where workspace_id = $1`,
          [workspaceId],
        );

        // Loaded once for the page. The rules are then matched in memory, with
        // the pipeline's own matcher — see the note beside the probe below.
        const rules = await loadPolicies(db, workspaceId);

        // A windowed rule is read in the workspace's own zone (migration 0020),
        // not in UTC. Reading it in the wrong zone would report a rule as shut
        // when it is open, or open when it is shut, for anybody not on UTC —
        // and only near the boundary, which is the worst way to be wrong.
        const zone = await db.query<{ timezone: string }>(
          `select timezone from workspaces where id = $1`,
          [workspaceId],
        );

        return {
          timeZone: zone.rows[0]?.timezone ?? 'UTC',
          lastUse: new Map(uses.rows.map((r) => [`${r.agent_id}\u0000${r.resource_ref}`, r.at])),
          lineage: new Map(created.rows.map((r) => [r.resource_ref, r])),
          since: oldest.rows[0]?.at ?? null,
          rules,
        };
      });

      const now = Date.now();
      const DAY_MS = 24 * 60 * 60 * 1000;

      return {
        grants: grants.map((g) => {
          const ref = grantRef(g.resourceType, g.resourceKey);
          const used = lastUse.get(`${g.agentId}\u0000${ref}`) ?? null;
          const born = lineage.get(`${ref}#agent=${g.agentId}`) ?? null;

          // Floored, so "today" reads as 0 rather than rounding up to 1.
          const days = used === null ? null : Math.floor((now - used.getTime()) / DAY_MS);

          // What a rule would actually permit, asked of the pipeline's own
          // matcher rather than a second implementation of it. A simpler
          // "does any filter match" check here would be a copy that drifts,
          // and the page disagreeing with the gateway about whether access
          // exists is worse than having no page.
          //
          // `ruleMatches` reads the agent, the action, and the resource type
          // and id. Everything else on this object is a placeholder that no
          // rule consults; it is spelled out rather than cast so a future
          // field has a defined value instead of undefined.
          const effective = PROBE_ACTIONS.flatMap((action) => {
            const probe: EvaluateInput = {
              requestId: 'req_consent_probe',
              workspaceId,
              humanId: '',
              agentId: g.agentId,
              clientId: 'consent-probe',
              tool: '',
              action,
              resource: { type: g.resourceType, id: g.resourceKey },
              arguments: {},
              declaredIntent: null,
              destination: null,
              occurredAt: new Date().toISOString(),
            };
            const verdict = matchPolicies(rules, probe, { at: new Date(), timeZone });
            return verdict.effect === 'deny' ? [] : [{ action, effect: verdict.effect }];
          });

          return {
            agent_id: g.agentId,
            resource_type: g.resourceType,
            resource_key: g.resourceKey,
            effective,
            // No rule matches any action, so step 4 refuses before Permit is
            // ever asked. The grant exists and reaches nothing.
            inert: effective.length === 0,
            granted_by: born?.actor ?? null,
            granted_at: born?.at.toISOString() ?? null,
            last_used_at: used?.toISOString() ?? null,
            days_since_last_use: days,
            // Never used counts as stale. It is the case most worth seeing:
            // access granted and then forgotten about entirely.
            stale: days === null || days >= STALE_AFTER_DAYS,
            inherits: CONTAINER_TYPES.has(g.resourceType),
          };
        }),
        stale_after_days: STALE_AFTER_DAYS,
        recording_since: since?.toISOString() ?? null,
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

      // Refused before the agent is even looked up: a key that cannot match is
      // not a question about this agent.
      const shape = KEY_SHAPE[body.resource_type];
      if (shape !== undefined && !shape.pattern.test(body.resource_key)) {
        throw new HttpError(
          400,
          'ARGUMENT_SCHEMA_INVALID',
          `A ${body.resource_type} grant needs ${shape.expected}. That value could never match, so it would appear on this screen as access and refuse every request.`,
        );
      }

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

  /**
   * Where every repository this installation can see actually lives.
   *
   * The GitHub counterpart of the folder walk, and far smaller: an installation
   * holds a flat list, bounded by what the installer picked, so there is no
   * recursion, no depth limit and no cycle to guard against. One page is the
   * whole answer.
   *
   * It writes one `parent` edge per repository, pointing at the account. That
   * is what makes a grant on the account reach the repositories under it —
   * without this, the account resource exists, the relation is declared, and
   * the inheritance reaches nothing. The dashboard offers "GitHub account — and
   * every repository under it", and this is the code that makes the sentence
   * true.
   *
   * It grants nothing. Every edge says where a repository sits, not who may
   * read it, so running it against an account nobody was granted changes
   * nobody's access.
   */
  app.post(
    '/v1/grants/github/sync',
    {
      schema: {
        body: { type: 'object', additionalProperties: false, properties: {} },
        response: {
          200: {
            type: 'object',
            properties: {
              repositories: { type: 'integer' },
              links: { type: 'integer' },
              skipped: { type: 'integer' },
              truncated: { type: 'boolean' },
            },
            required: ['repositories', 'links', 'skipped', 'truncated'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      const exchange = deps.githubExchange;
      const repos = deps.repos;
      if (!exchange || !repos) {
        throw new HttpError(
          503,
          'GITHUB_NOT_CONFIGURED',
          'GitHub is not configured on this control plane',
        );
      }

      // Found inside the workspace, so one tenant cannot enumerate another's
      // repositories by naming anything (invariant 4).
      const connection = await withWorkspace(deps.pool, workspaceId, (db) =>
        findConnectionForScope(db, workspaceId, 'github', GITHUB_METADATA_READ, userId),
      );
      if (!connection) {
        throw new HttpError(409, 'CONNECTION_UNKNOWN', 'No active GitHub connection');
      }

      let accessToken: string;
      try {
        const grant = await withWorkspace(deps.pool, workspaceId, (db) =>
          mintUpstreamToken(db, deps.wrapper, exchange, {
            workspaceId,
            connectionId: connection.id,
            // Listing repositories needs metadata and nothing else. This token
            // cannot read a file even though the installation can.
            requiredScopes: [GITHUB_METADATA_READ],
          }),
        );
        accessToken = grant.accessToken;
      } catch (error) {
        const reason = error instanceof BrokerError ? error.reason : 'EXCHANGE_FAILED';
        throw new HttpError(409, reason, 'The connected GitHub installation could not be used');
      }

      const listed = await repos.listRepos(accessToken, GITHUB_SYNC_LIMIT);

      // Written with bounded concurrency. Permit's Cloud API takes well over a
      // second per write, so twenty-five repositories serially is a request
      // that times out before it finishes.
      let links = 0;
      const queue = [...listed];
      const workers = Array.from({ length: GITHUB_SYNC_CONCURRENCY }, async () => {
        for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
          if (next.id === '') continue;
          await deps.policy.recordParent({
            workspaceId,
            childType: GITHUB_REPO_RESOURCE,
            childKey: next.id,
            // The account is keyed by the Veto user id, not the GitHub login —
            // the same key `normalize` builds for `list_repos`, so the edge
            // lands where the decision will look for it.
            parentKey: userId,
            parentType: GITHUB_ACCOUNT_RESOURCE,
          });
          links += 1;
        }
      });
      await Promise.all(workers);

      await withWorkspace(deps.pool, workspaceId, (db) =>
        writeAuditEvent(db, {
          workspaceId,
          actor: userId,
          eventType: 'grant.hierarchy_synced',
          resourceRef: `${GITHUB_ACCOUNT_RESOURCE}:${userId}#links=${String(links)}`,
          outcome: 'lifecycle',
          correlationId: String(request.id),
        }),
      );

      return {
        repositories: listed.length,
        links,
        skipped: 0,
        truncated: listed.length >= GITHUB_SYNC_LIMIT,
      };
    },
  );

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
