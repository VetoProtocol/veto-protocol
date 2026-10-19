/**
 * The authorization decision pipeline (spec §3.3).
 *
 * Nine steps, in the order the spec fixes them. A component that skips its
 * position is a security defect regardless of its tests, so the order here is
 * load-bearing and the comments say why each step sits where it does.
 *
 * ## How the three results combine
 *
 * A `deny` short-circuits immediately: nothing later can make a refusal
 * weaker, and there are things later steps must *not* do once a denial is
 * known — an emergency lock must not result in Permit being consulted at all,
 * and a locked workspace must not spend volume budget.
 *
 * A `challenge` is held and the pipeline continues. If a later step denies, the
 * denial wins. Challenge is not "allow with a form"; it is the least
 * permissive answer that is not an outright no, and a stricter answer always
 * replaces it.
 *
 * ## What is not here
 *
 * Step 8 — minting the upstream token and making the call — belongs to phase 5.
 * This pipeline decides; it never fetches. An `allow` from here means "you may",
 * not "it happened".
 */

import { randomBytes } from 'node:crypto';
import {
  actionDigest,
  newId,
  describeReason,
  grantRef,
  CURRENT_LEGAL_VERSIONS,
  LEGAL_DOCUMENTS,
  type DigestibleValue,
} from '@veto/core';
import type { Db } from '@veto/db';
import { enqueue } from '@veto/webhooks';
import { withWorkspace } from '@veto/db';
import {
  writeAuditEvent,
  findAgent,
  fingerprintStanding,
  fingerprintModeOf,
} from '@veto/identity';
import type { PolicyDecisions, PermitOutcome } from '@veto/permit';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { DecisionResponse, EvaluateInput } from './types.ts';
import { loadPolicies, matchPolicies } from './policy-store.ts';
import {
  DEFAULT_SENSITIVITY,
  loadLabels,
  matchLabel,
  requirementFor,
  type Sensitivity,
} from './labels.ts';
import { assessRisk } from './risk.ts';
import { findApprovedForDigest, redeemApproval } from './approvals.ts';
import { readPresence } from '@veto/presence';
import { currentUsage, reserve } from './volume.ts';
import { createStepClock, type StepTimings } from './timing.ts';

export interface PipelineDeps {
  readonly pool: Pool;
  readonly redis: Redis;
  readonly policy: PolicyDecisions;
  /** How long an approval stays open. §5.2 shows minutes, not hours. */
  readonly approvalTtlMs?: number;
  /**
   * Where the dashboard lives, for the link on an approval alert.
   *
   * Configuration, never derived from a request: a caller that could name this
   * origin could put its own address in an alert the delegating user is about
   * to click. Absent means the alert carries no link, which is the honest
   * degradation — a missing link costs convenience, a wrong one costs trust.
   */
  readonly dashboardUrl?: string | null;
}

interface Outcome {
  readonly result: 'allow' | 'deny' | 'challenge';
  readonly reasonCode: string;
}

const deny = (reasonCode: string): Outcome => ({ result: 'deny', reasonCode });
const challenge = (reasonCode: string): Outcome => ({ result: 'challenge', reasonCode });

export async function evaluate(deps: PipelineDeps, input: EvaluateInput): Promise<DecisionResponse> {
  const started = process.hrtime.bigint();
  // Where the time goes, beside how much of it there was. `latency_ms` answers
  // whether §11's budget was met; this answers which step to look at when it
  // was not.
  const clock = createStepClock();
  const decisionId = newId('dec_');

  // Step 2 — normalise, and bind the whole thing to a digest.
  //
  // Computed before any check runs, so every later step and any approval that
  // follows refer to the same immutable action. A changed argument produces a
  // different digest and therefore needs a new approval (invariants 6, 7).
  const digest = actionDigest({
    workspace_id: input.workspaceId,
    human_id: input.humanId,
    agent_id: input.agentId,
    client_id: input.clientId,
    tool: input.tool,
    action: input.action,
    resource: { type: input.resource.type, id: input.resource.id },
    // The digest rejects anything it cannot represent unambiguously — undefined,
    // NaN, functions, cycles — so a malformed argument set fails here rather
    // than producing a digest two different requests could share.
    arguments: input.arguments as { readonly [key: string]: DigestibleValue },
    declared_intent: input.declaredIntent,
    destination: input.destination,
  });

  // UTC until step 3 reads the workspace's own. A rule with a window is treated
  // as shut while this is unknown, so a failure to read it narrows rather than
  // widens.
  let timeZone = 'UTC';
  let permitResult: PermitOutcome | 'not_evaluated' = 'not_evaluated';
  let held: Outcome | null = null;
  let policyVersion: string | null = null;
  let sensitivity: Sensitivity = DEFAULT_SENSITIVITY;

  const outcome = await (async (): Promise<Outcome> => {
    // Step 3 — session, presence, expiry, emergency lock.
    //
    // First, and before Permit is reachable from here. A locked workspace is
    // Veto's answer alone (invariant 3), and asking Permit during a lock would
    // both waste the budget and imply the answer could matter.
    const gate = await clock.time('session', () =>
      withWorkspace(deps.pool, input.workspaceId, async (db) => {
      // The zone comes from the same row as the lock, on the same round trip.
      // A rule saying "09:00" means nine where the workspace is, and step 4
      // cannot read that without it.
      const { rows } = await db.query<{ emergency_lock: boolean; timezone: string }>(
        `select emergency_lock, timezone from workspaces where id = $1`,
        [input.workspaceId],
      );
      const workspace = rows[0];
      if (!workspace) return deny('IDENTITY_UNRESOLVED');
      if (workspace.emergency_lock) return deny('WORKSPACE_LOCKED');
      timeZone = workspace.timezone;

      const agent = await findAgent(db, input.workspaceId, input.agentId);
      if (!agent) return deny('AGENT_UNKNOWN');
      if (agent.status === 'revoked') return deny('AGENT_REVOKED');
      if (agent.status !== 'active') return deny('AGENT_REVOKED');
      if (agent.owner_user_id !== input.humanId) return deny('IDENTITY_UNRESOLVED');

      // Is the software using this agent the software we know?
      //
      // Step 3 because this is session standing — a fact about who is calling,
      // like the agent's own status and the emergency lock — and not a fact
      // about the request, which is what step 6 judges. It also means Permit is
      // never consulted about a client this workspace has refused, the same
      // reasoning the lock already uses.
      //
      // Skipped entirely in `observe`, which is every agent's default. A
      // workspace that has not turned this on spends nothing on it, and this
      // is the branch that keeps that promise literal: `observe` cannot change
      // an answer because in `observe` nothing is even read.
      // Read through a normaliser, never off the row directly: see
      // `fingerprintModeOf` for why an absent column must mean `observe`.
      const fingerprintMode = fingerprintModeOf(agent);
      if (fingerprintMode !== 'observe') {
        // A request that named no client is not pinned. Absence narrows, as it
        // does for presence and for an unreadable schedule — and a `null`
        // fingerprint reaching an enforcing agent means the caller was not an
        // MCP session at all.
        const standing =
          typeof input.clientFingerprint === 'string' && input.clientFingerprint !== ''
            ? await fingerprintStanding(db, input.workspaceId, input.agentId, input.clientFingerprint)
            : null;

        if (standing === 'refused') return deny('AGENT_FINGERPRINT_REJECTED');

        if (standing !== 'pinned') {
          // `deny` refuses outright; `challenge` holds and lets the rest of the
          // pipeline run, because a later denial must still win over it. Held
          // rather than returned for exactly the reason the presence gate is:
          // challenge is the least permissive answer that is not a refusal,
          // and anything stricter replaces it.
          if (fingerprintMode === 'deny') return deny('AGENT_FINGERPRINT_REJECTED');
          held = challenge('AGENT_FINGERPRINT_UNRECOGNISED');
        }
      }

      // Has the person this agent acts for agreed to the current terms?
      //
      // Step 3 because this is a fact about the human's standing, like the
      // emergency lock and session expiry — not a policy question. Putting it
      // in step 4 or 5 would mean Permit is consulted about an account that is
      // not permitted to be acting at all, and a control that runs at the wrong
      // step is a defect however well it tests.
      //
      // Counted rather than fetched: this runs on every protected call and the
      // §11 budget is 200 ms. One indexed count on (workspace_id, user_id) is
      // the cheapest true answer.
      //
      // It fails closed by arithmetic — a row that is missing, a version that
      // moved on, a workspace that was never asked — all produce a count below
      // the required one, and all deny. There is no branch here that can decide
      // to let somebody through.
      // Placeholders are generated from the document list; the values stay
      // parameters. The list is a compile-time constant, but building SQL by
      // interpolation is a habit this codebase does not keep.
      const pairs = LEGAL_DOCUMENTS.map(
        (_, i) => `($${i * 2 + 3}, $${i * 2 + 4})`,
      ).join(', ');
      const consent = await db.query<{ n: number }>(
        `select count(*)::int as n from legal_acceptances
          where workspace_id = $1 and user_id = $2
            and (document, version) in (${pairs})`,
        [
          input.workspaceId,
          input.humanId,
          ...LEGAL_DOCUMENTS.flatMap((d) => [d, CURRENT_LEGAL_VERSIONS[d]]),
        ],
      );
      if ((consent.rows[0]?.n ?? 0) < LEGAL_DOCUMENTS.length) return deny('CONSENT_REQUIRED');

        return null;
      }),
    );
    if (gate) return gate;

    const presence = await clock.time('session', () =>
      readPresenceState(deps.pool, input.workspaceId, input.humanId),
    );
    // §7.2: locked denies everything, whatever any policy says.
    if (presence === 'locked') return deny('WORKSPACE_LOCKED');

    // Step 4 — deterministic prechecks.
    const rules = await clock.time('precheck', () =>
      withWorkspace(deps.pool, input.workspaceId, (db) => loadPolicies(db, input.workspaceId)),
    );
    const verdict = matchPolicies(rules, input, { at: new Date(), timeZone });
    policyVersion = verdict.version;

    if (verdict.effect === 'deny') {
      // No rule matched, or a deny rule did. Either way nothing granted this.
      return deny(verdict.rule === null ? 'TOOL_NOT_ALLOWED' : 'RESOURCE_OUT_OF_SCOPE');
    }
    if (verdict.effect === 'challenge') held = challenge('APPROVAL_REQUIRED');

    // The resource's sensitivity label, if it has one.
    //
    // Applied *after* the rule and only ever as an extra requirement: a label
    // never grants, so a resource nothing allows stays denied whatever it is
    // labelled.
    const labels = await clock.time('precheck', () =>
      withWorkspace(deps.pool, input.workspaceId, (db) => loadLabels(db, input.workspaceId)),
    );
    const label = matchLabel(labels, input.resource.type, input.resource.id);
    sensitivity = label?.sensitivity ?? DEFAULT_SENSITIVITY;
    const labelled = requirementFor(sensitivity);

    // Presence gating, from the rule and from the label. Either can demand it;
    // the stricter of the two is what applies.
    const ruleStates = verdict.rule?.conditions.presence;
    const requiredStates =
      labelled.presence.length === 0
        ? ruleStates
        : ruleStates === undefined
          ? labelled.presence
          : // Both named states: keep only the ones both accept.
            ruleStates.filter((state) => labelled.presence.includes(state));

    if (requiredStates !== undefined && !requiredStates.includes(presence)) {
      if (presence === 'automation') return deny('AUTOMATION_WINDOW_VIOLATION');
      held = challenge(
        input.action === 'read' ? 'USER_AWAY_SENSITIVE_RESOURCE' : 'USER_AWAY_WRITE_ACTION',
      );
    }

    // Volume, read-only here so an obviously-spent budget fails fast. The
    // atomic reservation happens only if everything else says allow.
    const limit = verdict.rule?.conditions.maxPerDay;
    if (limit !== undefined) {
      const used = await clock.time('precheck', () =>
        currentUsage(deps.redis, input.workspaceId, input.agentId, input.action),
      );
      if (used >= limit) return deny('VOLUME_LIMIT_EXCEEDED');
    }

    // Step 5 — Permit, and only the relationship/attribute question.
    permitResult = await clock.time('policy', () =>
      deps.policy.check({
      workspaceId: input.workspaceId,
      agentId: input.agentId,
      action: input.action,
      resourceType: input.resource.type,
      resourceKey: input.resource.id,
      // Permit sees the label as an attribute (§4.3). It is a classification,
      // never the content it classifies (invariant 5).
        attributes: { user_presence: presence, sensitivity },
      }),
    );

    if (permitResult === 'unavailable') return deny('POLICY_UNAVAILABLE');
    if (permitResult === 'deny') return deny('POLICY_DENIED');

    // Step 6 — the checks Permit cannot express. After the check, so a Permit
    // denial is never overridden, and these can only narrow (invariant 3).
    const risk = await clock.time('risk', () =>
      assessRisk(input, {
      // Either the rule or the label can require a stated intent.
        requireIntent: verdict.rule?.conditions.requireIntent === true || labelled.requireIntent,
      }),
    );
    if (risk?.result === 'deny') return deny(risk.reasonCode);
    if (risk?.result === 'challenge') held = challenge(risk.reasonCode);

    if (held) {
      // A challenge resumes only with an unexpired, single-use grant that names
      // this exact action.
      //
      // The client may name the grant with `approval_id`. If it does not — and
      // no ordinary MCP client does, because that parameter is ours — the grant
      // is looked up by the thing that actually binds it: the action digest.
      // Without this the loop never closes; the human approves, the agent
      // retries the identical call, and is challenged again.
      //
      // Both paths redeem through `redeemApproval` below, so both get every
      // refusal it makes. Nothing here decides an approval is valid.
      const named = await clock.time('risk', () =>
        input.approvalId
          ? Promise.resolve(input.approvalId)
          : withWorkspace(deps.pool, input.workspaceId, (db) =>
              findApprovedForDigest(db, {
                workspaceId: input.workspaceId,
                humanId: input.humanId,
                actionDigest: digest,
              }),
            ),
      );

      // Still nothing to redeem: the challenge stands, exactly as before.
      if (!named) return held;

      const redeemed = await clock.time('risk', () =>
        withWorkspace(deps.pool, input.workspaceId, (db) =>
          redeemApproval(db, {
            workspaceId: input.workspaceId,
            approvalId: named,
            humanId: input.humanId,
            actionDigest: digest,
          }),
        ),
      );

      // A refused grant denies rather than re-challenging: replayed, expired
      // and digest-mismatched are deny codes, and handing back another approval
      // would let an attacker grind against one.
      if (!redeemed.ok) return deny(redeemed.reasonCode);
      held = null;
    }

    // Only now does an allow spend budget.
    if (limit !== undefined) {
      const fits = await clock.time('precheck', () =>
        reserve(deps.redis, input.workspaceId, input.agentId, input.action, limit),
      );
      if (!fits) return deny('VOLUME_LIMIT_EXCEEDED');
    }

    return { result: 'allow', reasonCode: 'ALLOWED_WITHIN_POLICY' };
  })();

  const latencyMs = Number(process.hrtime.bigint() - started) / 1e6;
  const spec = describeReason(outcome.reasonCode);

  // Steps 7 and 9 — emit, and record. The decision row and its audit event are
  // written in one transaction: a decision nobody can see happening is the
  // §7.3 audit-tampering failure arriving by accident.
  // Step 9 is timed but cannot be *in* the map it writes — the row is inserted
  // by the very call being measured. So it is measured here and reported on the
  // response; the stored map covers steps 2 to 6, which is where a slow
  // decision is diagnosed.
  const persistStarted = process.hrtime.bigint();
  const approvalId = await persist(deps, input, {
    decisionId,
    outcome,
    permitResult,
    policyVersion,
    digest,
    latencyMs,
    stepTimings: clock.read(),
    approvalTtlMs: deps.approvalTtlMs ?? 5 * 60 * 1000,
  });
  clock.record('audit', Number(process.hrtime.bigint() - persistStarted) / 1e6);

  return {
    decisionId,
    result: outcome.result,
    reasonCode: outcome.reasonCode,
    humanMessage: spec.message,
    approvalId,
    expiresAt:
      approvalId === null
        ? null
        : new Date(Date.now() + (deps.approvalTtlMs ?? 5 * 60 * 1000)).toISOString(),
    policyVersion,
    permitResult,
    latencyMs: Math.round(latencyMs * 100) / 100,
    stepTimings: clock.read(),
    actionDigest: digest,
  };
}

/**
 * Presence as the state machine interprets it.
 *
 * Delegated rather than queried here, so expiry and the "absence means away"
 * rule have one implementation. A second reading of the same row is a second
 * chance to get it wrong.
 */
async function readPresenceState(pool: Pool, workspaceId: string, userId: string): Promise<string> {
  const presence = await withWorkspace(pool, workspaceId, (db) =>
    readPresence(db, workspaceId, userId),
  );
  return presence.state;
}

interface PersistArgs {
  decisionId: string;
  outcome: Outcome;
  permitResult: PermitOutcome | 'not_evaluated';
  policyVersion: string | null;
  digest: string;
  latencyMs: number;
  stepTimings: StepTimings;
  approvalTtlMs: number;
}

async function persist(
  deps: PipelineDeps,
  input: EvaluateInput,
  args: PersistArgs,
): Promise<string | null> {
  return withWorkspace(deps.pool, input.workspaceId, async (db: Db) => {
    await db.query(
      `insert into decisions
         (id, workspace_id, request_id, human_id, agent_id, tool, action, resource_ref,
          policy_version, permit_result, veto_result, reason_code, latency_ms, step_timings)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [
        args.decisionId,
        input.workspaceId,
        input.requestId,
        input.humanId,
        input.agentId,
        input.tool,
        input.action,
        // A reference, never the content (invariant 5, §11).
        grantRef(input.resource.type, input.resource.id),
        args.policyVersion,
        args.permitResult,
        args.outcome.result,
        args.outcome.reasonCode,
        Math.round(args.latencyMs),
        // Numbers only. The map's type has no field an argument or a resource
        // id could occupy, which is the control — invariant 5 applies to a
        // timing map exactly as it applies to an audit event.
        JSON.stringify(args.stepTimings),
      ],
    );

    let approvalId: string | null = null;
    if (args.outcome.result === 'challenge') {
      // One live grant per action per approver, enforced by a partial unique
      // index. A second challenge for the same action reuses the outstanding
      // approval rather than opening a rival one — two pending grants for one
      // action would mean redeeming either satisfies it, which is not what
      // single-use means.
      const existing = await db.query<{ id: string }>(
        `select id from approvals
          where workspace_id = $1 and approver_id = $2 and action_digest = $3
            and status = 'pending' and expires_at > now()
          limit 1`,
        [input.workspaceId, input.humanId, args.digest],
      );

      const live = existing.rows[0];
      if (live) {
        approvalId = live.id;
        await writeAuditEvent(db, {
          workspaceId: input.workspaceId,
          actor: input.agentId,
          eventType: `decision.${args.outcome.result}`,
          resourceRef: grantRef(input.resource.type, input.resource.id),
          outcome: args.outcome.result,
          correlationId: input.requestId,
        });
        return approvalId;
      }

      // Retire anything that lapsed without being resolved, first.
      //
      // The unique index is on `status = 'pending'` alone, while the reuse
      // query above also requires `expires_at > now()`. An approval nobody
      // answered keeps `status = 'pending'` past its expiry, so it is invisible
      // to that lookup and still occupies the index — and the insert below
      // collided with it. The database raised a duplicate-key error, nothing
      // caught it, and the client was handed a bare internal error on every
      // subsequent challenge for that action. A human who let one challenge
      // time out could not be challenged for the same thing again.
      //
      // Sweeping it to `expired` is the same transition `resolveApproval`
      // already makes when it meets a lapsed row; doing it here keeps the
      // index's meaning ("one live grant") true rather than "one row that was
      // once live".
      await db.query(
        `update approvals set status = 'expired'
          where workspace_id = $1 and approver_id = $2 and action_digest = $3
            and status = 'pending' and expires_at <= now()`,
        [input.workspaceId, input.humanId, args.digest],
      );

      approvalId = newId('apr_');
      const inserted = await db.query<{ id: string }>(
        `insert into approvals
           (id, workspace_id, decision_id, approver_id, action_digest, challenge, expires_at)
         values ($1,$2,$3,$4,$5,$6, now() + ($7 || ' milliseconds')::interval)
         on conflict (workspace_id, approver_id, action_digest) where status = 'pending'
         do nothing
         returning id`,
        [
          approvalId,
          input.workspaceId,
          args.decisionId,
          // The original delegating user, and nobody else (invariant 7).
          input.humanId,
          args.digest,
          randomChallenge(),
          String(args.approvalTtlMs),
        ],
      );

      // Nothing inserted means somebody else opened the grant between the
      // lookup and here — two calls for the same action arriving together.
      // Reuse theirs rather than failing: a challenge is not the place to
      // surface a race, and two pending grants for one action would mean
      // redeeming either satisfies it.
      if (!inserted.rows[0]) {
        const raced = await db.query<{ id: string }>(
          `select id from approvals
            where workspace_id = $1 and approver_id = $2 and action_digest = $3
              and status = 'pending'
            limit 1`,
          [input.workspaceId, input.humanId, args.digest],
        );
        approvalId = raced.rows[0]?.id ?? approvalId;
      }
    }

    await writeAuditEvent(db, {
      workspaceId: input.workspaceId,
      actor: input.agentId,
      eventType: `decision.${args.outcome.result}`,
      resourceRef: grantRef(input.resource.type, input.resource.id),
      outcome: args.outcome.result,
      correlationId: input.requestId,
    });

    await announce(db, input, args, approvalId, deps.dashboardUrl ?? null);

    return approvalId;
  });
}

/**
 * The §5.4 events this decision produced.
 *
 * Inside the same transaction as the decision row, so an alert cannot describe
 * a decision that rolled back. Nothing is sent here: delivery is a worker, and
 * a receiver that hangs must never be able to spend the §11 authorization
 * budget (200 ms) on somebody else's downtime.
 *
 * An `allow` emits nothing. §5.4 lists denials and approvals, and a webhook per
 * successful read would be a firehose that buries the events that matter — the
 * audit trail is where the complete record lives.
 */
async function announce(
  db: Db,
  input: EvaluateInput,
  args: PersistArgs,
  approvalId: string | null,
  dashboardUrl: string | null,
): Promise<void> {
  const shared = {
    workspaceId: input.workspaceId,
    correlationId: input.requestId,
  };

  // A reference, never the content or the arguments (invariant 5).
  const resourceRef = grantRef(input.resource.type, input.resource.id);

  if (args.outcome.result === 'deny') {
    const data = {
      agent_id: input.agentId,
      human_id: input.humanId,
      decision_id: args.decisionId,
      resource_ref: resourceRef,
      reason_code: args.outcome.reasonCode,
      outcome: 'deny' as const,
    };

    await enqueue(db, { ...shared, type: 'decision.denied', data });

    // A refusal from step 6 is a different kind of news from a refusal at step
    // 4. "No rule allows this" is the system working as configured; "the
    // arguments looked like a credential" or "the destination is a private
    // address" is somebody trying something. §5.4 gives the second its own
    // event so an operator can alert on it without drowning in the first.
    if (describeReason(args.outcome.reasonCode).stage === 'risk') {
      await enqueue(db, { ...shared, type: 'risk.anomaly_detected', data });
    }
    return;
  }

  if (args.outcome.result === 'challenge' && approvalId !== null) {
    // The id goes in the path, encoded. It is ours — `newId` made it — but a
    // value interpolated into a URL somebody is about to click gets encoded
    // whatever its provenance, because the habit is what survives a refactor
    // that changes where the id comes from.
    const approvalUrl =
      dashboardUrl === null || dashboardUrl === ''
        ? null
        : `${dashboardUrl.replace(/\/+$/, '')}/approvals?id=${encodeURIComponent(approvalId)}`;

    await enqueue(db, {
      ...shared,
      type: 'approval.requested',
      data: {
        ...(approvalUrl === null ? {} : { approval_url: approvalUrl }),
        agent_id: input.agentId,
        // Who has to act. An alert about an approval nobody can route is noise.
        human_id: input.humanId,
        decision_id: args.decisionId,
        approval_id: approvalId,
        resource_ref: resourceRef,
        reason_code: args.outcome.reasonCode,
        outcome: 'challenge',
      },
    });
  }
}

/**
 * The WebAuthn challenge bytes.
 *
 * Stored for verification and never logged or audited (invariant 5). The
 * ceremony that consumes it is stage 3; what matters now is that it exists and
 * is unique per approval, so one approval can never be satisfied by replaying
 * another one's challenge.
 */
const randomChallenge = (): Buffer => randomBytes(32);
