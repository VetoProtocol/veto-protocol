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
import { actionDigest, newId, describeReason, type DigestibleValue } from '@veto/core';
import type { Db } from '@veto/db';
import { withWorkspace } from '@veto/db';
import { writeAuditEvent, findAgent } from '@veto/identity';
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
import { redeemApproval } from './approvals.ts';
import { readPresence } from '@veto/presence';
import { currentUsage, reserve } from './volume.ts';

export interface PipelineDeps {
  readonly pool: Pool;
  readonly redis: Redis;
  readonly policy: PolicyDecisions;
  /** How long an approval stays open. §5.2 shows minutes, not hours. */
  readonly approvalTtlMs?: number;
}

interface Outcome {
  readonly result: 'allow' | 'deny' | 'challenge';
  readonly reasonCode: string;
}

const deny = (reasonCode: string): Outcome => ({ result: 'deny', reasonCode });
const challenge = (reasonCode: string): Outcome => ({ result: 'challenge', reasonCode });

export async function evaluate(deps: PipelineDeps, input: EvaluateInput): Promise<DecisionResponse> {
  const started = process.hrtime.bigint();
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
    const gate = await withWorkspace(deps.pool, input.workspaceId, async (db) => {
      const { rows } = await db.query<{ emergency_lock: boolean }>(
        `select emergency_lock from workspaces where id = $1`,
        [input.workspaceId],
      );
      const workspace = rows[0];
      if (!workspace) return deny('IDENTITY_UNRESOLVED');
      if (workspace.emergency_lock) return deny('WORKSPACE_LOCKED');

      const agent = await findAgent(db, input.workspaceId, input.agentId);
      if (!agent) return deny('AGENT_UNKNOWN');
      if (agent.status === 'revoked') return deny('AGENT_REVOKED');
      if (agent.status !== 'active') return deny('AGENT_REVOKED');
      if (agent.owner_user_id !== input.humanId) return deny('IDENTITY_UNRESOLVED');

      return null;
    });
    if (gate) return gate;

    const presence = await readPresenceState(deps.pool, input.workspaceId, input.humanId);
    // §7.2: locked denies everything, whatever any policy says.
    if (presence === 'locked') return deny('WORKSPACE_LOCKED');

    // Step 4 — deterministic prechecks.
    const rules = await withWorkspace(deps.pool, input.workspaceId, (db) =>
      loadPolicies(db, input.workspaceId),
    );
    const verdict = matchPolicies(rules, input);
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
    const labels = await withWorkspace(deps.pool, input.workspaceId, (db) =>
      loadLabels(db, input.workspaceId),
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
      const used = await currentUsage(deps.redis, input.workspaceId, input.agentId, input.action);
      if (used >= limit) return deny('VOLUME_LIMIT_EXCEEDED');
    }

    // Step 5 — Permit, and only the relationship/attribute question.
    permitResult = await deps.policy.check({
      workspaceId: input.workspaceId,
      agentId: input.agentId,
      action: input.action,
      resourceType: input.resource.type,
      resourceKey: input.resource.id,
      // Permit sees the label as an attribute (§4.3). It is a classification,
      // never the content it classifies (invariant 5).
      attributes: { user_presence: presence, sensitivity },
    });

    if (permitResult === 'unavailable') return deny('POLICY_UNAVAILABLE');
    if (permitResult === 'deny') return deny('POLICY_DENIED');

    // Step 6 — the checks Permit cannot express. After the check, so a Permit
    // denial is never overridden, and these can only narrow (invariant 3).
    const risk = await assessRisk(input, {
      // Either the rule or the label can require a stated intent.
      requireIntent: verdict.rule?.conditions.requireIntent === true || labelled.requireIntent,
    });
    if (risk?.result === 'deny') return deny(risk.reasonCode);
    if (risk?.result === 'challenge') held = challenge(risk.reasonCode);

    if (held) {
      // A challenge resumes only with an unexpired, single-use grant that names
      // this exact action. Without one, the challenge stands.
      if (!input.approvalId) return held;

      const redeemed = await withWorkspace(deps.pool, input.workspaceId, (db) =>
        redeemApproval(db, {
          workspaceId: input.workspaceId,
          approvalId: input.approvalId ?? '',
          humanId: input.humanId,
          actionDigest: digest,
        }),
      );

      // A refused grant denies rather than re-challenging: replayed, expired
      // and digest-mismatched are deny codes, and handing back another approval
      // would let an attacker grind against one.
      if (!redeemed.ok) return deny(redeemed.reasonCode);
      held = null;
    }

    // Only now does an allow spend budget.
    if (limit !== undefined) {
      const fits = await reserve(
        deps.redis,
        input.workspaceId,
        input.agentId,
        input.action,
        limit,
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
  const approvalId = await persist(deps, input, {
    decisionId,
    outcome,
    permitResult,
    policyVersion,
    digest,
    latencyMs,
    approvalTtlMs: deps.approvalTtlMs ?? 5 * 60 * 1000,
  });

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
          policy_version, permit_result, veto_result, reason_code, latency_ms)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        args.decisionId,
        input.workspaceId,
        input.requestId,
        input.humanId,
        input.agentId,
        input.tool,
        input.action,
        // A reference, never the content (invariant 5, §11).
        `${input.resource.type}:${input.resource.id}`,
        args.policyVersion,
        args.permitResult,
        args.outcome.result,
        args.outcome.reasonCode,
        Math.round(args.latencyMs),
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
          resourceRef: `${input.resource.type}:${input.resource.id}`,
          outcome: args.outcome.result,
          correlationId: input.requestId,
        });
        return approvalId;
      }

      approvalId = newId('apr_');
      await db.query(
        `insert into approvals
           (id, workspace_id, decision_id, approver_id, action_digest, challenge, expires_at)
         values ($1,$2,$3,$4,$5,$6, now() + ($7 || ' milliseconds')::interval)`,
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
    }

    await writeAuditEvent(db, {
      workspaceId: input.workspaceId,
      actor: input.agentId,
      eventType: `decision.${args.outcome.result}`,
      resourceRef: `${input.resource.type}:${input.resource.id}`,
      outcome: args.outcome.result,
      correlationId: input.requestId,
    });

    return approvalId;
  });
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
