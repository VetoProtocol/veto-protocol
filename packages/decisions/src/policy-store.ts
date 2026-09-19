/**
 * Reading and matching policy rules (step 4 of §3.3).
 *
 * These are Veto's own deterministic checks, and they run *before* Permit
 * (invariant 3). Permit decides relationships and attributes — "is this agent
 * related to this folder"; this decides the things a relationship engine should
 * not be asked: is the tool on the allowlist at all, is the resource inside an
 * explicitly granted set, has the daily budget been spent.
 *
 * Deny-by-default is structural: a request with no matching rule has no rule
 * saying yes, and `matchPolicies` returns a deny for it rather than an absence
 * a caller might read as permission (invariant 2).
 */

import { newId } from '@veto/core';
import type { Db } from '@veto/db';
import { writeAuditEvent } from '@veto/identity';
import type { PolicyRule } from './types.ts';
import type { EvaluateInput } from './types.ts';

/**
 * The actions a rule may name.
 *
 * Closed, because a rule naming an action no tool declares is a rule that
 * silently grants nothing — and the person who wrote it has no way to tell the
 * difference between "typo" and "denied by something else". A gateway test
 * asserts every tool's action is in this list, so the two cannot drift.
 *
 * `*` is here and is a real wildcard. It is the only value that can match an
 * action added later, which is exactly why a rule using it deserves the
 * scrutiny the dashboard gives it.
 */
export const POLICY_ACTIONS = ['read', 'list', 'search', 'write', '*'] as const;
export type PolicyAction = (typeof POLICY_ACTIONS)[number];

interface PolicyRow {
  id: string;
  version: string;
  subject: string;
  action: string;
  effect: 'allow' | 'deny' | 'challenge';
  resource_filter: PolicyRule['resourceFilter'];
  conditions: PolicyRule['conditions'];
}

export async function loadPolicies(db: Db, workspaceId: string): Promise<PolicyRule[]> {
  const { rows } = await db.query<PolicyRow>(
    `select id, version, subject, action, effect, resource_filter, conditions
       from policies where workspace_id = $1
      order by created_at asc, id asc`,
    [workspaceId],
  );

  return rows.map((row) => ({
    id: row.id,
    version: row.version,
    subject: row.subject,
    action: row.action,
    effect: row.effect,
    resourceFilter: row.resource_filter ?? {},
    conditions: row.conditions ?? {},
  }));
}

export function ruleMatches(rule: PolicyRule, input: EvaluateInput): boolean {
  if (rule.subject !== '*' && rule.subject !== input.agentId) return false;
  if (rule.action !== '*' && rule.action !== input.action) return false;

  const filter = rule.resourceFilter;
  if (filter.type !== undefined && filter.type !== input.resource.type) return false;

  if (filter.ids !== undefined && !filter.ids.includes(input.resource.id)) return false;

  if (filter.prefix !== undefined && !input.resource.id.startsWith(filter.prefix)) return false;

  return true;
}

export interface PolicyVerdict {
  readonly effect: 'allow' | 'deny' | 'challenge';
  readonly rule: PolicyRule | null;
  readonly version: string | null;
}

/**
 * The most restrictive matching rule wins.
 *
 * deny beats challenge beats allow. A workspace that has both "allow reads of
 * /Work" and "never touch /Personal" must not depend on which was written
 * first, and an operator adding a deny should never have to audit the ordering
 * of everything already there.
 */
export function matchPolicies(rules: readonly PolicyRule[], input: EvaluateInput): PolicyVerdict {
  const matching = rules.filter((rule) => ruleMatches(rule, input));

  if (matching.length === 0) {
    // No rule said yes. That is a denial, not an absence (invariant 2).
    return { effect: 'deny', rule: null, version: null };
  }

  const rank = { deny: 3, challenge: 2, allow: 1 } as const;
  let winner = matching[0] as PolicyRule;
  for (const rule of matching) {
    if (rank[rule.effect] > rank[winner.effect]) winner = rule;
  }

  return { effect: winner.effect, rule: winner, version: winner.version };
}

export interface CreatePolicyInput {
  readonly workspaceId: string;
  readonly subject: string;
  readonly action: string;
  readonly effect: 'allow' | 'deny' | 'challenge';
  readonly resourceFilter: PolicyRule['resourceFilter'];
  readonly conditions: PolicyRule['conditions'];
  readonly actorUserId: string;
  readonly correlationId?: string | null;
}

/**
 * Write a rule.
 *
 * **Rules are created and deleted, never edited.** Every decision records the
 * `policy_version` that produced it, and editing a rule in place would leave
 * old decisions pointing at a version whose text has since changed — an auditor
 * asking "what did the rule say when this was allowed?" would get today's
 * answer. So each rule gets its own version at creation, and changing your mind
 * means deleting and writing a new one.
 *
 * Nothing here talks to Permit. These are Veto's own step-4 checks and they run
 * *before* the relationship question (invariant 3). A rule is necessary for an
 * allow and is not sufficient for one.
 */
export async function createPolicy(db: Db, input: CreatePolicyInput): Promise<PolicyRule> {
  const id = newId('pol_');
  const version = newId('polv_');

  await db.query(
    `insert into policies
       (id, workspace_id, subject, action, resource_filter, conditions, effect, version)
     values ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      id,
      input.workspaceId,
      input.subject,
      input.action,
      JSON.stringify(input.resourceFilter),
      JSON.stringify(input.conditions),
      input.effect,
      version,
    ],
  );

  await writeAuditEvent(db, {
    workspaceId: input.workspaceId,
    actor: input.actorUserId,
    eventType: 'policy.created',
    // What the rule is about. A rule is configuration rather than protected
    // content, but the resource ids inside the filter are referenced by shape
    // and not listed, so a long allowlist does not end up in the trail.
    resourceRef: `policy:${id}#${input.subject}:${input.action}:${input.effect}`,
    outcome: 'lifecycle',
    correlationId: input.correlationId ?? null,
  });

  return {
    id,
    version,
    subject: input.subject,
    action: input.action,
    effect: input.effect,
    resourceFilter: input.resourceFilter,
    conditions: input.conditions,
  };
}

/**
 * Delete a rule.
 *
 * Deleting an `allow` narrows what is possible, which needs no ceremony.
 * Deleting a `deny` *widens* it, and that is the dangerous direction — so the
 * audit event records which it was, and the dashboard makes a reader confirm
 * the second. The decisions the rule already produced keep their version
 * string; the row is gone but the history is not rewritten.
 */
export async function deletePolicy(
  db: Db,
  workspaceId: string,
  policyId: string,
  actorUserId: string,
  correlationId?: string | null,
): Promise<boolean> {
  const { rows } = await db.query<{ subject: string; action: string; effect: string }>(
    `delete from policies where workspace_id = $1 and id = $2
     returning subject, action, effect`,
    [workspaceId, policyId],
  );

  const row = rows[0];
  if (!row) return false;

  await writeAuditEvent(db, {
    workspaceId,
    actor: actorUserId,
    eventType: 'policy.removed',
    resourceRef: `policy:${policyId}#${row.subject}:${row.action}:${row.effect}`,
    outcome: 'lifecycle',
    correlationId: correlationId ?? null,
  });

  return true;
}
