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

import type { Db } from '@veto/db';
import type { PolicyRule } from './types.ts';
import type { EvaluateInput } from './types.ts';

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
