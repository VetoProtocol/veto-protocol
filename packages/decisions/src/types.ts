/**
 * The decision request and response (spec §5.1, §5.2).
 */

import type { DecisionResult } from '@veto/core';
import type { StepTimings } from './timing.ts';
import type { Schedule } from './schedule.ts';

export interface ResourceRef {
  readonly type: string;
  readonly id: string;
}

/** §5.1. Identity is already resolved — the gateway did that at step 1. */
export interface EvaluateInput {
  readonly requestId: string;
  readonly workspaceId: string;
  readonly humanId: string;
  readonly agentId: string;
  readonly clientId: string;
  readonly tool: string;
  readonly action: string;
  readonly resource: ResourceRef;
  readonly arguments: Readonly<Record<string, unknown>>;
  /**
   * What the agent says it is doing.
   *
   * A risk signal and nothing more (§7.3, FR-11). It may raise a challenge; it
   * may never authorise one. An agent under prompt injection will supply a
   * perfectly plausible intent.
   */
  readonly declaredIntent: string | null;
  /** Where data would be sent, when the tool sends anywhere. Checked for SSRF. */
  readonly destination: string | null;
  readonly occurredAt: string;
  /**
   * A grant the client is presenting to resume a challenged action (§5.3).
   *
   * Absent on a first attempt. Present on a retry after approval, and checked
   * against this exact action's digest.
   */
  readonly approvalId?: string | null;
}

/** §5.2. */
export interface DecisionResponse {
  readonly decisionId: string;
  readonly result: DecisionResult;
  readonly reasonCode: string;
  readonly humanMessage: string;
  readonly approvalId: string | null;
  readonly expiresAt: string | null;
  readonly policyVersion: string | null;
  /** Recorded separately from the final result; never collapsed (invariant 3). */
  readonly permitResult: 'allow' | 'deny' | 'unavailable' | 'not_evaluated';
  readonly latencyMs: number;
  /**
   * Milliseconds per §3.3 step. Sparse: a decision that stopped at step 5 has
   * nothing truthful to say about the steps after it.
   */
  readonly stepTimings: StepTimings;
  /** Binds an approval to this exact action (invariants 6, 7). */
  readonly actionDigest: string;
}

/** A row of `policies`, decoded. */
export interface PolicyRule {
  readonly id: string;
  readonly version: string;
  /** An agent id, or '*' for every agent in the workspace. */
  readonly subject: string;
  readonly action: string;
  readonly effect: DecisionResult;
  readonly resourceFilter: {
    readonly type?: string;
    readonly ids?: readonly string[];
    readonly prefix?: string;
  };
  readonly conditions: {
    /** Presence states in which this rule applies without a challenge (§7.2). */
    readonly presence?: readonly string[];
    /** Cumulative authorization limit — never a rate limit (§7.1). */
    readonly maxPerDay?: number;
    /** Requires a stated intent before a sensitive resource is touched. */
    readonly requireIntent?: boolean;
    /**
     * When this rule applies at all (FR-06's time dimension).
     *
     * Read in the workspace's zone. Outside it the rule simply does not match,
     * so it narrows by absence rather than by denying — see `schedule.ts`.
     */
    readonly schedule?: Schedule;
  };
}
