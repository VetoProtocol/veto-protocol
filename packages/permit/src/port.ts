/**
 * The Permit boundary, expressed as a port.
 *
 * Spec §4.1: Permit decides whether a known principal may act on a modeled
 * resource. Veto owns everything else. Two rules this port exists to enforce:
 *
 *  1. No route handler ever touches a Permit client directly. Everything goes
 *     through this interface, so failure handling lives in one place and cannot
 *     be forgotten at a call site (invariant 3).
 *  2. Unreachable means deny. A timeout or error is not a missing opinion, it is
 *     a denial (invariant 1, §7.3 policy outage). The real adapter in phase 5
 *     implements that; the contract is declared here so the rule predates the
 *     implementation.
 */

export interface AgentFact {
  readonly workspaceId: string;
  readonly agentId: string;
  readonly ownerUserId: string;
}

export interface PolicyFacts {
  /** Create or update the agent principal and its owner relationship (§4.4). */
  syncAgent(fact: AgentFact): Promise<void>;

  /**
   * Remove every fact that grants this agent anything: role assignments and
   * relationship tuples. Revocation is not complete until this succeeds
   * (FR-08, §7.3 privilege accumulation).
   */
  removeAgent(workspaceId: string, agentId: string): Promise<void>;

  /** Facts currently held for a workspace. Used to assert that revocation left nothing behind. */
  factsFor(workspaceId: string): Promise<readonly string[]>;
}

export class PolicyUnavailableError extends Error {
  constructor(operation: string, cause?: unknown) {
    super(`Permit is unavailable (${operation})`);
    this.name = 'PolicyUnavailableError';
    this.cause = cause;
  }
}
