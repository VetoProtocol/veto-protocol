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

/**
 * An agent's relationship to one resource (§4.2, §4.4 "Create relationships").
 *
 * ## Why this is not the same thing as a policy rule
 *
 * A Veto rule and a Permit grant answer different questions, and the split is
 * §4.1's:
 *
 *   * A **grant** says the agent is *connected to* this folder or file at all.
 *     It is a statement about the world, it inherits — a grant on a folder
 *     reaches the files inside it through the `parent` relation — and Permit
 *     owns it.
 *   * A **rule** says under what conditions that connection may be used: only
 *     while you are at your desk, at most fifty times a day, having stated a
 *     purpose. Veto owns that, at step 4, and it can only ever narrow.
 *
 * Both must say yes. Deriving one from the other would collapse them: if every
 * rule wrote its own grant, Permit would agree with Veto by construction and
 * the second opinion invariant 3 asks for would be a mirror.
 *
 * The practical consequence is the one that bites: writing an allow rule for a
 * folder nobody granted produces a denial at step 5, correctly, and the
 * dashboard has to say so or the operator concludes the product is broken.
 */
export interface ResourceGrant {
  readonly workspaceId: string;
  readonly agentId: string;
  /** `google_file` or `google_folder`. The tool catalogue's resourceType. */
  readonly resourceType: string;
  /** The file or folder id, exactly as a tool call would name it. */
  readonly resourceKey: string;
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

  /**
   * Connect an agent to one folder or file.
   *
   * Idempotent: granting twice is the same end state as granting once, so a
   * retry after a partial failure converges rather than erroring.
   *
   * Creates the resource instance if Permit has not seen it. Drive is not
   * enumerated anywhere, so the first time anybody names a folder is the moment
   * it becomes a thing Permit can hold an opinion about.
   */
  grantResource(grant: ResourceGrant): Promise<void>;

  /**
   * Disconnect it again.
   *
   * Removes the role assignment and leaves the instance. The instance is not a
   * grant — it is the noun the grant was about — and deleting it would also
   * delete any `parent` edges hanging off it, which would silently widen or
   * narrow unrelated grants.
   */
  revokeResource(grant: ResourceGrant): Promise<void>;

  /** Every resource grant in a workspace. The dashboard's read. */
  listGrants(workspaceId: string): Promise<readonly ResourceGrant[]>;
}

export class PolicyUnavailableError extends Error {
  constructor(operation: string, cause?: unknown) {
    super(`Permit is unavailable (${operation})`);
    this.name = 'PolicyUnavailableError';
    this.cause = cause;
  }
}
