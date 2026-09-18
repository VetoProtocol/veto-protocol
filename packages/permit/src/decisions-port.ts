/**
 * The runtime authorization question — `permit.check` (spec §4.3).
 *
 * A separate port from `PolicyFacts` on purpose. That one writes facts and
 * answers nothing, and a test asserts its exact method set so a `check`-shaped
 * method appearing on it fails the build. This is where checking lives, and
 * keeping them apart keeps the two responsibilities visible: one is control
 * plane, the other is on the hot path of every protected action.
 *
 * ## Unavailable is a result, not an exception
 *
 * `check` never throws. A timeout, a 500, a DNS failure — all return
 * `'unavailable'`, because the caller has to *record* that outcome:
 * `decisions.permit_result` distinguishes allow, deny, unavailable and
 * not_evaluated, and a database CHECK forbids an unavailable Permit producing
 * an allow. If this threw, the pipeline would have to reconstruct which of
 * those happened from a catch block, and the honest answer would be easy to
 * lose.
 *
 * Unavailable still denies. It is a distinct *reason*, never a softer outcome
 * (invariant 1).
 */

export type PermitOutcome = 'allow' | 'deny' | 'unavailable';

export interface CheckInput {
  readonly workspaceId: string;
  readonly agentId: string;
  /** A §4.2 action: read, search, create, update, delete, share, execute, transfer. */
  readonly action: string;
  readonly resourceType: string;
  readonly resourceKey: string;
  /**
   * Attributes Permit may consider (§4.3).
   *
   * Never secrets and never protected content (invariant 5) — sensitivity
   * labels, presence state and intent category are classifications, not the
   * thing classified.
   */
  readonly attributes?: Readonly<Record<string, string | number | boolean>>;
}

export interface PolicyDecisions {
  check(input: CheckInput): Promise<PermitOutcome>;
}
