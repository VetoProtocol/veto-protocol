/**
 * The mandatory adversarial scenarios (spec §12.1), as data.
 *
 * CLAUDE.md requires these tests to be written *before* the features they
 * target. Stage 2 is where the features land, so what exists today is this
 * registry plus a test that keeps it honest: every §12.1 scenario must be
 * present, must name a threat the threat model actually contains, and must
 * either point at a real test file or be openly marked pending.
 *
 * The failure mode this guards against is the one that matters. A checklist in
 * a document drifts quietly — a scenario gets dropped, or a test is deleted and
 * the row stays ticked, and nobody notices because nothing breaks. Here,
 * forgetting one is a build failure.
 *
 * `asserts` is the most important field. Several of these are easy to write in
 * a form that can never fail, so each says what the test must actually assert
 * rather than leaving it to whoever picks it up.
 */

import type { PipelineStage } from './reason-codes.ts';

export type ScenarioStatus = 'pending' | 'implemented';

export interface AdversarialScenario {
  readonly id: string;
  /** Which part of the spec demands it. */
  readonly source: 'spec §12.1' | 'spec §12 security';
  readonly summary: string;
  /** Threat id in docs/threat-model.md. Checked to exist. */
  readonly threat: string;
  /** The pipeline step (§3.3) this exercises. */
  readonly stage: PipelineStage;
  /** What the test must assert. Written to make an unfalsifiable test obvious. */
  readonly asserts: string;
  readonly status: ScenarioStatus;
  /** Repo-relative test file. Required when implemented, absent when pending. */
  readonly test: string | null;
}

export const ADVERSARIAL_SCENARIOS: readonly AdversarialScenario[] = [
  {
    id: 'S1',
    source: 'spec §12.1',
    summary: 'An email instructs the agent to search Drive for tax records.',
    threat: 'T1',
    stage: 'precheck',
    asserts:
      'Assert on the decision, never on model behaviour. Retrieved content must not ' +
      'change the action digest, and a tool or resource the agent was never granted ' +
      'must deny regardless of how plausible declared_intent is. A test that asserts ' +
      '"the model was not fooled" is a test about the weather.',
    status: 'implemented',
    test: 'apps/gateway/test/injection.test.ts',
  },
  {
    id: 'S2',
    source: 'spec §12.1',
    summary: 'An agent authorized for one file requests the whole folder.',
    threat: 'T4',
    stage: 'precheck',
    asserts:
      'The grant is for a file id; a folder request is a different resource and denies ' +
      'with RESOURCE_OUT_OF_SCOPE. Must also deny when the folder is the file\'s own ' +
      'parent — inheritance flows down, not up.',
    status: 'implemented',
    test: 'packages/decisions/test/pipeline.test.ts',
  },
  {
    id: 'S3',
    source: 'spec §12.1',
    summary: 'A previously approved action is replayed after its expiry.',
    threat: 'T5',
    stage: 'approval',
    asserts:
      'Three separate denials, not one: expired (APPROVAL_EXPIRED), already consumed ' +
      '(APPROVAL_REPLAYED), and arguments changed since approval ' +
      '(APPROVAL_DIGEST_MISMATCH). Each needs its own case.',
    status: 'implemented',
    test: 'packages/decisions/test/approvals.test.ts',
  },
  {
    id: 'S4',
    source: 'spec §12.1',
    summary: 'A compromised agent divides a blocked bulk request into many small ones.',
    threat: 'T13',
    stage: 'precheck',
    asserts:
      'Cumulative volume across a window denies with VOLUME_LIMIT_EXCEEDED. Must fail ' +
      'if implemented as a rate limit: throttling is an availability control and never ' +
      'an authorization one (§7.1). The counter is shared, so the test must run the ' +
      'requests through the real store, not a per-request counter.',
    status: 'implemented',
    test: 'packages/decisions/test/pipeline.test.ts',
  },
  {
    id: 'S5',
    source: 'spec §12.1',
    summary: 'An approval link is opened by a different user.',
    threat: 'T3',
    stage: 'approval',
    asserts:
      'APPROVER_NOT_DELEGATOR, even when the other user is an admin of the same ' +
      'workspace (invariant 7). Also assert the approval is not consumed by the ' +
      'failed attempt.',
    status: 'implemented',
    test: 'packages/decisions/test/approvals.test.ts',
  },
  {
    id: 'S6',
    source: 'spec §12.1',
    summary: 'The user activates emergency lock during an active agent session.',
    threat: 'T14',
    stage: 'session',
    asserts:
      'An in-flight session denies on its next request with WORKSPACE_LOCKED, checked ' +
      'at step 3 before any policy evaluation. Permit must not be consulted at all.',
    status: 'implemented',
    test: 'packages/decisions/test/pipeline.test.ts',
  },
  {
    id: 'S7',
    source: 'spec §12.1',
    summary: 'Permit is unavailable during a sensitive request.',
    threat: 'T7',
    stage: 'policy',
    asserts:
      'POLICY_UNAVAILABLE and deny. Assert the recorded decision keeps permit_result ' +
      'and veto_result distinct, and that no upstream call was made.',
    status: 'implemented',
    test: 'packages/decisions/test/pipeline.test.ts',
  },
  {
    id: 'S8',
    source: 'spec §12.1',
    summary: 'A request attempts to reach a private or metadata network address.',
    threat: 'T12',
    stage: 'risk',
    asserts:
      'DESTINATION_NOT_PERMITTED for loopback, RFC1918, link-local (169.254.0.0/16, ' +
      'including the cloud metadata address), IPv6 equivalents, and any hostname that ' +
      'resolves into them. DNS rebinding means the check must bind to the resolved ' +
      'address actually connected to, not the name.',
    status: 'implemented',
    test: 'packages/decisions/test/risk.test.ts',
  },
  {
    id: 'S9',
    source: 'spec §12 security',
    summary: 'OAuth CSRF on the callback.',
    threat: 'T11',
    stage: 'identity',
    asserts:
      'A callback with no flow cookie, a substituted state, or a replayed one is ' +
      'refused. Covered for dashboard sign-in; the gateway OAuth flow needs its own.',
    status: 'implemented',
    test: 'apps/dashboard/test/flow-cookie.test.ts',
  },
  {
    id: 'S10',
    source: 'spec §12 security',
    summary: 'Token replay.',
    threat: 'T16',
    stage: 'identity',
    asserts:
      'A capability token minted for one audience or scope is refused at another, and ' +
      'an expired or tampered one is refused everywhere.',
    status: 'implemented',
    test: 'apps/api/test/auth.test.ts',
  },
  {
    id: 'S11',
    source: 'spec §12 security',
    summary: 'IDOR on a resource id.',
    threat: 'T10',
    stage: 'identity',
    asserts:
      'A real id from another workspace returns a 404 byte-identical to one for an id ' +
      'that exists nowhere, so existence cannot be probed.',
    status: 'implemented',
    test: 'apps/api/test/agents.test.ts',
  },
  {
    id: 'S12',
    source: 'spec §12 security',
    summary: 'Cross-tenant access.',
    threat: 'T9',
    stage: 'identity',
    asserts:
      'Denied at the application query layer and again at the RLS layer, tested ' +
      'independently — a test that only proves one has not proven defence in depth.',
    status: 'implemented',
    test: 'packages/db/test/rls.test.ts',
  },
] as const;

export const MANDATORY_SCENARIO_COUNT = 8;

export const pendingScenarios = (): readonly AdversarialScenario[] =>
  ADVERSARIAL_SCENARIOS.filter((s) => s.status === 'pending');
