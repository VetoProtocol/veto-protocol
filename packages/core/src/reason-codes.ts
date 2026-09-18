/**
 * Reason codes and their user-facing explanations.
 *
 * Spec §16 requires these to exist *before* approval screens are built, and §14
 * requires every timeline entry to show why a decision was reached. Each decision
 * carries exactly one code.
 *
 * The spec does not enumerate the codes — only the example
 * `USER_AWAY_SENSITIVE_RESOURCE` (§5.2). This registry is ours; every entry cites
 * the spec clause it enforces so the list stays traceable rather than invented.
 */

/** Spec §5.3. These three are not interchangeable. */
export type DecisionResult = 'allow' | 'deny' | 'challenge';

/** Which pipeline step (spec §3.3) produced the code. */
export type PipelineStage =
  | 'identity'
  | 'session'
  | 'precheck'
  | 'policy'
  | 'risk'
  | 'credential'
  | 'approval'
  | 'outcome';

export interface ReasonCodeSpec {
  readonly result: DecisionResult;
  readonly stage: PipelineStage;
  /** Shown to the user. No secrets, no resource contents (invariant 5). */
  readonly message: string;
  /** Spec clause this code enforces. */
  readonly source: string;
}

const CODES = {
  // --- step 1: identity -----------------------------------------------------
  IDENTITY_UNRESOLVED: {
    result: 'deny',
    stage: 'identity',
    message: 'This request could not be linked to a known user and agent.',
    source: '§3.3.1, §7.1 fail closed',
  },
  AGENT_UNKNOWN: {
    result: 'deny',
    stage: 'identity',
    message: 'This agent is not registered in your workspace.',
    source: '§3.2 identity',
  },
  AGENT_REVOKED: {
    result: 'deny',
    stage: 'identity',
    message: 'Access for this agent was revoked.',
    source: 'FR-08, §11 revocation',
  },

  // --- step 3: session, presence, lock ---------------------------------------
  SESSION_EXPIRED: {
    result: 'deny',
    stage: 'session',
    message: 'This agent session has expired. Reconnect to continue.',
    source: '§3.3.3',
  },
  WORKSPACE_LOCKED: {
    result: 'deny',
    stage: 'session',
    message: 'Emergency lock is active. All agent access is blocked.',
    source: '§7.2 locked, invariant 1',
  },
  USER_AWAY_SENSITIVE_RESOURCE: {
    result: 'challenge',
    stage: 'session',
    message: 'Approval is required because you are away and this resource is sensitive.',
    source: '§5.2 example, §7.2 away',
  },
  USER_AWAY_WRITE_ACTION: {
    result: 'challenge',
    stage: 'session',
    message: 'Approval is required because you are away and this action changes data.',
    source: '§7.2 away',
  },
  AUTOMATION_WINDOW_VIOLATION: {
    result: 'deny',
    stage: 'session',
    message: 'This action is outside the approved automation window.',
    source: '§7.2 automation',
  },

  // --- step 4: deterministic prechecks ---------------------------------------
  TOOL_NOT_ALLOWED: {
    result: 'deny',
    stage: 'precheck',
    message: 'This agent is not permitted to use this tool.',
    source: 'FR-06, §8 authorize at call_tool',
  },
  RESOURCE_OUT_OF_SCOPE: {
    result: 'deny',
    stage: 'precheck',
    message: 'This agent is not permitted to access this resource.',
    source: '§12.1 folder-escalation scenario',
  },
  ARGUMENT_SCHEMA_INVALID: {
    result: 'deny',
    stage: 'precheck',
    message: 'The request was malformed and was not forwarded.',
    source: '§8 strict argument validation, invariant 9',
  },
  VOLUME_LIMIT_EXCEEDED: {
    result: 'deny',
    stage: 'precheck',
    message: 'This request exceeds the access volume allowed for this agent.',
    source: 'FR-06, §4.2 maximum_volume',
  },

  // --- step 5: Permit decision ------------------------------------------------
  POLICY_DENIED: {
    result: 'deny',
    stage: 'policy',
    message: 'Your policy does not permit this action.',
    source: '§4.3',
  },
  POLICY_UNAVAILABLE: {
    result: 'deny',
    stage: 'policy',
    message: 'Access is temporarily blocked because the policy service is unreachable.',
    source: '§7.3 policy outage, invariant 1',
  },

  // --- step 6: Veto-side risk checks ------------------------------------------
  INTENT_MISMATCH: {
    result: 'challenge',
    stage: 'risk',
    message: 'This request does not match the task the agent said it was doing.',
    source: 'FR-11, §7.3 indirect prompt injection',
  },
  SENSITIVE_ARGUMENT_BLOCKED: {
    result: 'deny',
    stage: 'risk',
    message: 'This request contained arguments that are not allowed.',
    source: '§4.3 note, invariant 3',
  },
  DESTINATION_NOT_PERMITTED: {
    result: 'deny',
    stage: 'risk',
    message: 'This request targeted a network address that is not allowed.',
    source: '§12.1 SSRF scenario',
  },

  // --- step 8: credentials ----------------------------------------------------
  CONNECTION_EXPIRED: {
    result: 'deny',
    stage: 'credential',
    message: 'The connection to this application has expired. Reconnect to continue.',
    source: '§4.3 note credential expiry',
  },
  CREDENTIAL_REVOKED: {
    result: 'deny',
    stage: 'credential',
    message: 'The stored credential for this application was revoked.',
    source: 'FR-08',
  },

  // --- step 7: approvals -------------------------------------------------------
  APPROVAL_REQUIRED: {
    result: 'challenge',
    stage: 'approval',
    message: 'This action needs your approval before it can run.',
    source: 'FR-07',
  },
  APPROVAL_EXPIRED: {
    result: 'deny',
    stage: 'approval',
    message: 'This approval expired. Ask the agent to request the action again.',
    source: '§12.1 replay-after-expiry, invariant 6',
  },
  APPROVAL_REPLAYED: {
    result: 'deny',
    stage: 'approval',
    message: 'This approval was already used and cannot be reused.',
    source: '§7.1 single-use challenges, invariant 6',
  },
  APPROVAL_DIGEST_MISMATCH: {
    result: 'deny',
    stage: 'approval',
    message: 'The action changed after it was approved, so the approval no longer applies.',
    source: '§7.1 action digest binding, invariant 6',
  },
  APPROVER_NOT_DELEGATOR: {
    result: 'deny',
    stage: 'approval',
    message: 'Only the person who delegated this agent can approve this action.',
    source: '§12.1 approval-link scenario, invariant 7',
  },

  // --- allow --------------------------------------------------------------------
  ALLOWED_WITHIN_POLICY: {
    result: 'allow',
    stage: 'outcome',
    message: 'Allowed by your policy.',
    source: '§5.3 allow',
  },
} as const satisfies Record<string, ReasonCodeSpec>;

export type ReasonCode = keyof typeof CODES;

export const REASON_CODES: Readonly<Record<ReasonCode, ReasonCodeSpec>> = CODES;

/**
 * Deny-by-default lookup (invariant 2). An unrecognised code cannot produce an
 * allow: it resolves to a denial rather than throwing, so a mis-typed code
 * blocks the action instead of crashing the gateway into an unhandled path.
 */
export const UNKNOWN_REASON: ReasonCodeSpec = {
  result: 'deny',
  stage: 'outcome',
  message: 'This action was blocked.',
  source: 'invariant 1 fail closed',
};

export function describeReason(code: string): ReasonCodeSpec {
  return Object.prototype.hasOwnProperty.call(CODES, code)
    ? CODES[code as ReasonCode]
    : UNKNOWN_REASON;
}

export function resultFor(code: string): DecisionResult {
  return describeReason(code).result;
}
