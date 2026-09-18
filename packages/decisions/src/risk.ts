/**
 * Step 6 — the checks Permit cannot express (§3.3, invariant 3).
 *
 * These run *after* `permit.check` and can only ever make the answer more
 * restrictive. Permit decides whether a relationship and its attributes allow
 * the action; whether the arguments are safe, the destination is reachable, or
 * the stated intent is present is Veto's alone.
 */

import type { EvaluateInput } from './types.ts';
import { checkDestination } from './destination.ts';

export interface RiskFinding {
  readonly reasonCode: string;
  readonly result: 'deny' | 'challenge';
  readonly message: string;
}

/**
 * Argument values that look like credentials.
 *
 * Invariant 10: credentials are never accepted through tool arguments. This is
 * not an attempt to detect every secret — it catches the shapes that show up
 * when an injected instruction tells an agent to "pass along the token", and it
 * denies rather than stripping, because a request built around a credential is
 * not a request to sanitise.
 */
const CREDENTIAL_PATTERNS: readonly RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+/-]{16,}/i,
  /\bsk-[A-Za-z0-9]{16,}/,
  /\bghp_[A-Za-z0-9]{20,}/,
  /\bAKIA[0-9A-Z]{12,}/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, // a JWT
  /\b(?:password|passwd|secret|api[_-]?key|refresh[_-]?token)\s*[:=]\s*\S{6,}/i,
];

export function findCredentialShapedArguments(args: Readonly<Record<string, unknown>>): boolean {
  const seen = new Set<unknown>();

  const walk = (value: unknown): boolean => {
    if (typeof value === 'string') {
      return CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value));
    }
    if (value === null || typeof value !== 'object') return false;
    // Arguments are caller-controlled and may be cyclic.
    if (seen.has(value)) return false;
    seen.add(value);
    return Object.values(value as Record<string, unknown>).some(walk);
  };

  return Object.values(args).some(walk);
}

export interface RiskContext {
  /** The policy asked for a stated intent before this resource is touched. */
  readonly requireIntent: boolean;
}

export async function assessRisk(
  input: EvaluateInput,
  context: RiskContext,
): Promise<RiskFinding | null> {
  if (findCredentialShapedArguments(input.arguments)) {
    return {
      reasonCode: 'SENSITIVE_ARGUMENT_BLOCKED',
      result: 'deny',
      message: 'This request carries something that looks like a credential.',
    };
  }

  if (input.destination !== null) {
    const verdict = await checkDestination(input.destination);
    if (!verdict.ok) {
      return {
        reasonCode: 'DESTINATION_NOT_PERMITTED',
        result: 'deny',
        // The reason is not echoed back: it tells a prober which ranges are
        // blocked and how the resolver behaved.
        message: 'That destination is not permitted.',
      };
    }
  }

  // Intent mismatch, deliberately narrow.
  //
  // This does not read the intent and judge it — no deterministic check can,
  // and a model judging it would be the agent approving itself. What it does is
  // enforce that a sensitive action *has* a stated intent, so there is
  // something for a human to compare against on the approval screen. It raises
  // a challenge and never an allow (FR-11).
  if (context.requireIntent) {
    const intent = input.declaredIntent?.trim() ?? '';
    if (intent.length < 8) {
      return {
        reasonCode: 'INTENT_MISMATCH',
        result: 'challenge',
        message: 'This action needs a stated purpose before it can go ahead.',
      };
    }
  }

  return null;
}
