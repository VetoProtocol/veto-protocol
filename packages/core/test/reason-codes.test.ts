import { describe, expect, it } from 'vitest';
import {
  describeReason,
  REASON_CODES,
  resultFor,
  UNKNOWN_REASON,
  type ReasonCode,
} from '../src/reason-codes.ts';

const codes = Object.keys(REASON_CODES) as ReasonCode[];

describe('reason code registry', () => {
  it('gives every code a user-facing message and a spec citation (§14, §16)', () => {
    for (const code of codes) {
      const spec = REASON_CODES[code];
      expect(spec.message.length, code).toBeGreaterThan(0);
      expect(spec.source.length, code).toBeGreaterThan(0);
    }
  });

  it('keeps secrets and resource contents out of messages (invariant 5)', () => {
    for (const code of codes) {
      expect(REASON_CODES[code].message).not.toMatch(/token|password|bearer|secret|challenge=/i);
    }
  });

  it('has exactly one allow code — allow is the exception, not the default', () => {
    expect(codes.filter((c) => REASON_CODES[c].result === 'allow')).toEqual(['ALLOWED_WITHIN_POLICY']);
  });

  it('only issues a challenge where a human can actually resolve it', () => {
    const challenges = codes.filter((c) => REASON_CODES[c].result === 'challenge');
    expect(challenges.sort()).toEqual(
      [
        'APPROVAL_REQUIRED',
        'INTENT_MISMATCH',
        'USER_AWAY_SENSITIVE_RESOURCE',
        'USER_AWAY_WRITE_ACTION',
      ].sort(),
    );
  });

  it('denies for an unknown code rather than throwing or allowing (invariants 1, 2)', () => {
    expect(describeReason('NOT_A_REAL_CODE')).toBe(UNKNOWN_REASON);
    expect(resultFor('NOT_A_REAL_CODE')).toBe('deny');
  });

  it('is not fooled by inherited Object properties', () => {
    // `describeReason('toString')` must not resolve to Object.prototype.toString.
    expect(resultFor('toString')).toBe('deny');
    expect(resultFor('constructor')).toBe('deny');
    expect(resultFor('__proto__')).toBe('deny');
  });

  it('never resolves emergency lock to anything but deny (invariant 1)', () => {
    expect(resultFor('WORKSPACE_LOCKED')).toBe('deny');
    expect(resultFor('POLICY_UNAVAILABLE')).toBe('deny');
    expect(resultFor('AGENT_REVOKED')).toBe('deny');
  });

  it('denies every approval-integrity failure (invariants 6, 7)', () => {
    for (const code of ['APPROVAL_EXPIRED', 'APPROVAL_REPLAYED', 'APPROVAL_DIGEST_MISMATCH', 'APPROVER_NOT_DELEGATOR']) {
      expect(resultFor(code), code).toBe('deny');
    }
  });
});
