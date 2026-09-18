/**
 * Test-only stand-in for `permit.check`.
 *
 * Holds a literal set of allowed tuples. It does **not** model Permit: no
 * relations, no inheritance, no attribute logic. That restraint is the point —
 * a fake that grows rules becomes a second authorization implementation, and
 * the tests then pass against something production does not run (invariant 3).
 *
 * A test that needs folder-to-file inheritance needs the real PDP.
 */

import type { CheckInput, PermitOutcome, PolicyDecisions } from './decisions-port.ts';

export interface FakePolicyDecisions extends PolicyDecisions {
  /** Permit one exact tuple. */
  allow(
    workspaceId: string,
    agentId: string,
    action: string,
    resourceType: string,
    resourceKey: string,
  ): void;
  /** Make the next check report an outage. */
  breakNext(): void;
  readonly calls: readonly CheckInput[];
}

export function createFakePolicyDecisions(): FakePolicyDecisions {
  if (process.env['NODE_ENV'] !== 'test') {
    throw new Error(
      'createFakePolicyDecisions() is test-only and must never run outside NODE_ENV=test',
    );
  }

  const allowed = new Set<string>();
  const calls: CheckInput[] = [];
  let broken = false;

  // JSON rather than a delimiter: a resource key is caller-controlled and could
  // contain whatever separator we picked, which would let two different tuples
  // collide into one key.
  const keyOf = (parts: readonly string[]): string => JSON.stringify(parts);

  return {
    calls,
    allow(w, a, act, rt, rk) {
      allowed.add(keyOf([w, a, act, rt, rk]));
    },
    breakNext() {
      broken = true;
    },
    async check(input: CheckInput): Promise<PermitOutcome> {
      calls.push(input);
      if (broken) {
        broken = false;
        return 'unavailable';
      }
      const present = allowed.has(
        keyOf([
          input.workspaceId,
          input.agentId,
          input.action,
          input.resourceType,
          input.resourceKey,
        ]),
      );
      return present ? 'allow' : 'deny';
    },
  };
}
