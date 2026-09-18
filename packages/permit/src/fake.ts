/**
 * In-memory stand-in for Permit, for tests only.
 *
 * This is a fixture with a Map in it, NOT a policy engine. The failure mode it
 * guards against is real: a fake like this quietly accretes rules until it
 * becomes a shadow authorization implementation, which is exactly what
 * CLAUDE.md invariant 3 forbids. Two guards keep it honest:
 *
 *   * It refuses to load outside NODE_ENV=test, so it can never be the thing
 *     making a production decision.
 *   * It answers no authorization questions at all. It records facts. Deciding
 *     is Permit's job and is not simulated here.
 */

import { delegatorFact } from './model.ts';
import { PolicyUnavailableError, type AgentFact, type PolicyFacts } from './port.ts';

export interface FakePolicyFacts extends PolicyFacts {
  /** Make the next call fail, to exercise the fail-closed path. */
  breakNext(operation: 'syncAgent' | 'removeAgent'): void;
}

export function createFakePolicyFacts(): FakePolicyFacts {
  if (process.env['NODE_ENV'] !== 'test') {
    throw new Error(
      'createFakePolicyFacts() is test-only and must never run outside NODE_ENV=test',
    );
  }

  const facts = new Map<string, Set<string>>();
  let broken: string | null = null;

  const failIfBroken = (operation: string): void => {
    if (broken === operation) {
      broken = null;
      throw new PolicyUnavailableError(operation);
    }
  };

  const keyFor = (workspaceId: string): Set<string> => {
    let set = facts.get(workspaceId);
    if (!set) {
      set = new Set();
      facts.set(workspaceId, set);
    }
    return set;
  };

  return {
    async syncAgent(fact: AgentFact): Promise<void> {
      failIfBroken('syncAgent');
      // Shared with the real adapter so a test asserting a fact string here is
      // asserting the string Permit would actually yield.
      keyFor(fact.workspaceId).add(delegatorFact(fact.agentId, fact.ownerUserId));
    },

    async removeAgent(workspaceId: string, agentId: string): Promise<void> {
      failIfBroken('removeAgent');
      const set = keyFor(workspaceId);
      for (const fact of set) {
        if (fact.startsWith(`agent:${agentId}#`)) set.delete(fact);
      }
    },

    async factsFor(workspaceId: string): Promise<readonly string[]> {
      return [...keyFor(workspaceId)].sort();
    },

    breakNext(operation): void {
      broken = operation;
    },
  };
}
