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

import { delegatorFact, grantFact, parentFact } from './model.ts';
import {
  PolicyUnavailableError,
  type AgentFact,
  type PolicyFacts,
  type ResourceGrant,
} from './port.ts';

export interface FakePolicyFacts extends PolicyFacts {
  /** Make the next call fail, to exercise the fail-closed path. */
  breakNext(operation: 'syncAgent' | 'removeAgent' | 'grantResource' | 'revokeResource'): void;
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

    async grantResource(grant): Promise<void> {
      failIfBroken('grantResource');
      // Recorded as a fact string, like the delegator edge, so `factsFor`
      // returns one comparable list. Still no decision is modelled: nothing in
      // this file ever answers whether a grant permits anything.
      keyFor(grant.workspaceId).add(
        grantFact(grant.agentId, grant.resourceType, grant.resourceKey),
      );
    },

    async revokeResource(grant): Promise<void> {
      failIfBroken('revokeResource');
      keyFor(grant.workspaceId).delete(
        grantFact(grant.agentId, grant.resourceType, grant.resourceKey),
      );
    },

    async recordParent(link): Promise<void> {
      // Deliberately not behind `failIfBroken`. The break switch exists to test
      // that a *grant* failure denies; a containment edge grants nothing, so
      // there is no denial to assert.
      keyFor(link.workspaceId).add(
        // The parent type is part of the fact. Without it the fake cannot tell
        // a repository-in-account edge from a file-in-folder one, and the test
        // guarding exactly that distinction would pass either way.
        parentFact(link.childType, link.childKey, link.parentKey, link.parentType),
      );
    },

    async listGrants(workspaceId: string): Promise<readonly ResourceGrant[]> {
      const grants: ResourceGrant[] = [];
      for (const fact of keyFor(workspaceId)) {
        const parsed = /^agent:(.+)#reader@([^:]+):(.+)$/.exec(fact);
        if (!parsed) continue;
        const [, agentId, resourceType, resourceKey] = parsed;
        if (!agentId || !resourceType || !resourceKey) continue;
        grants.push({ workspaceId, agentId, resourceType, resourceKey });
      }
      return grants;
    },

    async factsFor(workspaceId: string): Promise<readonly string[]> {
      return [...keyFor(workspaceId)].sort();
    },

    breakNext(operation): void {
      broken = operation;
    },
  };
}
