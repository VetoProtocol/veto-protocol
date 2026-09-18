/**
 * The real `permit.check` adapter (spec §4.3).
 *
 * One question, asked one way: may this principal take this action on this
 * resource instance in this tenant. Nothing here inspects arguments, checks an
 * emergency lock, or considers credential expiry — those are Veto's and run
 * around this call, never inside it (invariant 3).
 */

import { Permit } from 'permitio';
import type { PermitConfig } from './config.ts';
import { agentUserKey, tenantKey } from './model.ts';
import type { CheckInput, PermitOutcome, PolicyDecisions } from './decisions-port.ts';

export interface PermitPolicyDecisions extends PolicyDecisions {
  close(): Promise<void>;
}

export function createPermitPolicyDecisions(config: PermitConfig): PermitPolicyDecisions {
  const permit = new Permit({
    token: config.token,
    pdp: config.pdpUrl,
    ...(config.apiUrl === undefined ? {} : { apiUrl: config.apiUrl }),
    timeout: config.timeoutMs,
    throwOnError: true,
    // permitio 2.7.6 inverts this flag and a truthy log.json crashes pino 8 at
    // construction; see the matching note in permit-facts.ts.
    log: { level: 'warn', label: 'permit-check', json: false },
  });

  return {
    async check(input: CheckInput): Promise<PermitOutcome> {
      try {
        const allowed = await permit.check(agentUserKey(input.agentId), input.action, {
          type: input.resourceType,
          key: input.resourceKey,
          tenant: tenantKey(input.workspaceId),
          ...(input.attributes === undefined ? {} : { attributes: { ...input.attributes } }),
        });
        return allowed ? 'allow' : 'deny';
      } catch {
        // Every failure is the same answer. The caller records 'unavailable'
        // and denies; a timeout versus a 500 changes nothing about what happens
        // next, and pretending otherwise invites a retry that should not exist.
        return 'unavailable';
      }
    },

    async close(): Promise<void> {
      /* the SDK holds a keep-alive pool with nothing to release today */
    },
  };
}
