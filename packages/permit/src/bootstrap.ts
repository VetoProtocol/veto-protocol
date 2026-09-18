/**
 * Create the Permit resource model an environment needs (spec §4.2).
 *
 * Idempotent, so it is safe to run against an environment that already has
 * some of this. Run it once per environment — development, staging, production
 * — each with its own key (§16).
 *
 * Scope is deliberately narrow: only the two resource types that carry the
 * delegator relation. §4.2 lists eight resource types and nine actions, but
 * `google_file`, `mailbox` and the rest belong to the stage they are enforced
 * in. Modelling them now would put policy in Permit that nothing reads, and an
 * unread policy is one nobody notices is wrong.
 */

import { Permit } from 'permitio';
import type { PermitConfig } from './config.ts';
import { AGENT_RESOURCE, HUMAN_RESOURCE, RELATION_DELEGATOR } from './model.ts';

export interface BootstrapReport {
  readonly created: readonly string[];
  readonly existing: readonly string[];
}

export async function bootstrapPermitEnvironment(config: PermitConfig): Promise<BootstrapReport> {
  const permit = new Permit({
    token: config.token,
    pdp: config.pdpUrl,
    ...(config.apiUrl === undefined ? {} : { apiUrl: config.apiUrl }),
    timeout: config.timeoutMs,
    throwOnError: true,
    // `json: false` is not a typo. permitio 2.7.6 inverts this flag:
    //   prettyPrint: config.log.json ? { levelFirst: true } : false
    // and pino 8 throws on any truthy prettyPrint. So `json: true` crashes the
    // constructor, and `json: false` gives plain pino output — which is JSON,
    // because that is pino's default. The value that reads wrong is the one
    // that produces structured logs.
    log: { level: 'warn', label: 'permit-bootstrap', json: false },
  });

  const created: string[] = [];
  const existing: string[] = [];

  const step = async (label: string, fn: () => Promise<unknown>): Promise<void> => {
    try {
      await fn();
      created.push(label);
    } catch (error) {
      if (status(error) === 409) existing.push(label);
      else throw error;
    }
  };

  // Both types exist to be relation endpoints. Permit requires at least one
  // action on a resource, so each gets the single action that describes what it
  // is for; neither is granted to anyone here.
  await step(`resource:${HUMAN_RESOURCE}`, () =>
    permit.api.resources.create({
      key: HUMAN_RESOURCE,
      name: 'Veto human',
      description: 'A delegating user. Exists to be the subject of a delegator relation.',
      actions: { delegate: {} },
    }),
  );

  await step(`resource:${AGENT_RESOURCE}`, () =>
    permit.api.resources.create({
      key: AGENT_RESOURCE,
      name: 'Veto agent',
      description: 'An AI client identity. Holds no grants until a connection attaches them.',
      actions: { operate: {} },
    }),
  );

  // Defined on the agent, pointing at the human: "this agent's delegator is
  // that human". See the matching note in permit-facts.ts — the tuple's subject
  // is the human and its object is the agent.
  await step(`relation:${AGENT_RESOURCE}.${RELATION_DELEGATOR}`, () =>
    permit.api.resourceRelations.create(AGENT_RESOURCE, {
      key: RELATION_DELEGATOR,
      name: 'Delegator',
      description: 'The human who delegated to this agent. §7.1: only they may approve its challenges.',
      subject_resource: HUMAN_RESOURCE,
    }),
  );

  return { created, existing };
}

function status(error: unknown): number | undefined {
  const candidate = error as { response?: { status?: number }; status?: number };
  return candidate.response?.status ?? candidate.status;
}
