/**
 * Create the Permit resource model an environment needs (spec §4.2).
 *
 * Idempotent, so it is safe to run against an environment that already has
 * some of this. Run it once per environment — development, staging, production
 * — each with its own key (§16).
 *
 * Scope tracks what is actually enforced. Stage 1 needed the two types that
 * carry the delegator relation; stage 2 adds Drive, because the pipeline now
 * asks Permit about files and folders.
 *
 * `mailbox`, `calendar`, `wallet` and `contract` are still absent. §4.2 lists
 * them, but modelling a resource before anything enforces it puts policy in
 * Permit that nothing reads, and an unread policy is one nobody notices is
 * wrong. They arrive with the integrations that need them (§9.1).
 */

import { Permit } from 'permitio';
import type { PermitConfig } from './config.ts';
import {
  AGENT_RESOURCE,
  FILE_RESOURCE,
  FOLDER_RESOURCE,
  HUMAN_RESOURCE,
  RELATION_DELEGATOR,
  RELATION_PARENT,
} from './model.ts';

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

  // Drive, read-only. §9.1 starts with the narrowest read scopes and keeps
  // writes out of the MVP, so no create/update/delete/share action is declared
  // — an action Permit does not know cannot be granted by accident.
  await step(`resource:${FOLDER_RESOURCE}`, () =>
    permit.api.resources.create({
      key: FOLDER_RESOURCE,
      name: 'Google Drive folder',
      description: 'A Drive folder. Listing a folder is a separate permission from reading its files.',
      actions: { read: {}, search: {} },
      attributes: {
        sensitivity: { type: 'string', description: 'Classification label, never the content itself.' },
      },
    }),
  );

  await step(`resource:${FILE_RESOURCE}`, () =>
    permit.api.resources.create({
      key: FILE_RESOURCE,
      name: 'Google Drive file',
      description: 'One Drive file. Authorized individually on every call (invariant 9).',
      actions: { read: {}, search: {} },
      attributes: {
        sensitivity: { type: 'string', description: 'Classification label, never the content itself.' },
      },
    }),
  );

  // Defined on the file, pointing at the folder: "this file's parent is that
  // folder". Inheritance flows down — a grant on a folder can reach its files,
  // and a grant on a file never reaches the folder it sits in.
  await step(`relation:${FILE_RESOURCE}.${RELATION_PARENT}`, () =>
    permit.api.resourceRelations.create(FILE_RESOURCE, {
      key: RELATION_PARENT,
      name: 'Parent folder',
      description: 'The folder containing this file. Access flows from folder to file, never upward.',
      subject_resource: FOLDER_RESOURCE,
    }),
  );

  return { created, existing };
}

function status(error: unknown): number | undefined {
  const candidate = error as { response?: { status?: number }; status?: number };
  return candidate.response?.status ?? candidate.status;
}
