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
 * `wallet` and `contract` are still absent. §4.2 lists them, but
 * modelling a resource before anything enforces it puts policy in Permit that
 * nothing reads, and an unread policy is one nobody notices is wrong. They
 * arrive with the integrations that need them (§9.1). `mailbox` and `calendar`
 * arrived with Gmail and Calendar, on exactly that rule.
 */

import { Permit } from 'permitio';
import type { PermitConfig } from './config.ts';
import {
  AGENT_RESOURCE,
  CALENDAR_RESOURCE,
  FILE_RESOURCE,
  FOLDER_RESOURCE,
  GITHUB_ACCOUNT_RESOURCE,
  GITHUB_REPO_RESOURCE,
  HUMAN_RESOURCE,
  MAILBOX_RESOURCE,
  SLACK_CHANNEL_RESOURCE,
  SLACK_WORKSPACE_RESOURCE,
  RELATION_DELEGATOR,
  RELATION_PARENT,
  ROLE_READER,
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

  // A folder inside a folder, so containment is transitive.
  //
  // Declared on the folder and naming a folder as subject — the same relation
  // key as the file's, because it is the same fact: "this thing sits in that
  // folder". Without it, inheritance stops at the first level and a grant on
  // the Drive root reaches loose files but nothing in any subfolder, which
  // looks like a working grant right up until somebody opens a folder.
  await step(`relation:${FOLDER_RESOURCE}.${RELATION_PARENT}`, () =>
    permit.api.resourceRelations.create(FOLDER_RESOURCE, {
      key: RELATION_PARENT,
      name: 'Parent folder',
      description: 'The folder containing this folder. Access flows downward only.',
      subject_resource: FOLDER_RESOURCE,
    }),
  );

  // The one role an agent can hold, and the reason Permit is in the design.
  //
  // Without a role there is nothing to assign, which is the gap this closes:
  // `syncAgent` could create an agent principal and `removeAgent` could delete
  // it, and nothing in between could ever connect it to a resource. Every check
  // therefore denied, whatever a Veto rule said.
  //
  // Read-only, because §9.1 keeps writes out of the MVP. An action Permit does
  // not know cannot be granted by accident, and a role that cannot write cannot
  // be talked into writing.
  //
  // It inherits from itself through `parent`: a reader of a folder is a reader
  // of every folder inside it, to any depth. Combined with the file rule below,
  // one grant on a folder reaches the whole tree under it.
  const folderReader = {
    key: ROLE_READER,
    name: 'Folder reader',
    description: 'May list this folder and read the files and folders inside it.',
    permissions: ['read', 'search'],
    granted_to: {
      users_with_role: [
        {
          linked_by_relation: RELATION_PARENT,
          on_resource: FOLDER_RESOURCE,
          role: ROLE_READER,
        },
      ],
    },
  };

  // Upsert rather than create. An environment bootstrapped before folder
  // nesting existed already has this role *without* `granted_to`, and a plain
  // create would 409, be recorded as "existing", and leave the derivation
  // silently absent — the exact failure this step is here to fix.
  await step(`role:${FOLDER_RESOURCE}.${ROLE_READER}`, async () => {
    try {
      await permit.api.resourceRoles.create(FOLDER_RESOURCE, folderReader);
    } catch (error) {
      if (status(error) !== 409) throw error;
      await permit.api.resourceRoles.update(FOLDER_RESOURCE, ROLE_READER, {
        description: folderReader.description,
        permissions: folderReader.permissions,
        granted_to: folderReader.granted_to,
      });
      // Re-thrown so `step` files it under "existing": the role was already
      // there, it has just been brought up to date.
      throw error;
    }
  });

  // The inheritance. A reader of the folder is a reader of every file whose
  // `parent` is that folder — the thing a flat list of rules cannot express
  // without enumerating a Drive nobody has enumerated.
  //
  // One direction only. Being granted a file says nothing about the folder it
  // sits in, so §12.1's "authorized for one file, asks for the whole folder"
  // stays a denial.
  await step(`role:${FILE_RESOURCE}.${ROLE_READER}`, () =>
    permit.api.resourceRoles.create(FILE_RESOURCE, {
      key: ROLE_READER,
      name: 'File reader',
      description: 'May read this file. Also held by anyone who reads its parent folder.',
      permissions: ['read', 'search'],
      granted_to: {
        users_with_role: [
          {
            linked_by_relation: RELATION_PARENT,
            on_resource: FOLDER_RESOURCE,
            role: ROLE_READER,
          },
        ],
      },
    }),
  );

  // Gmail, read only (§9.1). `send` is not declared, so sending is not an
  // action Permit knows — it cannot be granted, mistyped into a rule, or
  // reached by a role that drifts.
  await step(`resource:${MAILBOX_RESOURCE}`, () =>
    permit.api.resources.create({
      key: MAILBOX_RESOURCE,
      name: 'Gmail mailbox',
      description:
        "One person's mail. Messages are not modelled: their ids cannot be known before a search runs, so which messages is a Veto rule's job.",
      actions: { read: {}, search: {} },
      attributes: {
        sensitivity: { type: 'string', description: 'Classification label, never the content itself.' },
      },
    }),
  );

  await step(`role:${MAILBOX_RESOURCE}.${ROLE_READER}`, () =>
    permit.api.resourceRoles.create(MAILBOX_RESOURCE, {
      key: ROLE_READER,
      name: 'Mailbox reader',
      description: 'May search and read this mailbox. Cannot send: no send action exists.',
      permissions: ['read', 'search'],
    }),
  );

  // Calendar, read only (§9.1: "Begin read-only; create/update requires
  // step-up approval in later releases"). No create or update action is
  // declared, so the later release has to come back here and say so out loud.
  await step(`resource:${CALENDAR_RESOURCE}`, () =>
    permit.api.resources.create({
      key: CALENDAR_RESOURCE,
      name: 'Google Calendar',
      description:
        "One person's calendar. Keyed by Veto user id, not by Google's calendar id: an agent reaches the calendar of the person who delegated to it.",
      actions: { read: {}, search: {} },
      attributes: {
        sensitivity: { type: 'string', description: 'Classification label, never the content itself.' },
      },
    }),
  );

  await step(`role:${CALENDAR_RESOURCE}.${ROLE_READER}`, () =>
    permit.api.resourceRoles.create(CALENDAR_RESOURCE, {
      key: ROLE_READER,
      name: 'Calendar reader',
      description: 'May list and read this calendar. Cannot create or change events.',
      permissions: ['read', 'search'],
    }),
  );

  // GitHub, read only. Same shape as Drive and for the same reason: a
  // container whose reader role flows down to the things inside it.
  //
  // The account is the container. A repository is the thing a grant usually
  // names, and it is keyed by GitHub's numeric id — `owner/repo` does not
  // survive Permit's instance-key grammar, and an id survives a rename.
  await step(`resource:${GITHUB_ACCOUNT_RESOURCE}`, () =>
    permit.api.resources.create({
      key: GITHUB_ACCOUNT_RESOURCE,
      name: 'GitHub account',
      description:
        'One GitHub organisation or user that installed the app. Keyed by login. Exists so "which repositories can I see" has something to be authorised against.',
      actions: { search: {} },
      attributes: {
        sensitivity: {
          type: 'string',
          description: 'Classification label, never the content itself.',
        },
      },
    }),
  );

  await step(`resource:${GITHUB_REPO_RESOURCE}`, () =>
    permit.api.resources.create({
      key: GITHUB_REPO_RESOURCE,
      name: 'GitHub repository',
      description:
        "One repository, keyed by GitHub's numeric id. Files, issues and pull requests are not separate resources — their ids are not knowable before a search, so Permit answers whether the repository is reachable and a Veto rule says under what conditions.",
      actions: { read: {}, search: {} },
      attributes: {
        sensitivity: {
          type: 'string',
          description: 'Classification label, never the content itself.',
        },
      },
    }),
  );

  // Declared on the repository, naming the account: "this repository belongs to
  // that account". Downward only, like the folder relation — being granted one
  // repository says nothing about the account, so it cannot be turned into a
  // list of everything the installation can see.
  await step(`relation:${GITHUB_REPO_RESOURCE}.${RELATION_PARENT}`, () =>
    permit.api.resourceRelations.create(GITHUB_REPO_RESOURCE, {
      key: RELATION_PARENT,
      name: 'Owning account',
      description:
        'The account this repository belongs to. Access flows from account to repository, never upward.',
      subject_resource: GITHUB_ACCOUNT_RESOURCE,
    }),
  );

  await step(`role:${GITHUB_ACCOUNT_RESOURCE}.${ROLE_READER}`, () =>
    permit.api.resourceRoles.create(GITHUB_ACCOUNT_RESOURCE, {
      key: ROLE_READER,
      name: 'Account reader',
      description: 'May list the repositories this installation can see.',
      permissions: ['search'],
    }),
  );

  // The inheritance, and the reason the account resource exists at all: an
  // operator who grants the account reaches every repository under it, without
  // enumerating repositories nobody has enumerated.
  //
  // Nothing writes that account grant automatically. An edge beneath an
  // ungranted account reaches nobody, exactly as a folder edge does.
  await step(`role:${GITHUB_REPO_RESOURCE}.${ROLE_READER}`, () =>
    permit.api.resourceRoles.create(GITHUB_REPO_RESOURCE, {
      key: ROLE_READER,
      name: 'Repository reader',
      description:
        'May browse and read this repository, its issues and its pull requests. Also held by anyone who reads the owning account.',
      permissions: ['read', 'search'],
      granted_to: {
        users_with_role: [
          {
            linked_by_relation: RELATION_PARENT,
            on_resource: GITHUB_ACCOUNT_RESOURCE,
            role: ROLE_READER,
          },
        ],
      },
    }),
  );

  await step(`resource:${SLACK_WORKSPACE_RESOURCE}`, () =>
    permit.api.resources.create({
      key: SLACK_WORKSPACE_RESOURCE,
      name: 'Slack workspace',
      description:
        'One installed Slack workspace, keyed by the Veto user id. Exists so "which channels can I see" has something to be authorised against, and so no argument could name somebody else\'s workspace.',
      actions: { search: {} },
      attributes: {
        sensitivity: {
          type: 'string',
          description: 'Classification label, never the content itself.',
        },
      },
    }),
  );

  await step(`resource:${SLACK_CHANNEL_RESOURCE}`, () =>
    permit.api.resources.create({
      key: SLACK_CHANNEL_RESOURCE,
      name: 'Slack channel',
      description:
        "One conversation, keyed by Slack's own channel id. A channel is a resource where a message is not: its id is knowable before any call, which is how somebody grants one in advance.",
      actions: { read: {} },
      attributes: {
        sensitivity: {
          type: 'string',
          description: 'Classification label, never the content itself.',
        },
      },
    }),
  );

  // Declared on the channel, naming the workspace. Downward only, like the
  // folder and repository relations: being granted one channel says nothing
  // about the workspace, so it cannot be turned into a list of every
  // conversation the bot can see.
  await step(`relation:${SLACK_CHANNEL_RESOURCE}.${RELATION_PARENT}`, () =>
    permit.api.resourceRelations.create(SLACK_CHANNEL_RESOURCE, {
      key: RELATION_PARENT,
      name: 'Owning workspace',
      description:
        'The workspace this channel belongs to. Access flows from workspace to channel, never upward.',
      subject_resource: SLACK_WORKSPACE_RESOURCE,
    }),
  );

  await step(`role:${SLACK_WORKSPACE_RESOURCE}.${ROLE_READER}`, () =>
    permit.api.resourceRoles.create(SLACK_WORKSPACE_RESOURCE, {
      key: ROLE_READER,
      name: 'Workspace reader',
      description: 'May list the channels this installation can see.',
      permissions: ['search'],
    }),
  );

  // Inheritance, with one honest limit: granting the workspace reaches every
  // channel *Permit* knows about, and Permit only knows the ones something
  // wrote an edge for. Nothing writes those edges yet — there is no Slack
  // equivalent of `/v1/grants/github/sync` — so today a workspace grant
  // reaches no channel and a channel must be granted directly. The relation
  // exists so that sync, when it is written, has somewhere to write to.
  await step(`role:${SLACK_CHANNEL_RESOURCE}.${ROLE_READER}`, () =>
    permit.api.resourceRoles.create(SLACK_CHANNEL_RESOURCE, {
      key: ROLE_READER,
      name: 'Channel reader',
      description:
        'May read messages in this channel, within whatever window a Veto rule allows. Also held by anyone who reads the owning workspace.',
      permissions: ['read'],
      granted_to: {
        users_with_role: [
          {
            linked_by_relation: RELATION_PARENT,
            on_resource: SLACK_WORKSPACE_RESOURCE,
            role: ROLE_READER,
          },
        ],
      },
    }),
  );

  return { created, existing };
}

function status(error: unknown): number | undefined {
  const candidate = error as { response?: { status?: number }; status?: number };
  return candidate.response?.status ?? candidate.status;
}
