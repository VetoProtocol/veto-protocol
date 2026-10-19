/**
 * How each grantable resource type is named on screen, and what connecting one
 * actually gets you.
 *
 * This exists because the same two-way check was written twice — in the grant
 * form's success notice and in the connected-resources table — and both read
 * `=== 'google_folder' ? 'folder' : 'file'`. A mailbox grant was stored
 * correctly and then described as a *file* in both places, so the screen
 * contradicted the database and the person reading it had no way to tell which
 * was wrong.
 *
 * It is a plain module, not part of `actions.ts`, because that file is
 * `'use server'` and may export only async functions — a constant beside the
 * actions is refused at runtime, which `next build` does not catch.
 *
 * Keys must stay in step with `GRANTABLE` in `apps/api/src/routes/grants.ts`;
 * `test/resource-kinds.test.ts` fails when they drift.
 */

export interface ResourceKind {
  /** The word for this kind in a table cell. */
  readonly label: string;
  /** What the agent can now reach, for the sentence after a grant lands. */
  readonly reach: string;
}

export const RESOURCE_KINDS: Readonly<Record<string, ResourceKind>> = {
  google_folder: { label: 'folder', reach: 'that folder' },
  google_file: { label: 'file', reach: 'that file' },
  gmail_mailbox: { label: 'mailbox', reach: 'that mailbox' },
  google_calendar: { label: 'calendar', reach: 'that calendar' },
  // A GitHub grant names a repository by its numeric id, so the label is the
  // only place a reader learns what the number *is*.
  github_repo: { label: 'repository', reach: 'that repository' },
  // Named for what granting it actually does. "GitHub account" alone would read
  // as one thing; it reaches every repository beneath it, and somebody about to
  // click should see that in the sentence rather than discover it later.
  github_account: { label: 'GitHub account', reach: 'every repository under that account' },
  // A channel is granted on Slack's side by inviting the bot, so the reach is
  // honest only if it says that: the grant permits reading, the invitation is
  // what makes the channel reachable at all.
  slack_channel: { label: 'channel', reach: 'that channel, if the bot is in it' },
  slack_workspace: {
    label: 'Slack workspace',
    reach: 'the list of channels \u2014 not the messages in them',
  },
};

/**
 * Never invent a word for a type we do not know. Showing the raw type is ugly
 * and honest; showing "file" for a calendar is neither.
 */
export const kindLabel = (resourceType: string): string =>
  RESOURCE_KINDS[resourceType]?.label ?? resourceType;

export const kindReach = (resourceType: string): string =>
  RESOURCE_KINDS[resourceType]?.reach ?? 'that resource';
