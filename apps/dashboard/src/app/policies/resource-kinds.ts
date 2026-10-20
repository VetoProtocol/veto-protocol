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
  /**
   * What the key field is called when this kind is selected.
   *
   * The grant form said `drive id — not a path` for every kind, including a
   * Slack workspace whose key is a Veto user id. A label that names the wrong
   * thing is worse than a vague one: somebody types what it asked for, the
   * grant is refused or lands on the wrong resource, and the label is the last
   * place they look.
   */
  readonly keyLabel: string;
  /**
   * The small grey qualifier beside the label — where to find the value.
   *
   * Positive, never a negation. `not a path` told somebody what the field was
   * not, which makes them check their input against a rule instead of
   * recognising the right shape; and a warning about a likely mistake belongs
   * in the sentence underneath, not in the name of the thing.
   */
  readonly keyHint: string;
  /** A real example, shown inside the empty field. Worth more than a rule. */
  readonly keyExample?: string;
  /** One sentence saying where to find the value. */
  readonly keyHelp: string;
  /**
   * True when the key is the delegating person's Veto user id.
   *
   * Those kinds are not something to look up — an agent can only ever reach
   * the account of the person who delegated to it, so there is exactly one
   * correct value and the form fills it in.
   */
  readonly userKeyed?: boolean;
}

export const RESOURCE_KINDS: Readonly<Record<string, ResourceKind>> = {
  google_folder: {
    label: 'folder',
    reach: 'that folder',
    keyLabel: 'folder id',
    keyHint: 'from the Drive URL',
    keyExample: '1a2B3c-_9zYxWvU8t',
    keyHelp:
      'The long string in the Drive URL after /folders/. A path like /Work is not an id and will be refused.',
  },
  google_file: {
    label: 'file',
    reach: 'that file',
    keyLabel: 'file id',
    keyHint: 'from the Drive URL',
    keyExample: '1a2B3c-_9zYxWvU8t',
    keyHelp: 'The long string in the Drive URL after /d/.',
  },
  gmail_mailbox: {
    label: 'mailbox',
    reach: 'that mailbox',
    keyLabel: 'whose mailbox',
    keyHint: 'filled in for you',
    keyHelp:
      'An agent can only ever reach the mailbox of the person who delegated to it, so there is one correct value and it is already here.',
    userKeyed: true,
  },
  google_calendar: {
    label: 'calendar',
    reach: 'that calendar',
    keyLabel: 'whose calendar',
    keyHint: 'filled in for you',
    keyHelp:
      'An agent can only ever reach the calendar of the person who delegated to it, so there is one correct value and it is already here.',
    userKeyed: true,
  },
  // A GitHub grant names a repository by its numeric id, so the label is the
  // only place a reader learns what the number *is*.
  github_repo: {
    label: 'repository',
    reach: 'that repository',
    keyLabel: 'repository id',
    keyHint: 'the number, not the name',
    keyExample: '289166878',
    keyHelp:
      "GitHub's numeric id for the repository — a name would silently follow whoever registered it next after a rename. `github_repo.list_repos` returns it.",
  },
  // Named for what granting it actually does. "GitHub account" alone would read
  // as one thing; it reaches every repository beneath it, and somebody about to
  // click should see that in the sentence rather than discover it later.
  github_account: {
    label: 'GitHub account',
    reach: 'every repository under that account',
    keyLabel: 'whose account',
    keyHint: 'filled in for you',
    keyHelp:
      'Keyed by the person who installed it, not by the GitHub login — a login in the key would be a value an agent could name.',
    userKeyed: true,
  },
  // A channel is granted on Slack's side by inviting the bot, so the reach is
  // honest only if it says that: the grant permits reading, the invitation is
  // what makes the channel reachable at all.
  slack_channel: {
    label: 'channel',
    reach: 'that channel, if the bot is in it',
    keyLabel: 'channel id',
    keyHint: 'from Slack, starts with C',
    keyExample: 'C01ABCDEF2G',
    keyHelp:
      'Slack\u2019s own channel id, from `slack_channel.list_channels` or from the channel details in Slack. Granting it permits reading; the bot still has to be in the channel.',
  },
  slack_workspace: {
    label: 'Slack workspace',
    reach: 'the list of channels \u2014 not the messages in them',
    keyLabel: 'whose workspace',
    keyHint: 'filled in for you',
    keyHelp:
      'Keyed by the person who connected Slack, so no argument could name somebody else\u2019s workspace. Note this grants the channel *list* only \u2014 reading a channel is a separate grant today.',
    userKeyed: true,
  },
  outlook_mailbox: {
    label: 'Outlook mailbox',
    reach: 'that mailbox',
    keyLabel: 'whose mailbox',
    keyHint: 'filled in for you',
    keyHelp:
      'An agent can only ever reach the Microsoft 365 mailbox of the person who delegated to it, so there is one correct value and it is already here. Separate from the Gmail mailbox on purpose \u2014 a grant has to say which account it reaches.',
    userKeyed: true,
  },
  outlook_calendar: {
    label: 'Outlook calendar',
    reach: 'that calendar',
    keyLabel: 'whose calendar',
    keyHint: 'filled in for you',
    keyHelp:
      'An agent can only ever reach the Microsoft 365 calendar of the person who delegated to it, so there is one correct value and it is already here.',
    userKeyed: true,
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

/** How to ask for this kind's key. Falls back to something true but vague. */
export const kindKey = (resourceType: string): Pick<
  ResourceKind,
  'keyLabel' | 'keyHint' | 'keyHelp' | 'keyExample' | 'userKeyed'
> =>
  RESOURCE_KINDS[resourceType] ?? {
    keyLabel: 'resource id',
    keyHint: '',
    keyHelp: 'The provider\u2019s own id for this resource.',
  };
