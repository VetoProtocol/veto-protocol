/**
 * Starter policy rules.
 *
 * ## Why this exists
 *
 * Veto denies by default (invariant 2), so a workspace with no rules refuses
 * everything — and a workspace refusing everything looks exactly like a
 * workspace that is broken. Somebody who has just connected Google and
 * registered an agent sees every call denied with `TOOL_NOT_ALLOWED` and has no
 * way to tell whether they have configured nothing or configured it wrong.
 *
 * That is the gap these close. They are not a feature of the decision pipeline:
 * applying one creates ordinary rows in `policies`, identical to rules written
 * by hand, and the pipeline cannot tell the difference afterwards.
 *
 * ## They invent no semantics
 *
 * Every field here is one the rule schema already has — subject, action,
 * effect, resource filter, conditions. A template is a *selection* of existing
 * primitives with a name on it. Nothing here can express a rule somebody could
 * not have typed, which is the property that keeps this from becoming a second
 * policy language nobody reviews.
 *
 * ## A template grants nothing
 *
 * A rule says *under what conditions* an agent may act. Permit says whether the
 * agent is connected to the resource at all, and the two are deliberately not
 * derived from each other. So applying a template to an agent with no grant
 * produces rules that reach nothing — correctly, and confusingly if the screen
 * does not say so. It must say so.
 *
 * ## Overlap
 *
 * `matchPolicies` ranks deny over challenge over allow, and is order
 * independent. Two overlapping templates therefore give the stricter answer
 * where they disagree, and applying one twice changes nothing — the apply path
 * skips a rule that already exists identically.
 *
 * One consequence worth stating: a *narrower allow* added beside a broader one
 * does not narrow anything, because both match and both are allows. Restricting
 * to working hours or a daily cap means putting that condition on the rule that
 * is already there, not adding a second one next to it. There is deliberately
 * no "working hours" template for that reason — it would appear to restrict and
 * would not.
 */

import type { PolicyRule } from './types.ts';
import type { PolicyAction } from './policy-store.ts';

export interface PolicyTemplateRule {
  readonly action: PolicyAction;
  readonly effect: 'allow' | 'deny' | 'challenge';
  readonly resourceFilter: PolicyRule['resourceFilter'];
  readonly conditions: PolicyRule['conditions'];
  /** One line, for the person deciding whether to apply this. */
  readonly explains: string;
}

export interface PolicyTemplate {
  readonly id: string;
  readonly title: string;
  /** What applying this actually does, in a sentence somebody can act on. */
  readonly summary: string;
  /**
   * What has to be connected for these rules to reach anything.
   *
   * Named so a screen can say "this needs Google" rather than letting somebody
   * apply a Drive template to a workspace with no Drive connection and read the
   * resulting silence as a bug.
   */
  readonly requires: 'google' | 'github' | 'slack' | 'nothing';
  readonly rules: readonly PolicyTemplateRule[];
}

/**
 * Presence states in which a rule applies without a challenge.
 *
 * `active` alone, everywhere here, so an agent acting while the person is away
 * raises a challenge instead of proceeding quietly. Presence can only ever
 * narrow (§7.2) — naming it adds a requirement and never grants one.
 */
const WHILE_PRESENT = { presence: ['active'] } as const;

const WRITABLE_TYPES = [
  'google_file',
  'google_folder',
  'gmail_mailbox',
  'google_calendar',
  'github_repo',
  'github_account',
  'slack_workspace',
  'slack_channel',
] as const;

export const POLICY_TEMPLATES: readonly PolicyTemplate[] = [
  {
    id: 'drive-read',
    title: 'Read Drive files, while you are there',
    summary:
      'Lets an agent open files and list folders it has been granted, but only while your presence is active. Away, the same request asks you first.',
    requires: 'google',
    rules: [
      {
        action: 'read',
        effect: 'allow',
        resourceFilter: { type: 'google_file' },
        conditions: WHILE_PRESENT,
        explains: 'Open a granted file while you are present.',
      },
      {
        // `google_drive.list_folder` is action `read`, not `list`. A template
        // that guessed `list` would match no tool and deny silently, which is
        // the failure this whole feature exists to prevent.
        action: 'read',
        effect: 'allow',
        resourceFilter: { type: 'google_folder' },
        conditions: WHILE_PRESENT,
        explains: 'List a granted folder while you are present.',
      },
    ],
  },
  {
    id: 'mail-read',
    title: 'Read mail, and say why',
    summary:
      'Lets an agent search and read the connected mailbox while you are present, and only when it states what it is doing. A stated reason is a risk signal, never permission on its own.',
    requires: 'google',
    rules: [
      {
        action: 'search',
        effect: 'allow',
        resourceFilter: { type: 'gmail_mailbox' },
        conditions: { ...WHILE_PRESENT, requireIntent: true },
        explains: 'Search your mailbox, with a stated reason, while present.',
      },
      {
        action: 'read',
        effect: 'allow',
        resourceFilter: { type: 'gmail_mailbox' },
        conditions: { ...WHILE_PRESENT, requireIntent: true },
        explains: 'Open one message, with a stated reason, while present.',
      },
    ],
  },
  {
    id: 'calendar-read',
    title: 'Read the calendar, while you are there',
    summary: 'Lets an agent list events in a window and open one, while your presence is active.',
    requires: 'google',
    rules: [
      {
        action: 'search',
        effect: 'allow',
        resourceFilter: { type: 'google_calendar' },
        conditions: WHILE_PRESENT,
        explains: 'List events in a bounded window while you are present.',
      },
      {
        action: 'read',
        effect: 'allow',
        resourceFilter: { type: 'google_calendar' },
        conditions: WHILE_PRESENT,
        explains: 'Open one event while you are present.',
      },
    ],
  },
  {
    id: 'github-read',
    title: 'Read GitHub, while you are there',
    summary:
      'Lets an agent list the repositories an installation holds, and read files, issues and pull requests in the ones it has been granted.',
    requires: 'github',
    rules: [
      {
        action: 'search',
        effect: 'allow',
        resourceFilter: { type: 'github_account' },
        conditions: WHILE_PRESENT,
        explains: 'List the repositories this installation can see.',
      },
      {
        // Files, issues and pull requests are all `read` on `github_repo`:
        // their ids are not knowable before a search, so they are not Permit
        // resources and a rule cannot separate them. One rule covers all three,
        // and a template claiming to allow "issues only" would be claiming a
        // narrowing the policy layer cannot express.
        action: 'read',
        effect: 'allow',
        resourceFilter: { type: 'github_repo' },
        conditions: WHILE_PRESENT,
        explains: 'Read files, issues and pull requests in a granted repository.',
      },
      {
        action: 'search',
        effect: 'allow',
        resourceFilter: { type: 'github_repo' },
        conditions: WHILE_PRESENT,
        explains: 'Search issues in a granted repository.',
      },
    ],
  },
  {
    id: 'slack-read',
    title: 'Read Slack channels, while you are there',
    summary:
      'Lets an agent list the conversations the bot can see, and read the ones it has been invited to. A channel is granted by adding the bot to it.',
    requires: 'slack',
    rules: [
      {
        action: 'search',
        effect: 'allow',
        resourceFilter: { type: 'slack_workspace' },
        conditions: WHILE_PRESENT,
        explains: 'List the channels this installation can see.',
      },
      {
        action: 'read',
        effect: 'allow',
        resourceFilter: { type: 'slack_channel' },
        conditions: WHILE_PRESENT,
        explains: 'Read messages in a granted channel, within a bounded window.',
      },
    ],
  },
  {
    id: 'no-writes',
    title: 'Never write anything',
    summary:
      'Refuses every write, on every connected application, whatever else is allowed. Nothing can write today — no write tool exists — so this changes nothing now and keeps it true if one ever ships.',
    requires: 'nothing',
    rules: WRITABLE_TYPES.map((type) => ({
      action: 'write' as const,
      effect: 'deny' as const,
      resourceFilter: { type },
      conditions: {},
      explains: `Refuse every write to ${type}.`,
    })),
  },
];

export const findTemplate = (id: string): PolicyTemplate | null =>
  POLICY_TEMPLATES.find((t) => t.id === id) ?? null;

/**
 * Normalised JSON, so two objects that mean the same thing compare equal.
 *
 * `{type, prefix}` and `{prefix, type}` are the same filter; a textual compare
 * would call them different and duplicate the row.
 */
function stable(value: unknown): string {
  return JSON.stringify(value, (_key, inner: unknown) =>
    inner !== null && typeof inner === 'object' && !Array.isArray(inner)
      ? Object.fromEntries(
          Object.entries(inner as Record<string, unknown>).sort(([x], [y]) =>
            x < y ? -1 : x > y ? 1 : 0,
          ),
        )
      : inner,
  );
}

/**
 * Do two rules say the same thing?
 *
 * Used to skip a rule the workspace already has, so applying a template twice
 * creates nothing the second time. Compared by meaning rather than by id:
 * rules are created and deleted and never edited, so the same rule written
 * twice is two rows with two versions and one effect.
 */
export function sameRule(
  a: Pick<PolicyRule, 'subject' | 'action' | 'effect' | 'resourceFilter' | 'conditions'>,
  b: Pick<PolicyRule, 'subject' | 'action' | 'effect' | 'resourceFilter' | 'conditions'>,
): boolean {
  return (
    a.subject === b.subject &&
    a.action === b.action &&
    a.effect === b.effect &&
    stable(a.resourceFilter) === stable(b.resourceFilter) &&
    stable(a.conditions) === stable(b.conditions)
  );
}
