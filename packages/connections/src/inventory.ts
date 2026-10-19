/**
 * Who else can reach the accounts Veto is supposed to sit in front of.
 *
 * ## The problem this names
 *
 * Veto only sees what passes through it. Somebody who connects a different AI
 * tool straight to the company Drive is invisible here — and the dashboard
 * looks perfectly healthy while it happens, because every request Veto *can*
 * see is being decided correctly. A green screen is not evidence of coverage.
 *
 * This reads the other side: the list of third-party applications holding
 * standing access to a connected account, as the provider itself reports it.
 * Anything on that list which is not Veto reaches the account without Veto
 * deciding anything.
 *
 * ## Standing access, not activity
 *
 * Deliberately a list of who *can* act rather than a log of who *did*. The
 * activity version — diffing a provider's audit log against Veto's decisions —
 * is a harder problem and a later one: there is no shared identifier between
 * the two records, so matching is by actor and timestamp, and Veto's own
 * upstream calls appear in that log as the same actor doing the same thing.
 * An inventory has no such ambiguity. An app is on the list or it is not.
 *
 * ## "I could not look" is not "I looked and found nothing"
 *
 * The single most important property here, and the reason this returns a
 * result union rather than an array.
 *
 * Reading an inventory needs administrative access a connection may not have:
 * Google's is an admin-only report and does not exist for a personal account;
 * GitHub's is scoped to an organisation, so a personal account has none. A
 * reader that answered `[]` when it lacked permission would render as **"no
 * shadow agents found"** — the most dangerous sentence this product could
 * display, because it is the reassurance somebody would act on.
 *
 * So the absence of permission is a value, carrying why, and the screen has to
 * say it. This is the same shape as deny-by-default being indistinguishable
 * from a broken workspace, and it has the same fix: make the two states
 * different things rather than the same empty one.
 */

/** One third-party application holding access to a connected account. */
export interface AuthorizedApp {
  /** `google` or `github` — which account this was read from. */
  readonly provider: string;
  /** The account the inventory was taken of, as a Veto id. Never an address. */
  readonly accountRef: string;
  /** The provider's own stable id for the app. */
  readonly appId: string;
  /** What the provider calls it. Attacker-adjacent text: an app names itself. */
  readonly displayName: string;
  /** What it can reach, in the provider's own words. */
  readonly scopes: readonly string[];
  /**
   * Is this us?
   *
   * Decided by the reader against our own configured client id, never by
   * matching the display name — an app may call itself anything, and one
   * calling itself "Veto" is exactly what somebody hiding would do.
   */
  readonly isVeto: boolean;
}

/**
 * Why an inventory could not be read.
 *
 * Each of these is a different conversation with the customer, so they are
 * different values rather than one `null`.
 */
export type InventoryUnavailable =
  /** No source is wired up for this provider yet. */
  | 'not_configured'
  /** The connection exists but lacks the administrative scope to see this. */
  | 'no_admin_scope'
  /** A personal Google account. The report is a Workspace-admin feature. */
  | 'not_a_workspace_account'
  /** A personal GitHub account. The audit surface is organisation-scoped. */
  | 'not_an_organization'
  /** The provider was asked and did not answer. */
  | 'provider_unavailable';

/**
 * What a reader returns.
 *
 * `read` with an empty `apps` is a real answer: nothing but Veto reaches this
 * account. `unavailable` is the absence of an answer. They must never collapse
 * into each other.
 */
export type InventoryResult =
  | { readonly kind: 'read'; readonly apps: readonly AuthorizedApp[] }
  | { readonly kind: 'unavailable'; readonly reason: InventoryUnavailable };

/**
 * A source of one provider's inventory.
 *
 * A port, with the real Google and GitHub adapters arriving when there is an
 * account with the access to test them against. Writing them now would mean
 * shipping code nobody has ever run against the API it claims to call, which
 * is how a control comes to exist only in prose — a mistake this codebase has
 * already paid for three times.
 */
export interface AppInventorySource {
  readonly provider: string;
  /**
   * Never throws for an expected refusal. A missing scope is an answer, and
   * callers must not have to tell an exception apart from an empty list.
   */
  read(input: { readonly workspaceId: string; readonly userId: string }): Promise<InventoryResult>;
}

/** The scopes an app needs before it is worth an operator's attention. */
const INTERESTING = [
  'drive',
  'gmail',
  'mail',
  'calendar',
  'contents',
  'issues',
  'pull_requests',
  'repo',
];

/**
 * Does this app reach anything Veto is meant to be in front of?
 *
 * An app with only a sign-in scope is not a shadow agent — it cannot read a
 * file or a message. Listing it would bury the three that matter under thirty
 * that do not, and a list nobody reads protects nobody.
 *
 * Substring matching on purpose: a provider's scope strings change shape
 * between products and versions, and the cost of a false positive here is one
 * extra row on a screen while the cost of a false negative is the whole point
 * of the feature.
 */
export const reachesProtectedData = (app: AuthorizedApp): boolean =>
  app.scopes.some((scope) => {
    const lower = scope.toLowerCase();
    return INTERESTING.some((needle) => lower.includes(needle));
  });

/**
 * A source that answers from a fixture.
 *
 * Exists so the engine, the route and the screen can be built and tested
 * before any customer has the administrative access the real adapters need —
 * the same role the Permit fakes play. It refuses to construct outside a test
 * environment for the same reason they do: a fake that reached production
 * would report a clean inventory for an account nobody had actually looked at.
 */
export function createFakeInventorySource(
  provider: string,
  result: InventoryResult,
): AppInventorySource {
  if (process.env['NODE_ENV'] !== 'test') {
    throw new Error('createFakeInventorySource is for tests only');
  }

  return {
    provider,
    read: () => Promise.resolve(result),
  };
}
