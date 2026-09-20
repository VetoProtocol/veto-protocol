/**
 * The Permit object vocabulary (spec §4.2).
 *
 * Every key that crosses into Permit is built here. Two reasons that matters:
 *
 *  * Key construction *is* tenant isolation. `agent:agt_x` is meaningless
 *    without the tenant it is scoped to, and a call that forgets the tenant
 *    silently asks a different question. Putting the shapes in one file makes
 *    the omission visible in review (invariant 4).
 *  * The fake and the real adapter must speak the same language. They share
 *    these helpers, so a test asserting a fact against the fake is asserting
 *    the same string the real adapter would produce.
 *
 * Two key spaces exist and are easy to confuse:
 *
 *  * **User keys** — the subject of `permit.check`. §4.2 fixes these as
 *    `human:{vetoUserId}` and `agent:{agentId}`.
 *  * **Resource-instance keys** — the endpoints of a relationship tuple, which
 *    Permit addresses as `{resourceType}:{key}`. A tuple cannot point at a user,
 *    so an agent that participates in a relation needs an instance as well.
 *
 * The same agent is therefore `agent|agt_x` as a principal and
 * `veto_agent:agt_x` as a relation endpoint. They are not interchangeable.
 *
 * ## Why `|` and not `:` in principal keys
 *
 * §4.2 writes the principal as `agent:{agentId}`, but that table is headed
 * "Suggested representation" and the suggestion does not survive contact with
 * the API: Permit validates user keys against
 *
 *     ^[A-Za-z0-9|@+\-\._]+$
 *
 * which excludes the colon, and `users.sync` answers 422. `|` is in the allowed
 * set, keeps the namespace prefix that makes the key self-describing, and is
 * already this repo's separator for subject identifiers (`oidc|usr_1` in
 * users.identity_subject). Resource-instance references are a different field
 * with a different grammar — Permit's own `type:key` — and keep the colon.
 */

/** Permit tenant. §4.2: one tenant per Veto workspace. */
export const tenantKey = (workspaceId: string): string => workspaceId;

/** Principal keys — the subject of a check. */
export const agentUserKey = (agentId: string): string => `agent|${agentId}`;
export const humanUserKey = (userId: string): string => `human|${userId}`;

/** The grammar Permit enforces on a user key. Public so a test can hold it. */
export const PERMIT_USER_KEY_PATTERN = /^[A-Za-z0-9|@+\-._]+$/;

/** Resource types that exist only to carry relations between principals. */
export const AGENT_RESOURCE = 'veto_agent';
export const HUMAN_RESOURCE = 'veto_human';

/**
 * Drive resource types (§4.2), matching the tool catalogue's resourceType.
 *
 * A file and the folder containing it are different resources with different
 * permissions — the §12.1 "authorized for one file, asks for the folder"
 * scenario is precisely this distinction.
 */
export const FILE_RESOURCE = 'google_file';
export const FOLDER_RESOURCE = 'google_folder';

/**
 * The mailbox, §4.2's `mailbox` resource type.
 *
 * One instance per *human*, keyed by the Veto user id — not `me`, which Gmail
 * uses for "the authenticated account". Two users in one workspace would share
 * a `me`, and a grant meant for one would silently cover the other.
 *
 * Individual messages are deliberately not Permit resources. Their ids are not
 * knowable before a search runs, so per-message grants could never be written
 * in advance; Permit answers "may this agent reach that person's mail at all",
 * and which messages, how many and when is the Veto rule's job at step 4.
 */
export const MAILBOX_RESOURCE = 'gmail_mailbox';

/**
 * The calendar, §4.2's `calendar` resource type.
 *
 * One instance per human, keyed by the Veto user id, for the same reason the
 * mailbox is: an agent acts for one person and reaches that person's calendar.
 * Google's own calendar ids are email-shaped (`a@b.com`, `x@group.calendar...`)
 * and would not survive Permit's instance-key grammar anyway — but the reason
 * not to use them is the delegation model, not the character set.
 */
export const CALENDAR_RESOURCE = 'google_calendar';

/**
 * Containment.
 *
 * Declared on the file *and* on the folder, both naming a folder as subject, so
 * a grant on a folder reaches the files inside it and every folder beneath it,
 * to any depth. One relation key, because it is one fact: "this thing sits in
 * that folder".
 *
 * The reverse never holds. Being granted a file says nothing about its folder,
 * which is what keeps §12.1's "authorized for one file, asks for the whole
 * folder" a denial.
 */
export const RELATION_PARENT = 'parent';

/** Relation-endpoint keys. */
export const agentInstanceKey = (agentId: string): string => `${AGENT_RESOURCE}:${agentId}`;
export const humanInstanceKey = (userId: string): string => `${HUMAN_RESOURCE}:${userId}`;

/**
 * A Drive resource as a relation endpoint: `google_folder:ws_x__1AbC`.
 *
 * The colon is Permit's own `type:key` grammar for instances, not our `|`
 * separator for principals. See the note at the top of this file — the two key
 * spaces are not interchangeable and this is the one that keeps the colon.
 */
export const resourceInstanceKey = (resourceType: string, key: string): string =>
  `${resourceType}:${key}`;

/** Separates the workspace from the resource it scopes. Two underscores, so a
 * single underscore inside a Drive id is never mistaken for the boundary. */
const SCOPE_SEPARATOR = '__';

/**
 * A resource instance key, scoped to its workspace.
 *
 * ## Why this exists
 *
 * Permit enforces uniqueness on a resource instance by `(resource, key,
 * environment)` — **not** by tenant. Two tenants cannot both hold an instance
 * called `root`; the second gets a 409 naming the first one's id, and any role
 * assigned against it lands on a resource belonging to somebody else's
 * workspace.
 *
 * Most Drive ids are globally unique and would never have collided. `root` is
 * not an id at all — it is Google's alias for "the top of *this* account's My
 * Drive" — so every workspace's first folder is the same string. The first
 * customer to grant it takes it, and every customer after them is refused.
 *
 * Scoping the key restores invariant 4 for a key space that did not have it:
 * every fact Veto writes into Permit is now addressed by workspace, the same
 * way every query, cache key and encryption context already is. It is not a
 * defence against a confused-deputy attack — the collision denies rather than
 * grants — it is the difference between a product that works for its second
 * customer and one that does not.
 *
 * The fake does not do this, deliberately. Its key space is already a map per
 * workspace, so it has no global namespace to collide in; scoping there would
 * encode an adapter's workaround into the shared vocabulary. This is the same
 * shape of asymmetry as `agent|` — an encoding one implementation needs and the
 * other does not.
 */
export const scopedInstanceKey = (workspaceId: string, key: string): string =>
  `${workspaceId}${SCOPE_SEPARATOR}${key}`;

/**
 * The resource key back out of a scoped one, or null when it belongs to another
 * workspace.
 *
 * Returning null rather than the raw string matters: a listing that fell back
 * to the unscoped value would report another tenant's resource as this
 * tenant's, which is the leak the scoping exists to prevent.
 */
export const unscopeInstanceKey = (workspaceId: string, scoped: string): string | null => {
  const prefix = `${workspaceId}${SCOPE_SEPARATOR}`;
  return scoped.startsWith(prefix) ? scoped.slice(prefix.length) : null;
};

/**
 * The only role this product grants.
 *
 * One role, read-only, because §9.1 keeps writes out of the MVP and a role that
 * can be granted is a role that will be. `reader` covers `read` and `search` on
 * files and folders, and there is deliberately no writer, owner or admin role
 * for an agent to be assigned to by accident.
 *
 * Granted on a *folder* it reaches the files inside, through the `parent`
 * relation. That inheritance is the whole reason Permit is in the design: a
 * flat list of rules cannot express "and everything under it" without
 * enumerating a Drive nobody has enumerated.
 */
export const ROLE_READER = 'reader';

/**
 * Canonical string form of a resource grant, for assertions and diffing.
 *
 * Local, like `delegatorFact` — never sent to Permit.
 */
export const grantFact = (agentId: string, resourceType: string, key: string): string =>
  `agent:${agentId}#${ROLE_READER}@${resourceType}:${key}`;

/**
 * The relation binding an agent to the human who delegated to it.
 *
 * `delegator` is taken verbatim from §4.2's relation list rather than invented.
 * It is the relation §7.1 depends on: only the original delegating user may
 * resolve that agent's challenge, and this tuple is where "original delegating
 * user" is written down.
 */
export const RELATION_DELEGATOR = 'delegator';

/**
 * Canonical string form of a stored fact, for assertions and diffing.
 *
 * Not a Permit concept and never sent to it — a local rendering, so that "what
 * does Permit hold for this workspace" has one answer both implementations
 * agree on. It keeps the colon precisely because it is ours and no API
 * validates it.
 */
export const delegatorFact = (agentId: string, ownerUserId: string): string =>
  `agent:${agentId}#owner=${ownerUserId}`;

export const roleFact = (userKey: string, role: string): string => `role:${role}@${userKey}`;

/**
 * Canonical string form of a containment tuple.
 *
 * Local, like `grantFact` and `delegatorFact` — never sent to Permit. Reads
 * child-in-parent, the direction access flows.
 */
export const parentFact = (childType: string, childKey: string, parentKey: string): string =>
  `${childType}:${childKey}#${RELATION_PARENT}@${FOLDER_RESOURCE}:${parentKey}`;
