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
 * Folder-to-file containment.
 *
 * Declared on the file, naming the folder as subject, so a grant on a folder
 * can reach the files inside it. The reverse never holds: being granted a file
 * says nothing about its folder.
 */
export const RELATION_PARENT = 'parent';

/** Relation-endpoint keys. */
export const agentInstanceKey = (agentId: string): string => `${AGENT_RESOURCE}:${agentId}`;
export const humanInstanceKey = (userId: string): string => `${HUMAN_RESOURCE}:${userId}`;

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
