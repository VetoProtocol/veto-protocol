/**
 * How a decision names the resource it was about.
 *
 * `decisions.resource_ref` and `audit_events.resource_ref` both hold
 * `type:key` — `google_file:1AbC`, `github_repo:524250555`. Consent Grants
 * joins a grant to its last use on that string, so the format stops being an
 * implementation detail of one writer: it becomes the only thing connecting
 * what an agent *may* reach to what it actually reached.
 *
 * It was built inline in three places in the pipeline. A join against a string
 * that three callers each format for themselves is a join that goes quietly
 * empty the day one of them changes — every grant would read "never used" and
 * the screen would look like it was working. One function, so that cannot
 * drift.
 *
 * ## Not the same as a Permit instance key
 *
 * `resourceInstanceKey` in `@veto/permit` produces the same shape and means
 * something else: Permit's own `type:key` grammar, whose keys are
 * workspace-scoped and must match `^[A-Za-z0-9\-_]+$`. This one carries the id
 * exactly as a tool call named it, which can be a Drive path. The two key
 * spaces are not interchangeable and `model.ts` says so; keeping them in
 * separate modules is what stops one being handed to the other.
 */

/** `google_folder:root`, `github_repo:524250555`. */
export const grantRef = (resourceType: string, resourceKey: string): string =>
  `${resourceType}:${resourceKey}`;

/**
 * Split one back apart, on the **first** colon only.
 *
 * A Drive id can contain a colon and a calendar id is email-shaped, so
 * splitting on the last would cut the key in half and match the wrong grant.
 * Returns null when there is no type or no key, rather than inventing an empty
 * one that would match everything.
 */
export function parseGrantRef(ref: string): { readonly type: string; readonly key: string } | null {
  const at = ref.indexOf(':');
  if (at <= 0 || at === ref.length - 1) return null;
  return { type: ref.slice(0, at), key: ref.slice(at + 1) };
}
