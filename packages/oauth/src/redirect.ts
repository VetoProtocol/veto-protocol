/**
 * Where an authorization code may be delivered.
 *
 * ## Why this is its own file with no imports
 *
 * The dashboard sets `allowImportingTsExtensions: false`, so it cannot import a
 * module that re-exports with `.ts` specifiers — which the package index does.
 * These two functions are the one piece of this package the browser-facing half
 * needs, and duplicating a security check so two copies can drift is worse than
 * a second entry point.
 *
 * So: no relative imports here, ever. Adding one breaks the dashboard's build
 * in a way that looks unrelated to the change that caused it.
 */

/** RFC 8252: a native client redirects to loopback or a private-use scheme. */
const LOOPBACK = /^http:\/\/(127\.0\.0\.1|\[::1\])(:\d{1,5})?(\/.*)?$/;
const PRIVATE_SCHEME = /^[a-z][a-z0-9+.-]*:\/(\/)?[^\s]*$/;

/**
 * Plain `http://` is refused except on loopback, because a code in transit over
 * cleartext to anywhere but this machine is a code somebody else also has.
 * `localhost` by name is refused in favour of the literal address: name
 * resolution is one more thing between the browser and the intended listener.
 */
export function redirectUriAllowed(uri: string): boolean {
  if (uri.length > 2048) return false;
  // A fragment is never part of a redirect URI (RFC 6749 §3.1.2) and is a
  // classic way to smuggle one target inside another.
  if (uri.includes('#')) return false;

  if (uri.startsWith('https://')) return true;
  if (LOOPBACK.test(uri)) return true;
  if (uri.startsWith('http://')) return false;

  return PRIVATE_SCHEME.test(uri);
}

/**
 * Exact match, whole string.
 *
 * Not a prefix, not a normalised comparison, not "same origin". Every published
 * open redirect in an otherwise correct authorization server comes from
 * loosening this one comparison, and there is no version of "close enough" that
 * an attacker cannot construct a URI for.
 */
export const redirectUriMatches = (
  registered: readonly string[],
  uri: string,
): boolean => registered.includes(uri);
