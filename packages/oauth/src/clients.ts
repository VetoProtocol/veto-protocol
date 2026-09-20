/**
 * Dynamically registered clients (RFC 7591).
 *
 * ## Registration is open, and that is the design
 *
 * A desktop MCP client on a customer's laptop arrives with no credential and no
 * way to obtain one. Requiring authentication to register would mean issuing
 * client ids by hand to every customer's machine, which is the problem this
 * whole feature exists to remove.
 *
 * What makes it safe is not a check here. It is that **a registered client
 * holds no authority**: it is a name and a list of redirect URIs. It cannot
 * read, decide, or be granted anything. It can ask a human to approve it, and
 * the human sees what they are approving. Registration creates a name, not a
 * capability.
 */

import { newId } from '@veto/core';
import type { Db } from '@veto/db';

export interface OAuthClient {
  readonly id: string;
  readonly clientName: string;
  readonly redirectUris: readonly string[];
}

export type RegistrationFailure =
  | 'NAME_INVALID'
  | 'REDIRECT_URIS_MISSING'
  | 'REDIRECT_URI_INVALID';

/** RFC 8252: a native client redirects to loopback or a private-use scheme. */
const LOOPBACK = /^http:\/\/(127\.0\.0\.1|\[::1\])(:\d{1,5})?(\/.*)?$/;
const PRIVATE_SCHEME = /^[a-z][a-z0-9+.-]*:\/(\/)?[^\s]*$/;

/**
 * Is this somewhere a code may be sent?
 *
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

  // A private-use scheme (`com.example.app:/callback`) belongs to an installed
  // application and never leaves the device.
  return PRIVATE_SCHEME.test(uri);
}

/**
 * Exact match, whole string.
 *
 * Not a prefix, not a normalised comparison, not "same origin". Every published
 * open-redirect in an otherwise correct authorization server comes from
 * loosening this one comparison, and there is no version of "close enough" that
 * an attacker cannot construct a URI for.
 */
export const redirectUriMatches = (client: OAuthClient, uri: string): boolean =>
  client.redirectUris.includes(uri);

export function validateRegistration(
  clientName: string,
  redirectUris: readonly string[],
): RegistrationFailure | null {
  if (clientName.trim() === '' || clientName.length > 200) return 'NAME_INVALID';
  if (redirectUris.length === 0 || redirectUris.length > 10) return 'REDIRECT_URIS_MISSING';
  if (!redirectUris.every(redirectUriAllowed)) return 'REDIRECT_URI_INVALID';
  return null;
}

export async function registerClient(
  db: Db,
  input: { clientName: string; redirectUris: readonly string[] },
): Promise<OAuthClient> {
  const id = newId('oac_');
  await db.query(
    `insert into oauth_clients (id, client_name, redirect_uris) values ($1, $2, $3)`,
    [id, input.clientName, [...input.redirectUris]],
  );
  return { id, clientName: input.clientName, redirectUris: [...input.redirectUris] };
}

export async function findClient(db: Db, clientId: string): Promise<OAuthClient | null> {
  const { rows } = await db.query<{
    id: string;
    client_name: string;
    redirect_uris: string[];
  }>(`select id, client_name, redirect_uris from oauth_clients where id = $1`, [clientId]);

  const row = rows[0];
  return row === undefined
    ? null
    : { id: row.id, clientName: row.client_name, redirectUris: row.redirect_uris };
}
