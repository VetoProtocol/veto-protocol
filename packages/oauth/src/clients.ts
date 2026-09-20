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
import { redirectUriAllowed as allowed, redirectUriMatches as matches } from './redirect.ts';

export interface OAuthClient {
  readonly id: string;
  readonly clientName: string;
  readonly redirectUris: readonly string[];
}

export type RegistrationFailure =
  | 'NAME_INVALID'
  | 'REDIRECT_URIS_MISSING'
  | 'REDIRECT_URI_INVALID';

export { redirectUriAllowed } from './redirect.ts';

/**
 * Exact match against what this client registered.
 *
 * The comparison itself lives in `redirect.ts`, which has no imports so the
 * dashboard can use it too. One copy of a security check, reachable from both
 * halves of the server.
 */
export const redirectUriMatches = (client: OAuthClient, uri: string): boolean =>
  matches(client.redirectUris, uri);

export function validateRegistration(
  clientName: string,
  redirectUris: readonly string[],
): RegistrationFailure | null {
  if (clientName.trim() === '' || clientName.length > 200) return 'NAME_INVALID';
  if (redirectUris.length === 0 || redirectUris.length > 10) return 'REDIRECT_URIS_MISSING';
  if (!redirectUris.every(allowed)) return 'REDIRECT_URI_INVALID';
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
