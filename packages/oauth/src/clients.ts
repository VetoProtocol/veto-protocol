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

/**
 * Characters that change how a name *reads* rather than what it says.
 *
 * The consent screen shows `client_name` to a person who is deciding. React
 * escapes it, so there is no injection — but a right-to-left override reverses
 * the text after it, and somebody reading the result has been told something
 * the string does not contain. A zero-width space splits a word that looks
 * whole, so two clients can present the same name. A newline turns a name into
 * a sentence the product did not write.
 *
 *   U+0000–U+001F, U+007F–U+009F  control characters, including newlines
 *   U+200B–U+200F                 zero-width and bidi marks
 *   U+202A–U+202E                 bidi embedding and override
 *   U+2066–U+2069                 bidi isolates
 *   U+FEFF                        zero-width no-break space
 *
 * Rejected, not stripped. Silently rewriting what a client asked to be called
 * would show one name on this screen and a different one in its own interface,
 * and the person comparing them is the one this check is for.
 *
 * This is not a defence against a client that calls itself something
 * misleading in plain characters — nothing here can be. That is the consent
 * screen's wording to handle, and it does, by saying the name is self-declared
 * and showing the redirect address instead.
 */
const DECEPTIVE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f], // C0 controls, including newline and tab
  [0x007f, 0x009f], // delete and C1 controls
  [0x200b, 0x200f], // zero-width space through the bidi marks
  [0x202a, 0x202e], // bidi embedding and override
  [0x2066, 0x2069], // bidi isolates
  [0xfeff, 0xfeff], // zero-width no-break space
];

/**
 * Checked by code point rather than a character class.
 *
 * A regex with literal control characters in it is almost always a mistake —
 * lint says so, and is right — so the deliberate version says which ranges and
 * why beside each one, which a character class cannot.
 */
const isDeceptive = (name: string): boolean => {
  for (const character of name) {
    const point = character.codePointAt(0) ?? 0;
    if (DECEPTIVE_RANGES.some(([low, high]) => point >= low && point <= high)) return true;
  }
  return false;
};

export function validateRegistration(
  clientName: string,
  redirectUris: readonly string[],
): RegistrationFailure | null {
  if (clientName.trim() === '' || clientName.length > 200) return 'NAME_INVALID';
  if (isDeceptive(clientName)) return 'NAME_INVALID';
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
