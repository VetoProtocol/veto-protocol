import { randomBytes } from 'node:crypto';

/**
 * Fresh identifier with the given prefix.
 *
 * base64url alphabet matches the `[A-Za-z0-9_-]` body accepted by the id
 * validators and the database CHECK constraints, so a generated id is valid by
 * construction rather than by coincidence. 96 bits of randomness: these are
 * public identifiers, not secrets, but they must not be guessable enough to
 * make an IDOR attempt cheap.
 */
export function newId(prefix: string): string {
  return `${prefix}${randomBytes(12).toString('base64url')}`;
}
