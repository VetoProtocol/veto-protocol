/**
 * Authorization codes.
 *
 * The code is the only value in this flow that travels through a browser
 * redirect — a URL bar, a history file, a referer header, whatever else is
 * watching. Everything about how it is handled follows from that.
 *
 * ## Single use, sixty seconds
 *
 * A code is spent by the exchange that redeems it and cannot be spent twice. A
 * code that survives its exchange is a replay; one that outlives the redirect
 * is a window nobody needs. Sixty seconds is the time between a browser
 * following a redirect and a client posting to the token endpoint, with room
 * for a slow laptop.
 *
 * ## Redis, like every other short-lived single-use value here
 *
 * Same store and same reasoning as approval challenges: expiry is the store's
 * job, and a value that must vanish is better held somewhere that forgets by
 * default than in a table somebody has to sweep.
 *
 * ## What the code carries
 *
 * Everything the exchange needs to mint a token, decided at the moment a human
 * approved it: workspace, human, agent, client, and the PKCE challenge. None of
 * it is re-derived at redemption from anything the client sends, because the
 * client is exactly who must not get to change it.
 */

import { randomBytes } from 'node:crypto';

/** Long enough that guessing is not a strategy; opaque to the client. */
const CODE_BYTES = 32;

export const CODE_TTL_SECONDS = 60;

export interface CodeGrant {
  readonly workspaceId: string;
  readonly userId: string;
  readonly agentId: string;
  readonly clientId: string;
  /** Compared whole at redemption against what the client then presents. */
  readonly redirectUri: string;
  readonly codeChallenge: string;
  /** RFC 8707: the protected resource this code may be exchanged for. */
  readonly resource: string;
}

/**
 * The slice of Redis this needs, declared structurally.
 *
 * Keeps the package free of an ioredis dependency and lets a test substitute a
 * map. `set` must support NX and EX, because the atomicity is the point.
 */
export interface CodeStore {
  set(
    key: string,
    value: string,
    mode: 'EX',
    seconds: number,
    exists: 'NX',
  ): Promise<string | null>;
  /** Must return the value and delete it in one step. */
  getdel(key: string): Promise<string | null>;
}

const keyFor = (code: string): string => `veto:oauth:code:${code}`;

/**
 * Mint a code for a grant a human has just approved.
 *
 * `NX` so a collision cannot overwrite an existing grant. With 256 bits of
 * randomness that will not happen, and a silent overwrite is not the failure to
 * accept on faith.
 */
export async function issueCode(store: CodeStore, grant: CodeGrant): Promise<string> {
  const code = randomBytes(CODE_BYTES).toString('base64url');
  const stored = await store.set(
    keyFor(code),
    JSON.stringify(grant),
    'EX',
    CODE_TTL_SECONDS,
    'NX',
  );
  if (stored === null) throw new Error('authorization code collision');
  return code;
}

/**
 * Spend a code.
 *
 * `getdel` reads and deletes in one operation, so two exchanges racing the same
 * code cannot both succeed. Doing this as a read then a delete would leave a
 * window in which a replay wins, which is the whole thing being prevented.
 *
 * Returns null for a code that never existed, already expired, or was already
 * spent — deliberately the same answer for all three. Distinguishing them would
 * tell a caller whether a code was ever real.
 */
export async function redeemCode(store: CodeStore, code: string): Promise<CodeGrant | null> {
  if (code === '' || code.length > 200) return null;

  const raw = await store.getdel(keyFor(code));
  if (raw === null) return null;

  try {
    return JSON.parse(raw) as CodeGrant;
  } catch {
    // Unparseable means something other than this wrote the key. Refuse rather
    // than guess at a grant.
    return null;
  }
}
