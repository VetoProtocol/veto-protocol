/**
 * The credential broker (spec §3.2, §3.3 step 8).
 *
 * The only thing allowed to touch a stored refresh token, and the only thing
 * that hands anything to an upstream call. What it returns is a short-lived
 * access token scoped no wider than the action needs — never the refresh token,
 * and never the vault row.
 *
 * ## The checks here are Veto's, not Permit's
 *
 * Connection status and credential expiry are checked here, every time
 * (invariant 3). Permit answers whether a relationship permits an action; it
 * has no idea whether the credential behind that action still works, and asking
 * it would be asking the wrong service a question it cannot answer.
 *
 * ## Narrowest scope
 *
 * A caller states the scopes the action needs. If the connection does not hold
 * them, the request fails rather than falling back to everything the connection
 * has — §9.1 asks for incremental, narrowest-first scopes, and silently
 * upgrading would undo that at the moment it matters.
 */

import type { Db } from '@veto/db';
import type { KeyWrapper } from '@veto/vault';
import { findConnection, revealRefreshTokenForBroker } from './store.ts';

export interface AccessGrant {
  readonly accessToken: string;
  readonly expiresAt: Date;
  readonly scopes: readonly string[];
}

/**
 * The provider boundary.
 *
 * A port so the broker is testable without the network, and so a second
 * provider does not mean a second broker.
 */
export interface UpstreamTokenExchange {
  /** Trade a refresh token for a short-lived access token. */
  refresh(refreshToken: string, scopes: readonly string[]): Promise<AccessGrant>;
  /** Tell the provider to invalidate the credential (§9.1). */
  revoke(refreshToken: string): Promise<void>;
}

export type BrokerFailure =
  | 'CONNECTION_UNKNOWN'
  | 'CREDENTIAL_REVOKED'
  | 'CONNECTION_EXPIRED'
  | 'SCOPE_NOT_GRANTED'
  | 'EXCHANGE_FAILED';

export class BrokerError extends Error {
  readonly reason: BrokerFailure;

  constructor(reason: BrokerFailure) {
    super(`Credential unavailable: ${reason}`);
    this.name = 'BrokerError';
    this.reason = reason;
  }
}

export interface MintInput {
  readonly workspaceId: string;
  readonly connectionId: string;
  /** Exactly what this one action needs. */
  readonly requiredScopes: readonly string[];
}

export async function mintUpstreamToken(
  db: Db,
  wrapper: KeyWrapper,
  exchange: UpstreamTokenExchange,
  input: MintInput,
): Promise<AccessGrant> {
  const connection = await findConnection(db, input.workspaceId, input.connectionId);

  // Tenant-scoped lookup: a connection id from another workspace is simply not
  // found, and is refused with the same answer as one that never existed.
  if (!connection) throw new BrokerError('CONNECTION_UNKNOWN');
  if (connection.status === 'revoked') throw new BrokerError('CREDENTIAL_REVOKED');
  if (connection.status === 'expired') throw new BrokerError('CONNECTION_EXPIRED');

  if (connection.expiresAt !== null && connection.expiresAt.getTime() <= Date.now()) {
    throw new BrokerError('CONNECTION_EXPIRED');
  }

  const missing = input.requiredScopes.filter((scope) => !connection.scopes.includes(scope));
  if (missing.length > 0) throw new BrokerError('SCOPE_NOT_GRANTED');

  const refreshToken = await revealRefreshTokenForBroker(
    db,
    wrapper,
    input.workspaceId,
    input.connectionId,
  );
  if (refreshToken === null) throw new BrokerError('CREDENTIAL_REVOKED');

  try {
    // Ask for what the action needs, not for what the connection holds.
    return await exchange.refresh(refreshToken, input.requiredScopes);
  } catch {
    // The provider's error text is not propagated: it is written for a
    // developer reading a console, and it can contain the request that carried
    // the credential.
    throw new BrokerError('EXCHANGE_FAILED');
  }
}

/**
 * Revoke at the provider, using the stored credential one last time.
 *
 * Called *after* the local row has been destroyed, so a provider outage leaves
 * the credential already unusable here rather than still live in both places.
 * It therefore takes the token directly — by then there is nothing left to read.
 */
export async function revokeUpstream(
  exchange: UpstreamTokenExchange,
  refreshToken: string,
): Promise<boolean> {
  try {
    await exchange.revoke(refreshToken);
    return true;
  } catch {
    // Reported, never thrown. The local credential is already gone; failing the
    // caller here would suggest the revocation did not happen locally, which is
    // the more dangerous misreading.
    return false;
  }
}
