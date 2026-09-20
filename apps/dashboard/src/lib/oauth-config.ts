import 'server-only';
import { mintCapability } from '@veto/tokens';
import { CONTROL_PLANE_AUDIENCE } from './credential';

/**
 * Where the authorization server lives, as clients will see it.
 *
 * Every URL in the discovery document is absolute and built from this, because
 * a client compares the issuer it discovered against the one in the metadata
 * and a mismatch is a mixed-up-provider attack. One value, one source.
 */
export const issuer = (): string =>
  (process.env['DASHBOARD_PUBLIC_URL'] ?? 'http://localhost:3000').replace(/\/$/, '');

/**
 * The protected resource these tokens are for.
 *
 * RFC 8707: a client names the resource it wants a token for, and the token is
 * audience-restricted to it. A token minted for the gateway must not be usable
 * anywhere else, which is already true of capability tokens — this keeps it true
 * when a client is the one asking.
 */
export const gatewayResource = (): string =>
  (process.env['VETO_GATEWAY_PUBLIC_URL'] ?? 'http://127.0.0.1:4100/mcp').replace(/\/$/, '');

export const SCOPE_OAUTH_SERVER = 'oauth-server';

/**
 * Credential for the authorization server's own storage calls.
 *
 * Carries no workspace or human, because at registration time neither exists —
 * the same inert placeholders `resolveCredential` uses, and refused everywhere
 * except the `/v1/oauth/*` routes.
 */
export const oauthServerCredential = (): string => {
  const secret = (process.env['VETO_CAPABILITY_SECRET'] ?? '').trim();
  if (secret.length < 32) throw new Error('VETO_CAPABILITY_SECRET must be at least 32 characters');
  return mintCapability(secret, {
    aud: CONTROL_PLANE_AUDIENCE,
    workspaceId: 'pending',
    humanId: 'pending',
    action: SCOPE_OAUTH_SERVER,
    resource: 'oauth',
    ttlMs: 60_000,
  });
};
