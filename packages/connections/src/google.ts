/**
 * Google as an UpstreamTokenExchange (spec §9, §15).
 *
 * Only the two calls the broker needs: refresh, and revoke. The authorization
 * code flow lives with the HTTP route that runs it, because PKCE and the state
 * cookie belong to a request, not to a token exchange.
 *
 * Scopes start narrow and stay narrow (§9.1): Drive read-only, and nothing is
 * requested for Gmail or Calendar until those integrations exist.
 */

import type { AccessGrant, UpstreamTokenExchange } from './broker.ts';

export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const GOOGLE_REVOKE_URL = 'https://oauth2.googleapis.com/revoke';
export const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';

/** Drive, read only. The narrowest scope that supports reading a named file. */
export const DRIVE_READONLY_SCOPE = 'https://www.googleapis.com/auth/drive.readonly';

export interface GoogleOAuthConfig {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
}

export function createGoogleExchange(config: GoogleOAuthConfig): UpstreamTokenExchange {
  return {
    async refresh(refreshToken: string): Promise<AccessGrant> {
      // Google does not narrow scopes at refresh time — the grant is fixed when
      // the user consents. The broker still states what it needs, and the
      // narrowing that matters happens at consent (§9.1) and in the policy
      // decision that preceded this call.
      const response = await fetch(GOOGLE_TOKEN_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: config.clientId,
          client_secret: config.clientSecret,
          refresh_token: refreshToken,
          grant_type: 'refresh_token',
        }),
      });

      if (!response.ok) throw new Error(`token refresh failed: ${response.status}`);

      const body = (await response.json()) as {
        access_token?: string;
        expires_in?: number;
        scope?: string;
      };

      if (typeof body.access_token !== 'string' || body.access_token === '') {
        throw new Error('token refresh returned no access token');
      }

      // A short default rather than a long one if the provider omits it: an
      // access token believed to live longer than it does is used after it is
      // dead, and the failure surfaces as an upstream error at the worst moment.
      const lifetimeSeconds = typeof body.expires_in === 'number' ? body.expires_in : 300;

      return {
        accessToken: body.access_token,
        expiresAt: new Date(Date.now() + lifetimeSeconds * 1000),
        scopes: body.scope === undefined ? [] : body.scope.split(' ').filter(Boolean),
      };
    },

    async revoke(refreshToken: string): Promise<void> {
      const response = await fetch(GOOGLE_REVOKE_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: refreshToken }),
      });

      // Google answers 200 for an already-invalid token, so anything else is a
      // real failure worth reporting to the caller.
      if (!response.ok) throw new Error(`revocation failed: ${response.status}`);
    },
  };
}
