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

/**
 * Gmail, read only. Searching and reading; there is no send scope here.
 *
 * `gmail.readonly` is a *restricted* scope in Google's classification, heavier
 * than Drive's *sensitive*. That is a verification cost, not a code one — see
 * `docs/google-setup.md`.
 */
export const GMAIL_READONLY_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';

/**
 * Calendar, read only. §9.1 begins read-only; create and update arrive later,
 * behind a step-up approval, and will need their own scope when they do.
 */
export const CALENDAR_READONLY_SCOPE = 'https://www.googleapis.com/auth/calendar.readonly';

/**
 * Which scopes each service needs, and nothing more.
 *
 * §9.1: "Do not request Gmail, Drive, and Calendar access together before the
 * user activates those integrations." So consent is per service and the caller
 * names one — a connect flow cannot ask for everything by passing a list,
 * because it does not take a list.
 *
 * Google merges grants on the same OAuth client, so activating Gmail after
 * Drive leaves the account holding both. That is the user's decision made
 * twice, which is the point; what must not happen is one screen asking for both
 * before either feature exists.
 */
export const GOOGLE_SERVICES = {
  drive: [DRIVE_READONLY_SCOPE],
  gmail: [GMAIL_READONLY_SCOPE],
  calendar: [CALENDAR_READONLY_SCOPE],
} as const satisfies Record<string, readonly string[]>;

export type GoogleService = keyof typeof GOOGLE_SERVICES;

export const GOOGLE_SERVICE_NAMES = Object.keys(GOOGLE_SERVICES) as readonly GoogleService[];

export const isGoogleService = (value: string): value is GoogleService =>
  Object.hasOwn(GOOGLE_SERVICES, value);

export interface GoogleOAuthConfig {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
}

/**
 * What building a consent URL needs — and pointedly not the client secret.
 *
 * The URL is assembled by the control plane but the browser round trip belongs
 * to the dashboard, so this narrower type is what crosses that line. Keeping
 * the secret unrepresentable here is the same move the vault makes with refresh
 * tokens: a field that does not exist cannot be handed to the wrong process.
 */
export type ConsentConfig = Pick<GoogleOAuthConfig, 'clientId' | 'redirectUri'>;

export interface CodeExchangeResult {
  readonly refreshToken: string;
  readonly scopes: readonly string[];
  readonly accessTokenExpiresAt: Date;
}

/**
 * Trade an authorization code for a refresh token.
 *
 * `redirect_uri` comes from configuration and never from the request. §12.1
 * covers exact redirect URI validation, and the way to get it exactly right is
 * to have nothing to validate: the value sent here is the one registered with
 * Google, so a caller cannot propose a different one.
 *
 * A grant with no refresh token is refused rather than stored. Google omits it
 * when the user has already consented and `prompt=consent` was not sent — the
 * result is an access token that works for an hour and a connection that dies
 * silently. Failing now is the honest outcome.
 */
export async function exchangeAuthorizationCode(
  config: GoogleOAuthConfig,
  code: string,
  codeVerifier: string,
): Promise<CodeExchangeResult> {
  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      code_verifier: codeVerifier,
      grant_type: 'authorization_code',
      redirect_uri: config.redirectUri,
    }),
  });

  if (!response.ok) throw new Error(`code exchange failed: ${response.status}`);

  const body = (await response.json()) as {
    refresh_token?: string;
    expires_in?: number;
    scope?: string;
  };

  if (typeof body.refresh_token !== 'string' || body.refresh_token === '') {
    throw new Error('code exchange returned no refresh token');
  }

  return {
    refreshToken: body.refresh_token,
    scopes: body.scope === undefined ? [] : body.scope.split(' ').filter(Boolean),
    accessTokenExpiresAt: new Date(Date.now() * 1 + (body.expires_in ?? 300) * 1000),
  };
}

/**
 * The consent URL.
 *
 * `access_type=offline` and `prompt=consent` together are what make Google
 * return a refresh token — without them a repeat authorization yields only an
 * access token, and the connection stops working an hour later.
 */
export function buildConsentUrl(
  config: ConsentConfig,
  options: { state: string; codeChallenge: string; scopes: readonly string[] },
): string {
  const url = new URL(GOOGLE_AUTH_URL);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: options.scopes.join(' '),
    state: options.state,
    code_challenge: options.codeChallenge,
    code_challenge_method: 'S256',
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: 'false',
  }).toString();
  return url.href;
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
