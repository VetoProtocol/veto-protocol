/**
 * Microsoft 365 as an UpstreamTokenExchange (spec §9, §15).
 *
 * The fourth provider, and the one that sits closest to Google: an ordinary
 * authorization-code flow with PKCE, a client secret on the control plane, and
 * a refresh token in the vault. Three things make it its own file rather than a
 * parameter on Google's, and each was measured against the protocol reference
 * before any of this was written. `docs/microsoft-setup.md` carries the
 * evidence; the consequences are here.
 *
 * ## It narrows at mint time — like GitHub, unlike Google
 *
 * The refresh grant's `scope` "must be equivalent to or a subset of the scopes
 * requested in the original authorization_code request leg". So the scopes a
 * tool asks for are **forwarded**, and a calendar read receives a token that
 * physically cannot read mail.
 *
 * That is a real control, not bookkeeping, which is why `refresh` takes the
 * scopes seriously where `slack.ts` deliberately ignores them. A reader of
 * `UPSTREAM_FOR_TOOL` should not assume every provider narrows the same way —
 * three of the four now behave differently.
 *
 * One rule rides along: every scope in one refresh must belong to a **single
 * resource**. Microsoft issues a token for whichever resource the first scope
 * names and ignores the rest, so a mixed list does not fail, it silently
 * returns the wrong token. Everything here is Graph, so the rule holds by
 * construction — `assertOneResource` makes that an assertion rather than a
 * hope, because the failure would otherwise surface as an upstream 403 on a
 * tool that looked correctly configured.
 *
 * ## The refresh token rotates, and the old one keeps working
 *
 * Microsoft returns a new refresh token on every refresh and, unlike Slack,
 * does **not** invalidate the previous one. The reference says to discard it
 * yourself. So `rotatedRefreshToken` is returned on every successful refresh
 * and the broker overwrites the ciphertext in place — there is no second copy
 * of a working credential anywhere.
 *
 * Returned rather than written here, so a provider adapter stays a thing that
 * talks to a provider.
 *
 * ## There is no way to revoke one refresh token
 *
 * Google has a revocation endpoint, Slack has `auth.revoke`, GitHub has an
 * installation to delete. Microsoft has no RFC 7009 endpoint and no per-token
 * equivalent. The nearest thing, Graph's `revokeSignInSessions`, kills every
 * application's tokens for that person and needs an administrator permission —
 * revoking Veto would sign them out of Outlook and Teams.
 *
 * So `revoke` makes **no provider call** and says so. See the note on it below:
 * a best-effort call to a far broader endpoint would read as a tighter control
 * than it is, which is the failure mode this repo has already paid for three
 * times in the GitHub path.
 */

import type { AccessGrant, UpstreamTokenExchange } from './broker.ts';

/**
 * Work and school accounts only.
 *
 * `common` would also admit personal Microsoft accounts, whose Graph surface
 * differs and whose mailbox is not a Microsoft 365 mailbox. The product says
 * Microsoft 365, so the endpoint says `organizations`.
 */
export const MICROSOFT_TENANT_AUDIENCE = 'organizations';

const AUTHORITY = `https://login.microsoftonline.com/${MICROSOFT_TENANT_AUDIENCE}`;

export const MICROSOFT_AUTH_URL = `${AUTHORITY}/oauth2/v2.0/authorize`;
export const MICROSOFT_TOKEN_URL = `${AUTHORITY}/oauth2/v2.0/token`;

export const GRAPH_API_URL = 'https://graph.microsoft.com/v1.0';

/**
 * The refresh token itself. Not a permission — the thing that makes the
 * connection outlive one hour.
 *
 * Microsoft returns no refresh token at all without it, which produces a
 * connection that works and then dies unattended. `exchangeMicrosoftCode`
 * refuses that outcome rather than storing it.
 */
export const MICROSOFT_OFFLINE_SCOPE = 'offline_access';

/** Who connected. Needed to name the account on screen, and nothing more. */
export const MICROSOFT_USER_READ_SCOPE = 'https://graph.microsoft.com/User.Read';

/** Outlook mail, read only. There is no send scope here and no write scope. */
export const MICROSOFT_MAIL_READ_SCOPE = 'https://graph.microsoft.com/Mail.Read';

/** Outlook calendar, read only. Create and update would need their own scope. */
export const MICROSOFT_CALENDAR_READ_SCOPE = 'https://graph.microsoft.com/Calendars.Read';

/**
 * Which scopes each service needs, and nothing more.
 *
 * Mirrors `GOOGLE_SERVICES`, `GITHUB_SERVICES` and `SLACK_SERVICES`: consent is
 * per service and the caller names one, so a connect flow cannot ask for
 * everything by passing a list — it does not take a list (§9.1).
 *
 * `offline_access` and `User.Read` are in both because they are not features:
 * one buys the refresh token, the other names the account that granted it.
 */
export const MICROSOFT_SERVICES = {
  mail: [MICROSOFT_OFFLINE_SCOPE, MICROSOFT_USER_READ_SCOPE, MICROSOFT_MAIL_READ_SCOPE],
  calendar: [MICROSOFT_OFFLINE_SCOPE, MICROSOFT_USER_READ_SCOPE, MICROSOFT_CALENDAR_READ_SCOPE],
} as const satisfies Record<string, readonly string[]>;

export type MicrosoftService = keyof typeof MICROSOFT_SERVICES;

export const MICROSOFT_SERVICE_NAMES = Object.keys(
  MICROSOFT_SERVICES,
) as readonly MicrosoftService[];

export const isMicrosoftService = (value: string): value is MicrosoftService =>
  Object.hasOwn(MICROSOFT_SERVICES, value);

export interface MicrosoftOAuthConfig {
  readonly clientId: string;
  /** Never in the vault, never in a response, never in a log. */
  readonly clientSecret: string;
  /** Must match the registration exactly. Comes from config, never a request. */
  readonly redirectUri: string;
}

/**
 * What building a consent URL needs — and pointedly not the client secret.
 *
 * The same narrowing `ConsentConfig` does for Google: the dashboard runs the
 * browser round trip, so the narrower type is what crosses that line. A field
 * that does not exist cannot be handed to the wrong process.
 */
export type MicrosoftConsentConfig = Pick<MicrosoftOAuthConfig, 'clientId' | 'redirectUri'>;

/**
 * Scopes that name no Graph resource — the OIDC-style ones Microsoft accepts
 * alongside any resource.
 */
const RESOURCE_FREE: ReadonlySet<string> = new Set([
  MICROSOFT_OFFLINE_SCOPE,
  'openid',
  'profile',
  'email',
]);

const resourceOf = (scope: string): string | null => {
  if (RESOURCE_FREE.has(scope)) return null;
  const slash = scope.lastIndexOf('/');
  return slash <= 0 ? scope : scope.slice(0, slash);
};

/**
 * Refuse a scope list that spans two Graph resources.
 *
 * Microsoft does not reject this: it issues a token for whichever resource the
 * *first* scope names and ignores the others. The caller then holds a token
 * that is valid, short-lived and for the wrong API, and the failure arrives as
 * an upstream 403 on a tool whose configuration looks right.
 *
 * Every scope here is Graph, so this never fires today. It exists because the
 * day somebody adds a non-Graph scope to an existing tool's list is the day
 * this becomes very hard to find.
 */
function assertOneResource(scopes: readonly string[]): void {
  const resources = new Set(scopes.map(resourceOf).filter((r): r is string => r !== null));
  if (resources.size > 1) {
    throw new Error(
      `microsoft scopes span ${resources.size} resources (${[...resources].sort().join(', ')}) — ` +
        'Microsoft would return a token for the first one and ignore the rest',
    );
  }
}

export interface MicrosoftCodeExchangeResult {
  readonly refreshToken: string;
  readonly scopes: readonly string[];
  readonly accessTokenExpiresAt: Date;
}

interface TokenResponse {
  access_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
  scope?: unknown;
}

/**
 * Microsoft's own error code, not just a status.
 *
 * `invalid_grant` (the code was used or expired), `consent_required` (the
 * tenant turned off user consent) and `invalid_client` (a bad secret) are all
 * the same 400 otherwise, and they need opposite responses from whoever reads
 * the log. The body carries an error code and a description; the client secret
 * and the refresh token are in the *request*, so this puts no credential in a
 * log (invariant 5).
 */
async function postToken(
  config: MicrosoftOAuthConfig,
  body: Record<string, string>,
): Promise<TokenResponse> {
  const response = await fetch(MICROSOFT_TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      ...body,
    }).toString(),
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`microsoft token request failed: ${response.status} ${detail.slice(0, 300)}`);
  }

  return (await response.json()) as TokenResponse;
}

const GRAPH_SCOPE_PREFIX = 'https://graph.microsoft.com/';

/**
 * Put a returned scope list into the one spelling the broker compares against.
 *
 * Microsoft answers with Graph scopes in **either** form — `Mail.Read` or
 * `https://graph.microsoft.com/Mail.Read` — and which one you get depends on
 * the tenant and the request. The broker's check is a set comparison against
 * `UPSTREAM_FOR_TOOL`, which names the full URI, so a short-form response
 * would record a connection holding "Mail.Read" that never matches
 * "https://graph.microsoft.com/Mail.Read". Every call would then fail
 * `SCOPE_NOT_GRANTED` on a connection that is perfectly good — a refusal
 * pointing at consent when the cause is a string format.
 *
 * So both forms are stored as the long one. `offline_access` and the OIDC
 * scopes keep their bare names, because that is what they are.
 */
export function normalizeMicrosoftScopes(scopes: readonly string[]): readonly string[] {
  return scopes.map((scope) =>
    RESOURCE_FREE.has(scope) || scope.includes('://') ? scope : `${GRAPH_SCOPE_PREFIX}${scope}`,
  );
}

const splitScopes = (scope: unknown): readonly string[] =>
  normalizeMicrosoftScopes(
    typeof scope === 'string' ? scope.split(' ').filter((s) => s !== '') : [],
  );

/**
 * The consent URL.
 *
 * `response_mode=query` because the callback is a server-side route reading a
 * query string — `fragment` never reaches the server, which is the shape of bug
 * that looks like a dead redirect.
 *
 * `prompt=consent` is deliberately absent. Microsoft returns a refresh token
 * whenever `offline_access` was granted, so Google's reason for forcing the
 * screen every time does not apply, and forcing it would re-ask a person who
 * already decided.
 */
export function buildMicrosoftConsentUrl(
  config: MicrosoftConsentConfig,
  options: {
    readonly state: string;
    readonly codeChallenge: string;
    readonly scopes: readonly string[];
  },
): string {
  assertOneResource(options.scopes);

  const url = new URL(MICROSOFT_AUTH_URL);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    response_type: 'code',
    redirect_uri: config.redirectUri,
    response_mode: 'query',
    scope: options.scopes.join(' '),
    state: options.state,
    code_challenge: options.codeChallenge,
    code_challenge_method: 'S256',
  }).toString();
  return url.href;
}

/**
 * Trade an authorization code for a refresh token.
 *
 * `redirect_uri` comes from configuration and never from the request (§12.1
 * asks for exact redirect URI validation; the way to get it exactly right is to
 * have nothing to validate).
 *
 * A grant with no refresh token is refused rather than stored. It means
 * `offline_access` was not granted, and the result would be a connection that
 * works for an hour and then dies silently. Failing now is the honest outcome,
 * and the message names the scope — the same choice Google and Slack make.
 */
export async function exchangeMicrosoftCode(
  config: MicrosoftOAuthConfig,
  code: string,
  codeVerifier: string,
): Promise<MicrosoftCodeExchangeResult> {
  const body = await postToken(config, {
    grant_type: 'authorization_code',
    code,
    code_verifier: codeVerifier,
    redirect_uri: config.redirectUri,
  });

  const refreshToken = typeof body.refresh_token === 'string' ? body.refresh_token : '';
  if (refreshToken === '') {
    throw new Error(
      'microsoft code exchange returned no refresh token — the offline_access scope is required',
    );
  }

  const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 0;

  // `offline_access` is recorded whether or not Microsoft echoes it, and that
  // is an inference rather than an assumption: this line is only reached when a
  // refresh token came back, and a refresh token is issued *only* when
  // `offline_access` was granted. Microsoft frequently omits it from `scope`
  // because it names no resource.
  //
  // It has to be on the connection because `UPSTREAM_FOR_TOOL` forwards it on
  // every refresh — without it in the request Microsoft issues no replacement
  // refresh token, and the broker's own check would refuse a request for a
  // scope the connection did not appear to hold.
  const granted = splitScopes(body.scope);
  const scopes = granted.includes(MICROSOFT_OFFLINE_SCOPE)
    ? granted
    : [MICROSOFT_OFFLINE_SCOPE, ...granted];

  return {
    refreshToken,
    scopes,
    // No lifetime means one we do not know. Treated as already spent, so the
    // next call refreshes rather than assuming — an access token believed to
    // live longer than it does is used after it is dead.
    accessTokenExpiresAt: new Date(Date.now() + expiresIn * 1000),
  };
}

export function createMicrosoftExchange(config: MicrosoftOAuthConfig): UpstreamTokenExchange {
  return {
    async refresh(refreshToken: string, scopes: readonly string[]): Promise<AccessGrant> {
      // Forwarded, not ignored. Microsoft honours a subset of what was
      // consented, so this is where a calendar read stops being able to read
      // mail. See the narrowing note at the top of this file.
      assertOneResource(scopes);

      const body = await postToken(config, {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: scopes.join(' '),
      });

      const accessToken = typeof body.access_token === 'string' ? body.access_token : '';
      if (accessToken === '') throw new Error('microsoft refresh returned no access token');

      const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 0;
      const rotated = typeof body.refresh_token === 'string' ? body.refresh_token : '';

      return {
        accessToken,
        expiresAt: new Date(Date.now() + expiresIn * 1000),
        // The response omits `scope` when the token is for exactly what was
        // asked, and an empty list would read to the broker's own check as "no
        // scopes" on the next call. Fall back to what was requested, which is
        // what Microsoft granted when it did not say otherwise.
        scopes: body.scope === undefined ? [...scopes] : splitScopes(body.scope),
        // Microsoft rotates on every refresh and leaves the old token working.
        // The broker persists this over the ciphertext, so the previous value
        // stops existing here even though it would still be accepted upstream.
        ...(rotated === '' ? {} : { rotatedRefreshToken: rotated }),
      };
    },

    /**
     * Local only, deliberately, and this is the one place in this system where
     * that is true.
     *
     * Microsoft exposes no way to invalidate one refresh token. The caller has
     * already destroyed the stored credential by the time this runs, so the
     * credential is unusable *from here* — which is what revocation in this
     * product means for every provider — but the grant on the Microsoft side
     * survives until the person removes it at myapplications.microsoft.com.
     *
     * The alternative was Graph's `revokeSignInSessions`, and it is refused on
     * purpose: it invalidates every application's refresh tokens for that
     * person, so revoking one Veto connection would sign them out of Outlook
     * and Teams, and it needs an administrator permission this app does not
     * hold and should not ask for.
     *
     * No call is better than a wildly broader one. A `revoke` that quietly did
     * something enormous would be the kind of comment this repo has already
     * been burned by three times in the GitHub path: one describing a control
     * that is not what it says. `docs/microsoft-setup.md` states the gap, and
     * the `/connections` screen repeats it to the person doing the revoking.
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async revoke(_refreshToken: string): Promise<void> {
      return;
    },
  };
}
