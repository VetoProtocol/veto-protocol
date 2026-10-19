/**
 * Slack as an UpstreamTokenExchange (spec §9, §15).
 *
 * ## Why a bot token, and why that happens to fit
 *
 * A Slack app can act as the installing *user* or as a *bot*. A user token
 * reaches everything that person can reach, which is usually every channel
 * they are in — no narrowing available, and no way to grant one conversation
 * without granting all of them.
 *
 * A bot reads only the conversations it has been invited to. That is Slack's
 * own mechanism, and it is exactly the boundary this product sells: the
 * customer chooses which channels by inviting the bot, one at a time, in the
 * place they already manage channel membership. The same shape as a GitHub App
 * holding only the repositories the installer picked.
 *
 * So: bot token. A channel an agent may read is a channel somebody deliberately
 * added the bot to.
 *
 * ## Token rotation is required, not optional
 *
 * A classic Slack bot token never expires. Stored in the vault it would be a
 * durable bearer credential that `refresh()` handed back unchanged forever —
 * and the broker's whole shape says "trade a long-lived secret for a
 * short-lived one". Returning the same string would be lying about which kind
 * it is.
 *
 * With rotation on, the install returns a refresh token plus a short-lived
 * access token, which is precisely what `UpstreamTokenExchange` expresses. An
 * install without it is **refused** rather than stored as something it is not,
 * and the error names the setting. See `docs/slack-setup.md`.
 *
 * Rotation also means the refresh token itself changes on every use, which the
 * broker had no way to record until `AccessGrant.rotatedRefreshToken` existed.
 * Dropping it would not fail now; it would fail on the second refresh, hours
 * later, on a connection nobody had touched.
 *
 * ## Narrowing is fixed at install, like Google and unlike GitHub
 *
 * GitHub honours a subset of permissions at mint time, so an issue read gets a
 * token that physically cannot read a file. Slack does not: a rotated token
 * carries whatever the installation was granted. `refresh` therefore takes the
 * requested scopes and does not forward them. What narrowing remains is the
 * broker's own check that the connection holds what the tool needs, and the
 * fact that the bot is only in some channels.
 *
 * Stated here rather than discovered: a reader of `UPSTREAM_FOR_TOOL` should
 * not assume every provider narrows the same way.
 *
 * ## Slack answers 200 for failures
 *
 * Every Slack call returns HTTP 200 with `{"ok": false, "error": "..."}` when
 * it fails. A status check alone treats a refusal as a success and hands back
 * an empty token — the same trap GitHub's code exchange sets, which is why
 * both are checked on `ok` rather than on `response.ok`.
 */

import type { AccessGrant, UpstreamTokenExchange } from './broker.ts';

export const SLACK_API_URL = 'https://slack.com/api';

/** Public conversations: list them, and read the ones the bot is in. */
export const SLACK_CHANNELS_READ = 'channels:read';
export const SLACK_CHANNELS_HISTORY = 'channels:history';
/** Private conversations. A separate decision, so a separate service. */
export const SLACK_GROUPS_READ = 'groups:read';
export const SLACK_GROUPS_HISTORY = 'groups:history';

/**
 * Which scopes each service needs, and nothing more.
 *
 * Mirrors `GOOGLE_SERVICES` and `GITHUB_SERVICES`: consent is per service and
 * the caller names one, so a connect flow cannot ask for everything by passing
 * a list — it does not take a list.
 *
 * Private channels are deliberately their own service. "Read our public
 * channels" and "read our private channels" are different conversations to
 * have with a customer, and bundling them would make the second one invisible.
 */
export const SLACK_SERVICES = {
  channels: [SLACK_CHANNELS_READ, SLACK_CHANNELS_HISTORY],
  private_channels: [SLACK_GROUPS_READ, SLACK_GROUPS_HISTORY],
} as const satisfies Record<string, readonly string[]>;

export type SlackService = keyof typeof SLACK_SERVICES;

export const SLACK_SERVICE_NAMES = Object.keys(SLACK_SERVICES) as readonly SlackService[];

export const isSlackService = (value: string): value is SlackService =>
  Object.hasOwn(SLACK_SERVICES, value);

export interface SlackAppConfig {
  readonly clientId: string;
  /** Never in the vault, never in a response, never in a log. */
  readonly clientSecret: string;
  /** Must match the app's configured redirect exactly. */
  readonly redirectUri: string;
}

/**
 * What building an install URL needs — and pointedly not the client secret.
 *
 * The same narrowing `ConsentConfig` does for Google: the dashboard runs the
 * browser round trip, so the narrower type is what crosses that line.
 */
export type SlackInstallConfig = Pick<SlackAppConfig, 'clientId' | 'redirectUri'>;

/**
 * The install URL for one service.
 *
 * `scope` carries bot scopes. `user_scope` is deliberately absent: this app
 * never acts as the installing person.
 */
export function buildSlackInstallUrl(
  config: SlackInstallConfig,
  options: { readonly service: SlackService; readonly state: string },
): string {
  const url = new URL('https://slack.com/oauth/v2/authorize');
  url.search = new URLSearchParams({
    client_id: config.clientId,
    scope: SLACK_SERVICES[options.service].join(','),
    redirect_uri: config.redirectUri,
    state: options.state,
  }).toString();
  return url.href;
}

export interface SlackInstallation {
  /** The rotating refresh token. This is what the vault holds. */
  readonly refreshToken: string;
  readonly accessToken: string;
  readonly expiresAt: Date;
  readonly scopes: readonly string[];
  /** `T…`, the workspace installed into. Fits Permit's key grammar as-is. */
  readonly teamId: string;
  readonly teamName: string;
}

interface SlackTokenResponse {
  ok?: unknown;
  error?: unknown;
  access_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
  scope?: unknown;
  team?: { id?: unknown; name?: unknown };
}

async function postForm(path: string, body: Record<string, string>): Promise<SlackTokenResponse> {
  const response = await fetch(`${SLACK_API_URL}/${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString(),
  });

  // A transport failure is still a failure, even though Slack's own refusals
  // arrive as 200s.
  if (!response.ok) throw new Error(`slack ${path} failed: HTTP ${response.status}`);

  const parsed = (await response.json()) as SlackTokenResponse;
  if (parsed.ok !== true) {
    // Slack's error code names the cause exactly — `invalid_code`,
    // `bad_redirect_uri`, `invalid_refresh_token`. It is a code rather than a
    // secret, and without it every one of these looks identical in a log.
    const code = typeof parsed.error === 'string' ? parsed.error : 'unknown';
    throw new Error(`slack ${path} refused: ${code}`);
  }

  return parsed;
}

const splitScopes = (scope: unknown): readonly string[] =>
  typeof scope === 'string' ? scope.split(',').filter((s) => s !== '') : [];

/**
 * Trade the install code for a rotating credential.
 *
 * Refuses an installation with no refresh token. That means rotation is off on
 * the app, and the alternative — storing the non-expiring bot token in the
 * refresh column — would put a permanent bearer secret where the system
 * promises a rotating one. Better to fail at connect time, where the message
 * can name the setting, than to hold a credential of the wrong kind.
 */
export async function exchangeSlackCode(
  config: SlackAppConfig,
  code: string,
): Promise<SlackInstallation> {
  const body = await postForm('oauth.v2.access', {
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: config.redirectUri,
  });

  const accessToken = typeof body.access_token === 'string' ? body.access_token : '';
  const refreshToken = typeof body.refresh_token === 'string' ? body.refresh_token : '';

  if (accessToken === '') throw new Error('slack install returned no access token');
  if (refreshToken === '') {
    throw new Error('slack install returned no refresh token — enable token rotation on the app');
  }

  const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 0;

  return {
    refreshToken,
    accessToken,
    // No `expires_in` means a lifetime we do not know. Treated as already
    // spent, so the next call refreshes rather than assuming.
    expiresAt: new Date(Date.now() + expiresIn * 1000),
    scopes: splitScopes(body.scope),
    teamId: typeof body.team?.id === 'string' ? body.team.id : '',
    teamName: typeof body.team?.name === 'string' ? body.team.name : '',
  };
}

/**
 * The broker adapter.
 *
 * `scopes` is accepted and not forwarded: Slack issues a rotated token holding
 * whatever the installation was granted, with no subset at mint time. The
 * broker still compares the connection's recorded scopes against what the tool
 * needs, so a tool asking for something this installation never held is
 * refused before the call rather than by the provider.
 */
export function createSlackExchange(config: SlackAppConfig): UpstreamTokenExchange {
  return {
    // The port passes scopes; Slack ignores them. See the note on narrowing
    // at the top of this file — pretending otherwise would make
    // `UPSTREAM_FOR_TOOL` read as narrowing when it is not.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async refresh(refreshToken: string, _scopes: readonly string[]): Promise<AccessGrant> {
      const body = await postForm('oauth.v2.access', {
        client_id: config.clientId,
        client_secret: config.clientSecret,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      });

      const accessToken = typeof body.access_token === 'string' ? body.access_token : '';
      if (accessToken === '') throw new Error('slack refresh returned no access token');

      const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 0;
      const rotated = typeof body.refresh_token === 'string' ? body.refresh_token : '';

      return {
        accessToken,
        expiresAt: new Date(Date.now() + expiresIn * 1000),
        scopes: splitScopes(body.scope),
        // The broker persists this. Returned rather than written here, so a
        // provider adapter stays a thing that talks to a provider.
        ...(rotated === '' ? {} : { rotatedRefreshToken: rotated }),
      };
    },

    async revoke(refreshToken: string): Promise<void> {
      // Best effort, like every other provider's revoke: the local credential
      // is destroyed whatever Slack says, and a provider that refuses must not
      // stop a revocation completing here.
      await postForm('auth.revoke', { token: refreshToken }).catch(() => undefined);
    },
  };
}
