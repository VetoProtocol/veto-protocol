/**
 * GitHub as an UpstreamTokenExchange (spec §9, §15).
 *
 * ## Why a GitHub App and not an OAuth App
 *
 * An OAuth App acts *as the user*, with a scope list that is coarse to the
 * point of being unusable here: `repo` is read **and** write across every
 * repository that user can reach, and there is no read-only variant of it. A
 * product whose position is "reads first, and a write path is a new trust
 * boundary" cannot ask for a credential that can push.
 *
 * A GitHub App acts as itself, is installed per account, and holds only the
 * repositories and permissions the installer picked. It is the only shape that
 * makes "you choose which repositories, one at a time" a true sentence.
 *
 * ## What sits where a refresh token sits
 *
 * There is no refresh token. The durable thing is the **installation id**, and
 * the secret is the App's private key, which lives in configuration and never
 * in the vault. The installation id goes in the vault's credential column
 * anyway: it is the value the broker hands back to `refresh`, and keeping the
 * shape identical means `mintUpstreamToken` needs no second code path.
 *
 * An installation id is not a bearer credential — it is useless without the
 * private key — but it is still tenant data and is still encrypted at rest.
 *
 * ## Narrowing actually narrows here
 *
 * Google fixes a grant's scopes at consent and ignores what the broker asks for
 * at refresh time. GitHub does not: an installation token can be requested with
 * a subset of the installation's permissions, and the token that comes back
 * holds only that subset. So step 8's "mint the narrowest token" is literal for
 * GitHub in a way it cannot be for Google — a Drive read gets a Drive-only
 * token because of which *connection* it uses, but an issue read gets an
 * issues-only token because of what this call asked for.
 */

import { createSign } from 'node:crypto';
import type { AccessGrant, UpstreamTokenExchange } from './broker.ts';

export const GITHUB_API_URL = 'https://api.github.com';

/**
 * Permissions, written as `name:level`.
 *
 * GitHub's token API wants them split into an object; the broker compares scope
 * strings and the vault already stores a `text[]`. Carrying them joined keeps
 * one representation everywhere and splits only at the API boundary.
 */
export const GITHUB_METADATA_READ = 'metadata:read';
export const GITHUB_CONTENTS_READ = 'contents:read';
export const GITHUB_ISSUES_READ = 'issues:read';
export const GITHUB_PULL_REQUESTS_READ = 'pull_requests:read';

/**
 * Which permissions each service needs, and nothing more.
 *
 * `metadata:read` appears everywhere because GitHub requires it for nearly
 * every read and grants it implicitly. Naming it keeps the broker's
 * `SCOPE_NOT_GRANTED` check honest rather than letting an implicit permission
 * paper over a missing explicit one.
 *
 * Mirrors `GOOGLE_SERVICES`: consent is per service and the caller names one,
 * so a connect flow cannot ask for everything by passing a list — it does not
 * take a list.
 */
export const GITHUB_SERVICES = {
  repos: [GITHUB_METADATA_READ, GITHUB_CONTENTS_READ],
  issues: [GITHUB_METADATA_READ, GITHUB_ISSUES_READ],
  pulls: [GITHUB_METADATA_READ, GITHUB_PULL_REQUESTS_READ],
} as const satisfies Record<string, readonly string[]>;

export type GitHubService = keyof typeof GITHUB_SERVICES;

export const GITHUB_SERVICE_NAMES = Object.keys(GITHUB_SERVICES) as readonly GitHubService[];

export const isGitHubService = (value: string): value is GitHubService =>
  Object.hasOwn(GITHUB_SERVICES, value);

export interface GitHubAppConfig {
  /** The numeric App id from the app's settings page. */
  readonly appId: string;
  /** PEM private key. The only real secret, and never stored in the vault. */
  readonly privateKeyPem: string;
  /** The app's public slug, used to build the install URL. */
  readonly appSlug: string;
}

/**
 * What building an install URL needs — and pointedly not the private key.
 *
 * Same move as `ConsentConfig`: the dashboard runs the browser round trip, so
 * the narrower type is what crosses that line. A field that does not exist
 * cannot be handed to the wrong process.
 */
export type InstallConfig = Pick<GitHubAppConfig, 'appSlug'>;

/** Split `contents:read` into the shape the token API wants. */
function asPermissionObject(scopes: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const scope of scopes) {
    const at = scope.indexOf(':');
    if (at <= 0) continue;
    out[scope.slice(0, at)] = scope.slice(at + 1);
  }
  return out;
}

/** Re-join a permissions object into the `name:level` strings we compare on. */
function asScopeList(permissions: Record<string, unknown>): readonly string[] {
  return Object.entries(permissions)
    .filter(([, level]) => typeof level === 'string')
    .map(([name, level]) => `${name}:${String(level)}`)
    .sort();
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

/**
 * A short-lived JWT proving we are the App.
 *
 * GitHub rejects anything over ten minutes, and rejects an `iat` in its own
 * future, which a clock a few seconds fast will produce. Backdating by a minute
 * is GitHub's documented advice and costs nothing.
 */
export function createAppJwt(config: GitHubAppConfig, now: Date = new Date()): string {
  const issued = Math.floor(now.getTime() / 1000) - 60;
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64url(JSON.stringify({ iat: issued, exp: issued + 540, iss: config.appId }));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  signer.end();
  return `${header}.${payload}.${base64url(signer.sign(config.privateKeyPem))}`;
}

/**
 * The install URL.
 *
 * Unlike Google's consent URL there is no scope parameter: what an installation
 * may reach is chosen on GitHub's own screen, by the person installing it, and
 * cannot be widened from here. `state` still round-trips so the callback can be
 * tied to the request that started it (§12.1 OAuth CSRF).
 */
export function buildInstallUrl(config: InstallConfig, options: { state: string }): string {
  const url = new URL(`https://github.com/apps/${config.appSlug}/installations/new`);
  url.search = new URLSearchParams({ state: options.state }).toString();
  return url.href;
}

/**
 * The App's *user*-authorization credentials — and why they have to exist.
 *
 * ## The hole this closes
 *
 * `readInstallation` authenticates with the **App JWT**, which can read any
 * installation of this App, including one on a GitHub account the caller has
 * never touched. It confirms an installation *exists*. It has never confirmed
 * that the person claiming it controls it.
 *
 * The install `state` does not close that gap either. It proves "this user, in
 * this workspace, began an install flow recently" — CSRF protection, and
 * nothing about any particular installation. So an authenticated caller could
 * start a flow, never visit GitHub, and post somebody else's installation id;
 * ids are small sequential integers. This server would then mint real tokens
 * for that stranger's repositories with the App private key it holds.
 *
 * ## What actually proves it
 *
 * GitHub's own answer: with "Request user authorization (OAuth) during
 * installation" enabled, the post-install redirect carries a `code` as well as
 * the installation id. That code exchanges for a **user** access token, and
 * `GET /user/installations` with that token returns only the installations
 * *that person* can reach. An id absent from that list was not theirs to claim.
 *
 * The client secret lives here and never reaches the dashboard or the gateway.
 * The gateway mints installation tokens and has no business in the install
 * round trip, which is why this is a separate type from `GitHubAppConfig`
 * rather than two more fields on it — the same narrowing `ConsentConfig` does.
 */
export interface GitHubUserAuthConfig {
  readonly clientId: string;
  /** Never in the vault, never in a response, never in a log. */
  readonly clientSecret: string;
}

/**
 * Trade the post-install `code` for a user access token.
 *
 * The token is used once, immediately, to ask which installations the person
 * can reach — and is never stored. It is a means of asking GitHub a question
 * about the human in front of us, not a credential this product keeps.
 */
export async function exchangeUserCode(
  config: GitHubUserAuthConfig,
  code: string,
): Promise<string> {
  const response = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
    }),
  });

  if (!response.ok) throw new Error(`user code exchange failed: HTTP ${response.status}`);

  // GitHub answers 200 with an `error` field for a bad code rather than a 4xx,
  // so a status check alone would accept a failure as a success.
  const body = (await response.json()) as {
    access_token?: unknown;
    error?: unknown;
    error_description?: unknown;
  };

  if (typeof body.access_token !== 'string' || body.access_token === '') {
    // Carry GitHub's own code — `bad_verification_code`,
    // `incorrect_client_credentials`, `redirect_uri_mismatch`. It names the
    // cause exactly, it is an error code rather than a secret, and without it
    // every one of those failures looks identical in a log. The description is
    // left out: it is prose written for a console and can echo the request.
    const code = typeof body.error === 'string' ? body.error : 'no access_token in response';
    throw new Error(`user code exchange refused: ${code}`);
  }

  return body.access_token;
}

/**
 * Which installations this person can actually reach.
 *
 * Paginated deliberately rather than trusting the first page: somebody who
 * belongs to many organisations would otherwise have a legitimate installation
 * silently judged not theirs. Bounded, because this runs on a request and an
 * unbounded loop against a third party is somebody else's rate limit deciding
 * when our handler returns.
 */
export async function userInstallationIds(userToken: string): Promise<ReadonlySet<string>> {
  const ids = new Set<string>();
  const PER_PAGE = 100;
  const MAX_PAGES = 10;

  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const response = await fetch(
      `${GITHUB_API_URL}/user/installations?per_page=${String(PER_PAGE)}&page=${String(page)}`,
      {
        headers: {
          authorization: `Bearer ${userToken}`,
          accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28',
        },
      },
    );

    if (!response.ok) {
      throw new Error(`installation list failed: HTTP ${response.status} on page ${String(page)}`);
    }

    const body = (await response.json()) as { installations?: unknown };
    const page_ = Array.isArray(body.installations) ? body.installations : [];

    for (const entry of page_) {
      const id = (entry as { id?: unknown }).id;
      // GitHub sends a number; everything compared downstream is a string.
      if (typeof id === 'number' || typeof id === 'string') ids.add(String(id));
    }

    if (page_.length < PER_PAGE) break;
  }

  return ids;
}

/**
 * Does this person control this installation?
 *
 * The whole point of the `code` on the callback. A `false` here means the id
 * was claimed rather than owned, and the only correct response is to refuse —
 * there is no degraded version of this answer.
 */
export async function userControlsInstallation(
  config: GitHubUserAuthConfig,
  input: { readonly code: string; readonly installationId: string },
): Promise<boolean> {
  const userToken = await exchangeUserCode(config, input.code);
  const reachable = await userInstallationIds(userToken);
  return reachable.has(input.installationId);
}

export interface InstallationResult {
  readonly installationId: string;
  readonly accountLogin: string;
  readonly scopes: readonly string[];
}

/**
 * Read back what an installation actually holds.
 *
 * **This does not establish ownership and never could.** It authenticates with
 * the App JWT, which can read any installation of this App, so it answers
 * "does this exist and what does it hold" — not "is this yours". An earlier
 * version of this comment treated it as the check on a caller-supplied
 * installation id, which it was not; `userControlsInstallation` is. Call that
 * first, and use this only for the facts that get stored.
 *
 * What it is good for: the permissions recorded are GitHub's answer rather than
 * the caller's claim, so an installer who granted only issues cannot be
 * recorded as having granted code. The same shape as reading a file's parent from
 * Drive rather than from an argument.
 */
export async function readInstallation(
  config: GitHubAppConfig,
  installationId: string,
): Promise<InstallationResult> {
  const response = await fetch(
    `${GITHUB_API_URL}/app/installations/${encodeURIComponent(installationId)}`,
    {
      headers: {
        authorization: `Bearer ${createAppJwt(config)}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
      },
    },
  );

  if (!response.ok) throw new Error(`installation lookup failed: ${response.status}`);

  const body = (await response.json()) as {
    id?: number;
    account?: { login?: string };
    permissions?: Record<string, unknown>;
  };

  if (typeof body.id !== 'number') throw new Error('installation lookup returned no id');

  return {
    installationId: String(body.id),
    accountLogin: typeof body.account?.login === 'string' ? body.account.login : '',
    scopes: asScopeList(body.permissions ?? {}),
  };
}

export function createGitHubExchange(config: GitHubAppConfig): UpstreamTokenExchange {
  return {
    /**
     * `installationId` occupies the refresh-token parameter. See the note at the
     * top of this file: the broker's shape is reused deliberately.
     */
    async refresh(installationId: string, scopes: readonly string[]): Promise<AccessGrant> {
      const requested = asPermissionObject(scopes);

      const response = await fetch(
        `${GITHUB_API_URL}/app/installations/${encodeURIComponent(installationId)}/access_tokens`,
        {
          method: 'POST',
          headers: {
            authorization: `Bearer ${createAppJwt(config)}`,
            accept: 'application/vnd.github+json',
            'content-type': 'application/json',
            'x-github-api-version': '2022-11-28',
          },
          // Asking for a subset narrows the token GitHub returns. An empty
          // object would mean "everything the installation has", so a call
          // naming no scopes must not reach here — the broker refuses first.
          body: JSON.stringify({ permissions: requested }),
        },
      );

      if (!response.ok) {
        // GitHub's reason, not just its status. A suspended installation, a
        // permission the installation never had, and a secondary rate limit are
        // all 4xx and need opposite responses from whoever reads the log. The
        // body carries an error message; it does not carry the private key or
        // the minted token, which are in the *request* (invariant 5).
        const detail = await response.text().catch(() => '');
        throw new Error(`installation token failed: ${response.status} ${detail.slice(0, 200)}`);
      }

      const body = (await response.json()) as {
        token?: string;
        expires_at?: string;
        permissions?: Record<string, unknown>;
      };

      if (typeof body.token !== 'string' || body.token === '') {
        throw new Error('installation token response carried no token');
      }

      // GitHub states an absolute expiry rather than a lifetime. If it is
      // missing or unparseable, assume a short one: a token believed to live
      // longer than it does is used after it is dead, and the failure surfaces
      // at the worst moment.
      const stated = body.expires_at === undefined ? Number.NaN : Date.parse(body.expires_at);
      const expiresAt = Number.isFinite(stated)
        ? new Date(stated)
        : new Date(Date.now() + 300 * 1000);

      return {
        accessToken: body.token,
        expiresAt,
        // What GitHub actually granted, which can be narrower than what was
        // asked for. Reporting the request back would be reporting a wish.
        scopes: asScopeList(body.permissions ?? requested),
      };
    },

    /**
     * Delete the installation.
     *
     * GitHub has no "revoke this grant but keep the install" — an installation
     * *is* the grant. Deleting it is what makes every token minted from it stop
     * working, which is what revocation has to mean here (§5.4
     * `credential.revoked`).
     */
    async revoke(installationId: string): Promise<void> {
      const response = await fetch(
        `${GITHUB_API_URL}/app/installations/${encodeURIComponent(installationId)}`,
        {
          method: 'DELETE',
          headers: {
            authorization: `Bearer ${createAppJwt(config)}`,
            accept: 'application/vnd.github+json',
            'x-github-api-version': '2022-11-28',
          },
        },
      );

      // 204 on success, 404 when it is already gone — both mean "no longer
      // installed", which is the state the caller asked for.
      if (!response.ok && response.status !== 404) {
        throw new Error(`installation delete failed: ${response.status}`);
      }
    },
  };
}
