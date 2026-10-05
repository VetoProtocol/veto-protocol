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

export interface InstallationResult {
  readonly installationId: string;
  readonly accountLogin: string;
  readonly scopes: readonly string[];
}

/**
 * Confirm an installation exists and read back what it actually holds.
 *
 * The callback carries an `installation_id` query parameter, which is a
 * caller-supplied number. It is not trusted: this asks GitHub what that
 * installation is and which permissions it has, and the answer — not the
 * request — is what gets stored. The same shape as reading a file's parent from
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
