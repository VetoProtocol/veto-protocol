/**
 * OIDC sign-in.
 *
 * Generic: the dashboard discovers everything from the issuer's
 * `.well-known/openid-configuration`, so any conformant provider works with
 * three environment variables and no code change. See `docs/auth-setup.md`.
 *
 * ## Why a library
 *
 * `openid-client` does discovery, PKCE, and — the part that matters — id token
 * validation: signature against the provider's rotating JWKS, issuer, audience,
 * nonce, expiry, and algorithm pinning. Hand-rolling that is where
 * authentication bugs actually live, and none of them are visible in testing:
 * an id token whose signature is never checked works perfectly until somebody
 * forges one.
 *
 * ## What the flow protects against
 *
 *  * **CSRF on the callback** — `state`, random per attempt, stored in a signed
 *    cookie and compared on return (§12.1 OAuth CSRF).
 *  * **Code injection / replay** — PKCE S256. The verifier never leaves this
 *    server, so an intercepted code cannot be redeemed.
 *  * **Token replay across sessions** — `nonce`, bound into the id token by the
 *    provider and checked on return.
 *  * **Open redirect** — the redirect URI is built from configuration, never
 *    from the request, and post-sign-in navigation is a fixed path.
 *
 * ## Why it does not use the ambient fetch
 *
 * Next instruments the global `fetch` to add its own caching and
 * deduplication. Every request here is an authentication step — discovery,
 * token exchange, JWKS — and none of them may be served from a cache or
 * coalesced with another request. Under `next start` the instrumented fetch
 * also hung outright, which is how this was found; correctness is the reason it
 * stays.
 */

import 'server-only';
import { fetch as undiciFetch } from 'undici';
import * as client from 'openid-client';

export interface OidcSettings {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly scope: string;
}

export function oidcSettings(): OidcSettings {
  const issuer = required('OIDC_ISSUER');
  const redirectUri = required('OIDC_REDIRECT_URI');

  // A provider reached over plain HTTP can be rewritten in flight, and the
  // whole flow trusts what it says. Localhost is the exception every provider
  // already makes for development.
  const url = new URL(issuer);
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new Error('OIDC_ISSUER must be https (localhost excepted)');
  }

  return {
    issuer,
    clientId: required('OIDC_CLIENT_ID'),
    clientSecret: required('OIDC_CLIENT_SECRET'),
    redirectUri,
    // openid gets the id token; profile and email are not requested. The
    // dashboard needs a stable subject and nothing else, and §11 asks for data
    // minimisation — an email we do not use is an email we would have to protect.
    scope: process.env['OIDC_SCOPE']?.trim() || 'openid',
  };
}

/**
 * An uninstrumented fetch, pinned to no-store.
 *
 * `undici.fetch` rather than the global one, so Next's patch is out of the
 * path entirely.
 */
type CustomFetch = NonNullable<client.Configuration[typeof client.customFetch]>;

// undici's RequestInit and the DOM's differ in optionality, which
// exactOptionalPropertyTypes makes visible. The shapes are compatible at
// runtime; the cast is confined to this one line rather than loosening the
// whole module.
const directFetch = ((url: string, options: unknown) =>
  undiciFetch(url, options as Parameters<typeof undiciFetch>[1])) as unknown as CustomFetch;

let cached: Promise<client.Configuration> | null = null;

/**
 * Discovery result, cached for the process.
 *
 * Cached because it is one network round trip per sign-in otherwise. The JWKS
 * behind it is *not* frozen — the library refetches keys when it sees an unknown
 * key id, so provider key rotation still works.
 */
export function discover(settings: OidcSettings): Promise<client.Configuration> {
  cached ??= client
    .discovery(new URL(settings.issuer), settings.clientId, settings.clientSecret, undefined, {
      [client.customFetch]: directFetch,
    })
    .then((config) => {
      // The same fetch has to carry the later token and JWKS requests, not just
      // discovery.
      config[client.customFetch] = directFetch;
      return config;
    })
    .catch((error: unknown) => {
      // Do not cache a failed discovery: a provider that was briefly
      // unreachable would otherwise stay unreachable for the life of the
      // process.
      cached = null;
      throw error;
    });
  return cached;
}

function required(name: string): string {
  const value = (process.env[name] ?? '').trim();
  if (!value) {
    throw new Error(`${name} is not set. Sign-in is not configured; see docs/auth-setup.md.`);
  }
  return value;
}
