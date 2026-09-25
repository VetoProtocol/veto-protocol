import 'server-only';
import type { NextRequest } from 'next/server';

/**
 * Where this app is reached from, as a browser sees it.
 *
 * `request.url` cannot answer that behind a reverse proxy. `next start` builds
 * it from the address the server is bound to, not from the `Host` header — so
 * on a deployment where Caddy terminates TLS and proxies to 127.0.0.1:3000,
 * every route that redirected via `new URL(path, request.url)` sent the browser
 * to `localhost:3000`. Caddy rewrites the scheme on the way out, which is why
 * the symptom was the peculiar `https://localhost:3000/signed-out` rather than
 * something obviously internal.
 *
 * Worse than a broken sign-out: the OIDC callback passes the current URL to
 * `authorizationCodeGrant`, which compares it with the redirect URI the
 * provider has registered. `http://localhost:3000/auth/callback` matches
 * nothing, so every sign-in was refused with a message about verification.
 *
 * None of this is visible in development, because there the wrong answer and
 * the right one are the same string.
 *
 * `DASHBOARD_PUBLIC_URL` is the same value the OAuth metadata is built from, so
 * there is one idea of where this app lives rather than two that can disagree.
 * Unset — development — it falls back to the request, which is then correct.
 */
export function publicOrigin(request: NextRequest): string {
  const configured = (process.env['DASHBOARD_PUBLIC_URL'] ?? '').trim();
  if (configured !== '') return configured.replace(/\/+$/, '');
  return new URL(request.url).origin;
}

/**
 * This request's path and query, rebased onto the public origin.
 *
 * For the OIDC callback, which must hand the library the URL the *browser*
 * arrived at — the query string carries the code and state, and the origin has
 * to be the one the provider redirected to.
 */
export function publicRequestUrl(request: NextRequest): URL {
  const here = new URL(request.url);
  const url = new URL(publicOrigin(request));
  url.pathname = here.pathname;
  url.search = here.search;
  return url;
}
