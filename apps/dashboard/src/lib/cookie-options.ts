import 'server-only';

/**
 * Cookie flags for everything this app sets.
 *
 *  * `httpOnly` — no script reads the session, so an XSS cannot exfiltrate it.
 *  * `sameSite: 'lax'` — strict would drop the flow cookie on the way back from
 *    the provider, which is a cross-site GET navigation. Lax is the tightest
 *    setting the OIDC redirect actually survives, and it still blocks the
 *    cross-site POST that CSRF needs.
 *  * `secure` unless explicitly running over plain HTTP locally. Set
 *    DASHBOARD_INSECURE_COOKIES=true only for local development; over the
 *    network it is how a session gets read off the wire.
 */
export function cookieOptions() {
  const insecure = (process.env['DASHBOARD_INSECURE_COOKIES'] ?? '').trim() === 'true';
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: !insecure,
    path: '/',
  };
}
