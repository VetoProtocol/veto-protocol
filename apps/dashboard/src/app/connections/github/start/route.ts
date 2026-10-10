/**
 * GET /connections/github/start — begin the GitHub App install round trip.
 *
 * The browser half, and deliberately thinner than its Google counterpart. There
 * is no PKCE here because there is no code to exchange: GitHub hands back an
 * installation id, and an installation id is worth nothing without the App
 * private key, which lives on the server and never moves.
 *
 * What this route still does is carry `state`, because the callback has to be
 * tied to the request that began it. Without that, a crafted link could land
 * somebody on our callback with an installation id of the attacker's choosing
 * and attach it to the victim's workspace (§12.1 OAuth CSRF).
 *
 * The state is **issued by the control plane**, not minted here. It is checked
 * there, and the side that checks a value should be the side that creates it.
 * An earlier version generated it in this route and sent it along, which made
 * it a value the caller picked.
 *
 * A signed-in session is required first, for the reason the Google route
 * requires one: an installation granted by an anonymous visitor would have no
 * workspace to belong to.
 *
 * Failures come back as a fixed code, never as text, so a crafted link cannot
 * put words in the product's mouth.
 */

import { NextResponse, type NextRequest } from 'next/server';
import { cookieOptions } from '@/lib/cookie-options';
import { CONNECT_COOKIE, CONNECT_TTL_MS, sealConnect } from '@/lib/connect-cookie';
import { ApiError, githubInstallUrl } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { publicOrigin } from '@/lib/public-url';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const session = await currentSession();
  if (!session) return back(request, 'session');

  // The state comes back from the control plane now; this route no longer
  // mints one. A value the browser chooses is not CSRF protection against the
  // browser, and the side that checks it is the side that should issue it.
  let url: string;
  let state: string;
  try {
    ({ url, state } = await githubInstallUrl(session.credential));
  } catch (error) {
    // 503 from this route means one thing: the GitHub App is not configured on
    // the server. That is a deployment fact worth naming precisely.
    if (error instanceof ApiError && error.failure.status === 503) {
      return back(request, 'unconfigured');
    }

    if (error instanceof ApiError) {
      // The control plane answered, with a refusal. Logged with the code,
      // because the browser must not learn which field a schema rejected but an
      // operator has to be able to find out.
      console.warn(
        `[connect] control plane refused github install-url: ${error.failure.status} ${error.failure.code}`,
      );
      return back(request, 'rejected');
    }

    return back(request, 'unavailable');
  }

  const response = NextResponse.redirect(url, { status: 302 });
  response.cookies.set(
    CONNECT_COOKIE,
    // No PKCE verifier: there is no code to exchange. The flow says which
    // provider it belongs to, so the opener knows that empty field is correct
    // here and still refuses it for Google — and so the two callbacks cannot
    // satisfy each other.
    sealConnect({ verifier: '', state, provider: 'github', expiresAt: Date.now() + CONNECT_TTL_MS }),
    { ...cookieOptions(), maxAge: Math.floor(CONNECT_TTL_MS / 1000) },
  );
  return response;
}

function back(request: NextRequest, reason: string): NextResponse {
  const target = new URL('/connections', publicOrigin(request));
  target.searchParams.set('error', reason);
  return NextResponse.redirect(target, { status: 303 });
}
