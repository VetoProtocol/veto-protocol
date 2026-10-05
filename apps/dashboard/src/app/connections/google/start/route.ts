/**
 * GET /connections/google/start — begin the Google consent round trip.
 *
 * The browser half of §9. What this route does *not* do is as much the point as
 * what it does: it never sees the client secret, never learns the redirect URI,
 * and never touches a token. It generates a PKCE verifier and a state, keeps
 * both in a signed five-minute cookie, asks the control plane where to send the
 * user, and redirects.
 *
 * A signed-in session is required first. Consent granted by an anonymous
 * visitor would have no workspace to belong to, and inventing one is the
 * auto-provisioning hole the sign-in callback already refuses.
 *
 * Failures come back as a fixed code, never as text. The page looks the code
 * up, so a crafted link cannot put words in the product's mouth — the same rule
 * `signed-out` follows.
 */

import { NextResponse, type NextRequest } from 'next/server';
import * as client from 'openid-client';
import { cookieOptions } from '@/lib/cookie-options';
import { CONNECT_COOKIE, CONNECT_TTL_MS, sealConnect } from '@/lib/connect-cookie';
import { ApiError, googleAuthorizeUrl } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { publicOrigin } from '@/lib/public-url';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const session = await currentSession();
  if (!session) return back(request, 'session');

  const verifier = client.randomPKCECodeVerifier();
  const challenge = await client.calculatePKCECodeChallenge(verifier);
  const state = client.randomState();

  // One service per consent screen (§9.1). Read from the query because the
  // button names it, and checked against a closed set here so nothing
  // unrecognised is forwarded to Google.
  //
  // This set is a hand-kept copy of `GOOGLE_SERVICES`. The guard that owns that
  // list — `isGoogleService` — cannot be imported here: `@veto/connections`
  // re-exports six relative `.ts` files and the dashboard builds with
  // `allowImportingTsExtensions` off. The copy drifted, `calendar` was missing,
  // and because the fallback was Drive, asking to connect Calendar silently
  // connected Drive instead.
  //
  // So the fallback is gone. Substituting one service for another is the one
  // thing a consent screen must never do — the user approves what they were
  // shown, and a grant they did not ask for is a wrong `allow`. An
  // unrecognised service is refused; only a missing one still defaults.
  const GOOGLE_SERVICES: ReadonlySet<string> = new Set(['drive', 'gmail', 'calendar']);
  const asked = request.nextUrl.searchParams.get('service') ?? 'drive';
  if (!GOOGLE_SERVICES.has(asked)) return back(request, 'unknownservice');
  const service = asked;

  let url: string;
  try {
    ({ url } = await googleAuthorizeUrl(session.credential, {
      state,
      code_challenge: challenge,
      service,
    }));
  } catch (error) {
    // 503 from this route means one thing: Google is not configured on the
    // server. That is a deployment fact worth naming precisely, and it is the
    // one an operator hits first.
    if (error instanceof ApiError && error.failure.status === 503) {
      return back(request, 'unconfigured');
    }

    if (error instanceof ApiError) {
      // The control plane *answered*, with a refusal. Saying "it did not
      // answer" here sent somebody looking for a dead process when the real
      // cause was a running API older than this dashboard — the two halves
      // disagreeing about a query parameter. Logged with the code, because the
      // browser must not be told which field a schema rejected but an operator
      // has to be able to find out.
      console.warn(
        `[connect] control plane refused authorize-url: ${error.failure.status} ${error.failure.code}`,
      );
      return back(request, 'rejected');
    }

    return back(request, 'unavailable');
  }

  const response = NextResponse.redirect(url, { status: 302 });
  response.cookies.set(
    CONNECT_COOKIE,
    sealConnect({ verifier, state, provider: 'google', expiresAt: Date.now() + CONNECT_TTL_MS }),
    { ...cookieOptions(), maxAge: Math.floor(CONNECT_TTL_MS / 1000) },
  );
  return response;
}

function back(request: NextRequest, reason: string): NextResponse {
  const target = new URL('/connections', publicOrigin(request));
  target.searchParams.set('error', reason);
  return NextResponse.redirect(target, { status: 303 });
}
