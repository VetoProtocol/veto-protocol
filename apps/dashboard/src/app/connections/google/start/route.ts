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

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const session = await currentSession();
  if (!session) return back(request, 'session');

  const verifier = client.randomPKCECodeVerifier();
  const challenge = await client.calculatePKCECodeChallenge(verifier);
  const state = client.randomState();

  let url: string;
  try {
    ({ url } = await googleAuthorizeUrl(session.credential, {
      state,
      code_challenge: challenge,
    }));
  } catch (error) {
    // 503 from this route means one thing: Google is not configured on the
    // server. That is a deployment fact worth naming precisely, and it is the
    // one an operator hits first.
    if (error instanceof ApiError && error.failure.status === 503) {
      return back(request, 'unconfigured');
    }
    return back(request, 'unavailable');
  }

  const response = NextResponse.redirect(url, { status: 302 });
  response.cookies.set(
    CONNECT_COOKIE,
    sealConnect({ verifier, state, expiresAt: Date.now() + CONNECT_TTL_MS }),
    { ...cookieOptions(), maxAge: Math.floor(CONNECT_TTL_MS / 1000) },
  );
  return response;
}

function back(request: NextRequest, reason: string): NextResponse {
  const target = new URL('/connections', request.url);
  target.searchParams.set('error', reason);
  return NextResponse.redirect(target, { status: 303 });
}
