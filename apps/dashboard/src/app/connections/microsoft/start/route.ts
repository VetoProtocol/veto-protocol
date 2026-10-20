/**
 * GET /connections/microsoft/start — begin the Microsoft 365 consent round trip.
 *
 * Google's route with a different provider name, and deliberately so: both are
 * authorization-code flows with PKCE, so the browser half is the same shape and
 * the differences belong in the provider adapter rather than here.
 *
 * What this route does *not* do remains the point: it never sees the client
 * secret, never learns the redirect URI, and never touches a token. It
 * generates a PKCE verifier and a state, keeps both in a signed five-minute
 * cookie, asks the control plane where to send the user, and redirects.
 *
 * A signed-in session is required first. Consent granted by an anonymous
 * visitor would have no workspace to belong to.
 *
 * Failures come back as a fixed code, never as text, so a crafted link cannot
 * put words in the product's mouth.
 */

import { NextResponse, type NextRequest } from 'next/server';
import * as client from 'openid-client';
import { cookieOptions } from '@/lib/cookie-options';
import { CONNECT_COOKIE, CONNECT_TTL_MS, sealConnect } from '@/lib/connect-cookie';
import { ApiError, microsoftAuthorizeUrl } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { publicOrigin } from '@/lib/public-url';

export const dynamic = 'force-dynamic';

/**
 * A hand-kept copy of `MICROSOFT_SERVICES`, checked against a closed set.
 *
 * The real list lives in `@veto/connections`, which the dashboard cannot
 * import: it re-exports relative `.ts` files and the Next build runs with
 * `allowImportingTsExtensions` off. So `connect-services.test.ts` compares the
 * two by reading both files, because this exact copy drifted for Google —
 * `calendar` was missing, the fallback was Drive, and pressing "connect
 * Calendar" stored a **Drive** grant. The user approved what they were shown
 * and got something else, which §1 calls a security incident.
 *
 * There is therefore no fallback for an unrecognised service. Substituting one
 * service for another is the one thing a consent screen must never do. Only a
 * *missing* service defaults.
 */
const MICROSOFT_SERVICES: ReadonlySet<string> = new Set(['mail', 'calendar']);

export async function GET(request: NextRequest) {
  const session = await currentSession();
  if (!session) return back(request, 'session');

  const verifier = client.randomPKCECodeVerifier();
  const challenge = await client.calculatePKCECodeChallenge(verifier);
  const state = client.randomState();

  const asked = request.nextUrl.searchParams.get('service') ?? 'mail';
  if (!MICROSOFT_SERVICES.has(asked)) return back(request, 'unknownservice');
  const service = asked;

  let url: string;
  try {
    ({ url } = await microsoftAuthorizeUrl(session.credential, {
      state,
      code_challenge: challenge,
      service,
    }));
  } catch (error) {
    // 503 from this route means one thing: Microsoft is not configured on the
    // server. That is a deployment fact worth naming precisely, and the one an
    // operator hits first.
    if (error instanceof ApiError && error.failure.status === 503) {
      return back(request, 'unconfigured');
    }

    if (error instanceof ApiError) {
      // The control plane answered, with a refusal. Reporting that as "it did
      // not answer" once sent somebody looking for a dead process when the
      // cause was a running API older than this dashboard. Logged with the
      // code, because the browser must not be told which field a schema
      // rejected but an operator has to be able to find out.
      console.warn(
        `[connect] control plane refused microsoft authorize-url: ${error.failure.status} ${error.failure.code}`,
      );
      return back(request, 'rejected');
    }

    return back(request, 'unavailable');
  }

  const response = NextResponse.redirect(url, { status: 302 });
  response.cookies.set(
    CONNECT_COOKIE,
    sealConnect({ verifier, state, provider: 'microsoft', expiresAt: Date.now() + CONNECT_TTL_MS }),
    { ...cookieOptions(), maxAge: Math.floor(CONNECT_TTL_MS / 1000) },
  );
  return response;
}

function back(request: NextRequest, reason: string): NextResponse {
  const target = new URL('/connections', publicOrigin(request));
  target.searchParams.set('error', reason);
  return NextResponse.redirect(target, { status: 303 });
}
