/**
 * GET /connections/slack/start — begin a Slack install.
 *
 * The state comes back from the control plane rather than being minted here.
 * A value the browser chooses is not CSRF protection against the browser, and
 * the side that checks a value should be the side that issues it — the F-01
 * lesson, applied rather than repeated.
 *
 * No PKCE: Slack's OAuth has no code challenge, and this is a confidential
 * client whose secret never leaves the control plane. The cookie carries an
 * empty verifier for the same reason the GitHub flow does, and the `provider`
 * field is what stops either flow's cookie satisfying another's.
 *
 * Failures come back as a fixed code, never as text, so a crafted link cannot
 * put words in the product's mouth.
 */

import { NextResponse, type NextRequest } from 'next/server';
import { cookieOptions } from '@/lib/cookie-options';
import { CONNECT_COOKIE, CONNECT_TTL_MS, sealConnect } from '@/lib/connect-cookie';
import { ApiError, slackInstallUrl } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { publicOrigin } from '@/lib/public-url';

export const dynamic = 'force-dynamic';

/** Public channels unless asked otherwise. Private is a separate decision. */
const SERVICES = new Set(['channels', 'private_channels']);

export async function GET(request: NextRequest) {
  const session = await currentSession();
  if (!session) return back(request, 'session');

  const asked = request.nextUrl.searchParams.get('service') ?? 'channels';
  if (!SERVICES.has(asked)) return back(request, 'unknownservice');

  let url: string;
  let state: string;
  try {
    ({ url, state } = await slackInstallUrl(session.credential, { service: asked }));
  } catch (error) {
    if (error instanceof ApiError && error.failure.status === 503) {
      return back(request, 'unconfigured');
    }
    if (error instanceof ApiError) {
      console.warn(
        `[connect] control plane refused slack install-url: ${error.failure.status} ${error.failure.code}`,
      );
      return back(request, 'rejected');
    }
    return back(request, 'unavailable');
  }

  const response = NextResponse.redirect(url, { status: 302 });
  response.cookies.set(
    CONNECT_COOKIE,
    sealConnect({ verifier: '', state, provider: 'slack', expiresAt: Date.now() + CONNECT_TTL_MS }),
    { ...cookieOptions(), maxAge: Math.floor(CONNECT_TTL_MS / 1000) },
  );
  return response;
}

function back(request: NextRequest, reason: string): NextResponse {
  const target = new URL('/connections', publicOrigin(request));
  target.searchParams.set('error', reason);
  return NextResponse.redirect(target, { status: 303 });
}
