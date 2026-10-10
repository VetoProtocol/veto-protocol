/**
 * GET /connections/github/callback — finish the GitHub App install.
 *
 * Every step is a refusal rather than a fallback:
 *
 *  1. A signed-in session. The installation is stored against *this* workspace,
 *     so a callback arriving without one has nowhere legitimate to land.
 *  2. The connect cookie must be present, signed with this app's key, and
 *     unexpired. A callback arriving on its own is the OAuth CSRF case (§12.1),
 *     and it bites harder here than it does for Google: an attacker who can
 *     make the browser follow this route with their own `installation_id`
 *     would attach *their* repositories to the victim's workspace — and every
 *     file the victim's agents then read would be the attacker's to choose.
 *  3. `state` must equal the sealed one, compared without leaking where it
 *     stopped matching.
 *  4. A `code` must be present. It is what proves the installation belongs to
 *     the person who just completed the flow — the control plane exchanges it
 *     for a user token and asks GitHub which installations that person can
 *     actually reach. Asking what an installation *is* was never a check on
 *     who may claim it, and for a while nothing here was.
 *  5. All of it goes to the control plane. This route never decides whose
 *     repositories these are; it carries values the server then verifies.
 *
 * The cookie is cleared on every path out, success or failure, so one attempt
 * cannot be replayed. Outcomes travel as a fixed code that the page looks up,
 * never as text: this route handles values a stranger chose.
 */

import { timingSafeEqual } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { ApiError, connectGithub } from '@/lib/api';
import { CONNECT_COOKIE, openConnect } from '@/lib/connect-cookie';
import { currentSession } from '@/lib/session';
import { publicOrigin } from '@/lib/public-url';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const session = await currentSession();
  if (!session) return done(request, 'error', 'session');

  const sealed = request.cookies.get(CONNECT_COOKIE)?.value;
  const flow = sealed ? openConnect(sealed) : null;
  if (!flow) return done(request, 'error', 'expired');

  // A Google consent cookie must not open this door. They are different round
  // trips with different properties, and one standing in for the other is the
  // kind of substitution that looks like it works right up until it matters.
  if (flow.provider !== 'github') return done(request, 'error', 'mismatch');

  const params = request.nextUrl.searchParams;

  // GitHub's own refusal. The parameter is caller-controlled, so it decides
  // which of our messages to show and is never printed itself.
  const refused = params.get('error');
  if (refused !== null) {
    return done(request, 'error', refused === 'access_denied' ? 'declined' : 'refused');
  }

  if (!equal(params.get('state') ?? '', flow.state)) {
    return done(request, 'error', 'mismatch');
  }

  // Digits only. The id reaches a URL path on the server, and a schema there
  // enforces the same thing — but a value that cannot be a path segment should
  // not travel this far in the first place.
  const installationId = params.get('installation_id') ?? '';
  if (!/^[0-9]{1,20}$/.test(installationId)) return done(request, 'error', 'noinstallation');

  // The proof. Present only because the App has "Request user authorization
  // (OAuth) during installation" switched on — without it GitHub sends no code,
  // and there is no way to tell whether this installation belongs to the person
  // who just arrived. Missing is a refusal, never a reason to continue: the
  // whole point is that an installation id alone is a claim.
  const code = params.get('code') ?? '';
  if (!/^[A-Za-z0-9._~-]{8,512}$/.test(code)) return done(request, 'error', 'nouserauth');

  try {
    // Nothing from this is carried back in the URL. The page re-reads the
    // connection list, so what it shows is what GitHub confirmed rather than
    // what this redirect claimed.
    // Three values, three different jobs. The cookie proves this browser began
    // the flow; the state proves the control plane issued it for this
    // workspace; the code proves the installation belongs to the person who
    // just granted it. Only the third is about ownership, and it is the one
    // that was missing.
    await connectGithub(session.credential, {
      installation_id: installationId,
      state: flow.state,
      code,
    });
    return done(request, 'connected', 'ok');
  } catch (error) {
    if (error instanceof ApiError && error.failure.status === 503) {
      return done(request, 'error', 'unconfigured');
    }
    return done(request, 'error', 'exchange');
  }
}

function done(request: NextRequest, key: 'connected' | 'error', reason: string): NextResponse {
  const target = new URL('/connections', publicOrigin(request));
  target.searchParams.set(key, reason);
  const response = NextResponse.redirect(target, { status: 303 });
  response.cookies.delete(CONNECT_COOKIE);
  return response;
}

function equal(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
