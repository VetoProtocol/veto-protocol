/**
 * GET /connections/microsoft/callback — finish the Microsoft 365 round trip.
 *
 * Every step is a refusal rather than a fallback:
 *
 *  1. A signed-in session. The grant is stored against *this* workspace, so a
 *     callback arriving without one has nowhere legitimate to land.
 *  2. The connect cookie must be present, signed with this app's key, unexpired
 *     and minted for **this** provider. A callback arriving on its own is the
 *     OAuth CSRF case (§12.1): an attacker who can make the browser follow
 *     their own consent URL would otherwise attach *their* Microsoft account to
 *     the victim's workspace.
 *  3. `state` must equal the sealed one, compared without leaking where it
 *     stopped matching.
 *  4. The code and the PKCE verifier go to the control plane, which holds the
 *     client secret and does the exchange. Neither value is ever reflected back
 *     into a URL or a page.
 *
 * The cookie is cleared on every path out, success or failure, so one attempt
 * cannot be replayed. Outcomes travel as a fixed code the page looks up, never
 * as text: this route handles values a stranger chose.
 */

import { timingSafeEqual } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { ApiError, connectMicrosoft } from '@/lib/api';
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
  // A cookie minted for another provider must not open this one. They are
  // different round trips with different security properties, and one ending
  // in a Microsoft grant is not interchangeable with one ending in a Google
  // grant or a Slack bot token.
  if (flow.provider !== 'microsoft') return done(request, 'error', 'mismatch');

  const params = request.nextUrl.searchParams;

  // Microsoft's own refusal. The parameter is caller-controlled, so it decides
  // which of *our* messages to show and is never printed itself.
  //
  // `consent_required` is called out because it has a specific cause and a
  // specific fix: the tenant has turned off user consent, and an administrator
  // has to approve the app once. Reported as a generic failure it reads like a
  // bad secret, and somebody goes looking in the wrong place.
  const refused = params.get('error');
  if (refused !== null) {
    if (refused === 'access_denied') return done(request, 'error', 'declined');
    if (refused === 'consent_required' || refused === 'admin_consent_required') {
      return done(request, 'error', 'adminconsent');
    }
    return done(request, 'error', 'refused');
  }

  if (!equal(params.get('state') ?? '', flow.state)) {
    return done(request, 'error', 'mismatch');
  }

  const code = params.get('code') ?? '';
  if (code === '') return done(request, 'error', 'nocode');

  try {
    // Nothing from the exchange is carried back in the URL. The page re-reads
    // the connection list, so what it shows is what was actually granted
    // rather than what this redirect claimed.
    await connectMicrosoft(session.credential, { code, code_verifier: flow.verifier });
    // Names the provider, because the page once reported every success in
    // Google's words — including a GitHub one.
    return done(request, 'connected', 'microsoft');
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
