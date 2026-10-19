/**
 * GET /connections/slack/callback — finish a Slack install.
 *
 * Every step is a refusal rather than a fallback: a signed-in session, a
 * connect cookie sealed by this app and unexpired, a `provider` of `slack`,
 * and a state equal to the sealed one.
 *
 * The `code` is what proves this. Unlike a GitHub installation id — a small
 * integer anybody could type, which is why that flow needed a separate
 * ownership check — an authorization code cannot be forged, and exchanging it
 * with the client secret is itself the proof. The state here is CSRF
 * protection and nothing more.
 *
 * The cookie is cleared on every path out, so one attempt cannot be replayed.
 */

import { timingSafeEqual } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { ApiError, connectSlack } from '@/lib/api';
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

  // A Google or GitHub cookie must not open this door. Different round trips
  // with different properties, and one standing in for another is the kind of
  // substitution that looks like it works right up until it matters.
  if (flow.provider !== 'slack') return done(request, 'error', 'mismatch');

  const params = request.nextUrl.searchParams;

  // Slack's own refusal. Caller-controlled, so it picks which of our messages
  // to show and is never printed itself.
  const refused = params.get('error');
  if (refused !== null) {
    return done(request, 'error', refused === 'access_denied' ? 'declined' : 'refused');
  }

  if (!equal(params.get('state') ?? '', flow.state)) {
    return done(request, 'error', 'mismatch');
  }

  const code = params.get('code') ?? '';
  if (!/^[A-Za-z0-9._~-]{8,512}$/.test(code)) return done(request, 'error', 'nocode');

  try {
    await connectSlack(session.credential, { code, state: flow.state });
    return done(request, 'connected', 'slack');
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

/** Compared without leaking where it stopped matching. */
function equal(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
