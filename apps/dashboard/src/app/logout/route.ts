/**
 * POST /logout.
 *
 * POST, not GET: a GET logout can be triggered by any page that can make the
 * browser issue a request, which is a nuisance rather than a vulnerability but
 * an avoidable one.
 *
 * Clearing the cookie ends the dashboard session. The capability token inside
 * it is already short-lived and cannot be extended, so nothing needs revoking
 * server-side.
 */

import { NextResponse, type NextRequest } from 'next/server';
import { SESSION_COOKIE } from '@/lib/session';

export const dynamic = 'force-dynamic';

export async function POST(request: NextRequest) {
  const response = NextResponse.redirect(new URL('/signed-out', request.url), { status: 303 });
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
