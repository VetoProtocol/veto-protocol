/**
 * GET /auth/callback — finish the OIDC flow.
 *
 * Order matters here, and every step is a refusal rather than a fallback:
 *
 *  1. The flow cookie must be present, signed, and unexpired. Without it there
 *     is nothing to validate the response against, so a callback arriving on
 *     its own is refused — that is the CSRF case (§12.1).
 *  2. The library checks state, PKCE verifier and nonce, and validates the id
 *     token's signature, issuer, audience and expiry against the provider's
 *     JWKS.
 *  3. The subject is resolved to a user and workspace through the API. An
 *     unknown subject is refused: there is **no auto-provisioning**, because
 *     creating a workspace for anyone who can complete a sign-in would make the
 *     provider's entire user base members of this system.
 *
 * The flow cookie is cleared on every path out, success or failure, so one
 * attempt cannot be replayed.
 */

import { NextResponse, type NextRequest } from 'next/server';
import * as client from 'openid-client';
import { discover, oidcSettings } from '@/lib/oidc';
import { FLOW_COOKIE, openFlow } from '@/lib/flow-cookie';
import { cookieOptions } from '@/lib/cookie-options';
import { resolveCredential, sessionCredential, SESSION_TTL_MS } from '@/lib/credential';
import { resolveIdentity } from '@/lib/api';
import { SESSION_COOKIE, signSession } from '@/lib/session';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const settings = oidcSettings();

  const sealed = request.cookies.get(FLOW_COOKIE)?.value;
  const flow = sealed ? openFlow(sealed) : null;
  if (!flow) return failed('expired');

  let subject: string;
  try {
    const config = await discover(settings);
    const tokens = await client.authorizationCodeGrant(config, new URL(request.url), {
      pkceCodeVerifier: flow.verifier,
      expectedState: flow.state,
      expectedNonce: flow.nonce,
    });
    subject = tokens.claims()?.sub ?? '';
  } catch {
    // The detail stays server-side. A callback failure is either a
    // misconfiguration or an attack, and neither is helped by telling the
    // browser which.
    return failed('rejected');
  }

  if (subject === '') return failed('rejected');

  // Namespaced the same way the seeds and tests write it, so one provider's
  // subject cannot collide with another's if a second is added later.
  const identities = await resolveIdentity(resolveCredential(), `oidc|${subject}`);

  if (identities.length === 0) {
    // Logged because there is no admin UI yet: this is how an operator learns
    // the subject to put in the invitation. A subject is an opaque identifier,
    // not a secret or protected content, so invariant 5 is not in play — but it
    // is the only identity detail that gets logged anywhere, deliberately.
    console.warn(`[auth] no workspace for subject oidc|${subject}`);
    return failed('unknown');
  }
  if (identities.length > 1) return failed('ambiguous');

  const identity = identities[0];
  if (!identity) return failed('unknown');

  const expiresAt = Date.now() + SESSION_TTL_MS;
  const response = NextResponse.redirect(new URL('/agents', request.url), { status: 303 });

  response.cookies.set(
    SESSION_COOKIE,
    signSession({
      workspaceId: identity.workspace_id,
      userId: identity.user_id,
      // The session cannot outlive the credential inside it; both expire together.
      credential: sessionCredential(identity.workspace_id, identity.user_id),
      expiresAt,
    }),
    { ...cookieOptions(), maxAge: Math.floor(SESSION_TTL_MS / 1000) },
  );
  response.cookies.delete(FLOW_COOKIE);
  return response;
}

function failed(reason: 'expired' | 'rejected' | 'unknown' | 'ambiguous'): NextResponse {
  const response = NextResponse.redirect(
    new URL(`/signed-out?reason=${reason}`, process.env['DASHBOARD_URL'] ?? 'http://localhost:3000'),
    { status: 303 },
  );
  response.cookies.delete(FLOW_COOKIE);
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
