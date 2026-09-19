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
 *  3. The subject is resolved to a user and workspace through the API.
 *
 * Step 3 has three endings, and only one of them used to exist:
 *
 *   * **One workspace.** Sign in. The ordinary case.
 *   * **None.** Nobody knows this subject, so they are offered a workspace of
 *     their own (§1.3's individual professional). This is *not* a way into an
 *     existing tenant — the API refuses to provision a subject that already
 *     belongs anywhere, and nothing here can name a workspace to join.
 *   * **Several.** They belong to more than one and have to choose. Reachable
 *     the moment people can have a personal workspace *and* be invited to an
 *     employer's, which is the day self-signup shipped.
 *
 * The last two hand off through a signed cookie rather than a query parameter:
 * the subject is the one thing the next page must not let a visitor choose.
 *
 * The flow cookie is cleared on every path out, success or failure, so one
 * attempt cannot be replayed.
 */

import { NextResponse, type NextRequest } from 'next/server';
import * as client from 'openid-client';
import { discover, oidcSettings } from '@/lib/oidc';
import { FLOW_COOKIE, openFlow } from '@/lib/flow-cookie';
import { PENDING_COOKIE, PENDING_TTL_MS, sealPending } from '@/lib/pending-cookie';
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

  if (identities.length !== 1) {
    // Nobody knows them, or several workspaces do. Either way the next page
    // needs to know *which verified human* this is, and a query parameter would
    // let a visitor answer that question themselves.
    const response = NextResponse.redirect(
      new URL(identities.length === 0 ? '/welcome' : '/choose', request.url),
      { status: 303 },
    );

    response.cookies.set(
      PENDING_COOKIE,
      sealPending({
        subject: `oidc|${subject}`,
        candidates: identities.map((i) => ({
          userId: i.user_id,
          workspaceId: i.workspace_id,
        })),
        expiresAt: Date.now() + PENDING_TTL_MS,
      }),
      { ...cookieOptions(), maxAge: Math.floor(PENDING_TTL_MS / 1000) },
    );
    response.cookies.delete(FLOW_COOKIE);
    return response;
  }

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
  // A pending cookie left over from an abandoned signup must not outlive a
  // successful sign-in as a second, stale identity.
  response.cookies.delete(PENDING_COOKIE);
  return response;
}

function failed(reason: 'expired' | 'rejected' | 'unknown' | 'ambiguous'): NextResponse {
  const response = NextResponse.redirect(
    new URL(`/signed-out?reason=${reason}`, process.env['DASHBOARD_URL'] ?? 'http://localhost:3000'),
    { status: 303 },
  );
  response.cookies.delete(FLOW_COOKIE);
  response.cookies.delete(PENDING_COOKIE);
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
