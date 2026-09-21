/**
 * Verify a wallet signature and, if it resolves to one identity, sign them in.
 *
 * The branches are the same three the OIDC callback takes, deliberately: nobody
 * knows this subject (offer a workspace), exactly one does (sign in), or
 * several do (ask which). A second way in should not be a second set of rules
 * about what being known means.
 */

import { NextResponse, type NextRequest } from 'next/server';
import { verifyWalletSignature } from '@veto/wallet';
import { cookieOptions } from '@/lib/cookie-options';
import { resolveIdentity } from '@/lib/api';
import { resolveCredential, sessionCredential, SESSION_TTL_MS } from '@/lib/credential';
import { SESSION_COOKIE, signSession } from '@/lib/session';
import { PENDING_COOKIE, PENDING_TTL_MS, sealPending } from '@/lib/pending-cookie';
import { openWalletFlow, WALLET_COOKIE } from '@/lib/wallet-cookie';

export const dynamic = 'force-dynamic';

const domainOf = (request: NextRequest): string =>
  (process.env['DASHBOARD_PUBLIC_URL'] ?? request.nextUrl.origin).replace(/^https?:\/\//, '');

const refuse = (reason: string) => NextResponse.json({ error: reason }, { status: 400 });

export async function POST(request: NextRequest) {
  const sealed = request.cookies.get(WALLET_COOKIE)?.value ?? '';
  const flow = openWalletFlow(sealed);
  // No cookie means no attempt was started here. A signature arriving without
  // one was gathered somewhere else.
  if (!flow) return refuse('That attempt timed out. Start again.');

  const body = (await request.json().catch(() => ({}))) as {
    address?: unknown;
    message?: unknown;
    signature?: unknown;
  };

  const verified = await verifyWalletSignature({
    address: typeof body.address === 'string' ? body.address : '',
    message: typeof body.message === 'string' ? body.message : '',
    signature: typeof body.signature === 'string' ? body.signature : '',
    // From the cookie, never from the body. A nonce the caller supplies both
    // sides of is not a nonce.
    expectedNonce: flow.nonce,
    expectedDomain: domainOf(request),
  });

  if (!verified.ok) {
    // One answer for every failure. Which check refused is not something a
    // caller needs, and telling them turns the endpoint into an oracle.
    return refuse('That signature could not be verified.');
  }

  const identities = await resolveIdentity(resolveCredential(), verified.subject);

  const clearFlow = (response: NextResponse) => {
    // Single use. The nonce is spent whatever happened next.
    response.cookies.delete(WALLET_COOKIE);
    return response;
  };

  if (identities.length !== 1) {
    const response = NextResponse.json({
      next: identities.length === 0 ? '/welcome' : '/choose',
    });
    response.cookies.set(
      PENDING_COOKIE,
      sealPending({
        subject: verified.subject,
        candidates: identities.map((i) => ({ userId: i.user_id, workspaceId: i.workspace_id })),
        expiresAt: Date.now() + PENDING_TTL_MS,
      }),
      { ...cookieOptions(), maxAge: Math.floor(PENDING_TTL_MS / 1000) },
    );
    return clearFlow(response);
  }

  const identity = identities[0];
  if (!identity) return refuse('That signature could not be verified.');

  const expiresAt = Date.now() + SESSION_TTL_MS;
  const response = NextResponse.json({ next: '/agents' });
  response.cookies.set(
    SESSION_COOKIE,
    signSession({
      workspaceId: identity.workspace_id,
      userId: identity.user_id,
      credential: sessionCredential(identity.workspace_id, identity.user_id),
      expiresAt,
    }),
    { ...cookieOptions(), maxAge: Math.floor(SESSION_TTL_MS / 1000) },
  );
  // A pending cookie from an abandoned signup must not outlive a successful
  // sign-in as a second, stale identity.
  response.cookies.delete(PENDING_COOKIE);
  return clearFlow(response);
}
