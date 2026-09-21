/**
 * Issue a nonce, and the message to sign with it.
 *
 * The message is composed **here**, never by the client. A message the client
 * composes is a message the client chooses, and "sign this to prove you own the
 * key" becomes "sign whatever I put in front of you" — which is how a signing
 * prompt is turned into an approval for something else entirely.
 */

import { NextResponse, type NextRequest } from 'next/server';
import { buildSiweMessage, ADDRESS_PATTERN } from '@veto/wallet';
import { cookieOptions } from '@/lib/cookie-options';
import { newNonce, sealWalletFlow, WALLET_COOKIE, WALLET_TTL_MS } from '@/lib/wallet-cookie';

export const dynamic = 'force-dynamic';

const domainOf = (request: NextRequest): string =>
  (process.env['DASHBOARD_PUBLIC_URL'] ?? request.nextUrl.origin).replace(/^https?:\/\//, '');

export async function POST(request: NextRequest) {
  const body = (await request.json().catch(() => ({}))) as { address?: unknown };
  const address = typeof body.address === 'string' ? body.address : '';
  if (!ADDRESS_PATTERN.test(address)) {
    return NextResponse.json({ error: 'address is required' }, { status: 400 });
  }

  const nonce = newNonce();
  const domain = domainOf(request);
  const message = buildSiweMessage({
    domain,
    address,
    uri: `https://${domain}`,
    nonce,
    issuedAt: new Date().toISOString(),
  });

  const response = NextResponse.json({ message });
  // The nonce goes back in a signed cookie, not in the response. The client
  // echoes the message; it never gets to choose what the server compares
  // against.
  response.cookies.set(
    WALLET_COOKIE,
    sealWalletFlow({ nonce, expiresAt: Date.now() + WALLET_TTL_MS }),
    { ...cookieOptions(), maxAge: Math.floor(WALLET_TTL_MS / 1000) },
  );
  return response;
}
