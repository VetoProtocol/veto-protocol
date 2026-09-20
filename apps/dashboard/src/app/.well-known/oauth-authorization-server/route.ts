/**
 * Authorization server metadata (RFC 8414).
 *
 * The document a client fetches after the gateway's 401 tells it where to look.
 * Everything a conforming client needs to complete the flow without being
 * configured by hand — which is the entire point of the exercise.
 *
 * What is advertised is what is supported, and nothing else. Listing `plain`
 * PKCE or a grant type the token endpoint refuses would be inviting clients to
 * pick a path that fails, or worse, to assume a downgrade is available.
 */

import { NextResponse } from 'next/server';
import { gatewayResource, issuer } from '@/lib/oauth-config';

export const dynamic = 'force-dynamic';

export async function GET() {
  const base = issuer();

  return NextResponse.json(
    {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,

      response_types_supported: ['code'],
      // Authorization code only. Implicit puts a token in a URL and the
      // password grant asks a client to handle somebody's credentials; neither
      // survives RFC 9700, and a server that lists them will be asked for them.
      grant_types_supported: ['authorization_code', 'refresh_token'],

      // S256 only. `plain` makes the challenge equal the verifier, so a server
      // that offers it offers no protection to whoever selects it.
      code_challenge_methods_supported: ['S256'],

      // A public client: a desktop application cannot keep a secret, and
      // pretending otherwise would mean shipping one inside every copy.
      token_endpoint_auth_methods_supported: ['none'],

      // RFC 8707. The gateway is the only resource a token from here is for.
      resource_indicators_supported: true,
      resource_documentation: gatewayResource(),
    },
    {
      // Discovery is fetched before every authorization by some clients and
      // cached hard by others. Five minutes is short enough that moving an
      // endpoint takes effect, long enough not to be a hot path.
      headers: { 'cache-control': 'public, max-age=300' },
    },
  );
}
