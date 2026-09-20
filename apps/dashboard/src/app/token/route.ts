/**
 * The token endpoint, as a client sees it.
 *
 * ## A translator, not a decision maker
 *
 * Every check — the code, PKCE, the redirect URI, the resource, refresh
 * rotation — happens on the control plane, which holds the code, the refresh
 * row and the signing key. Splitting those across a network hop would mean each
 * half trusting the other to have done its share, and the half a client talks
 * to is the wrong place to hold a signing key.
 *
 * What this adds is the vocabulary. Clients parse RFC 6749 §5.2 error codes,
 * and this codebase's error envelope means nothing to them.
 *
 * ## Form encoding, because that is what the RFC says
 *
 * §4.1.3 posts `application/x-www-form-urlencoded`. A client that does the
 * right thing must not be met with a server that only accepts JSON.
 */

import { NextResponse, type NextRequest } from 'next/server';
import { oauthServerCredential } from '@/lib/oauth-config';

export const dynamic = 'force-dynamic';

const CONTROL_PLANE = process.env['VETO_API_URL'] ?? 'http://127.0.0.1:4000';

/** RFC 6749 §5.2. `invalid_grant` covers a code or refresh token that is not usable. */
const REASON_TO_OAUTH: Record<string, string> = {
  APPROVAL_EXPIRED: 'invalid_grant',
  APPROVAL_REPLAYED: 'invalid_grant',
  IDENTITY_UNRESOLVED: 'invalid_grant',
  RESOURCE_OUT_OF_SCOPE: 'invalid_target',
  ARGUMENT_SCHEMA_INVALID: 'invalid_request',
  CLIENT_UNKNOWN: 'invalid_client',
  POLICY_UNAVAILABLE: 'temporarily_unavailable',
};

const fail = (error: string, description: string, status: number) =>
  NextResponse.json(
    { error, error_description: description },
    // §5.2: no caching, ever. A cached token response is a token somebody else
    // can read out of a proxy.
    { status, headers: { 'cache-control': 'no-store', pragma: 'no-cache' } },
  );

export async function POST(request: NextRequest) {
  let form: URLSearchParams;
  try {
    const type = request.headers.get('content-type') ?? '';
    if (type.includes('application/json')) {
      // Not required by the RFC, and accepted because some clients send it.
      const body = (await request.json()) as Record<string, unknown>;
      form = new URLSearchParams(
        Object.entries(body).map(([k, v]) => [k, typeof v === 'string' ? v : String(v)]),
      );
    } else {
      form = new URLSearchParams(await request.text());
    }
  } catch {
    return fail('invalid_request', 'Body could not be read', 400);
  }

  const grantType = form.get('grant_type') ?? '';
  if (grantType !== 'authorization_code' && grantType !== 'refresh_token') {
    return fail('unsupported_grant_type', 'Only authorization_code and refresh_token', 400);
  }

  const payload: Record<string, string> = { grant_type: grantType };
  for (const key of ['client_id', 'code', 'code_verifier', 'redirect_uri', 'refresh_token', 'resource']) {
    const value = form.get(key);
    if (value !== null && value !== '') payload[key] = value;
  }

  const response = await fetch(`${CONTROL_PLANE}/v1/oauth/token`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${oauthServerCredential()}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15_000),
  }).catch(() => null);

  if (response === null) {
    return fail('temporarily_unavailable', 'The control plane could not be reached', 503);
  }

  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;

  if (!response.ok) {
    const failure = body['error'] as { code?: string; message?: string } | undefined;
    const code = failure?.code ?? '';
    return fail(
      REASON_TO_OAUTH[code] ?? 'invalid_request',
      // The control plane's own wording. It is written for a person reading a
      // log, and a vaguer version here would help nobody.
      failure?.message ?? 'The request was refused',
      response.status === 503 ? 503 : 400,
    );
  }

  return NextResponse.json(body, {
    headers: { 'cache-control': 'no-store', pragma: 'no-cache' },
  });
}
