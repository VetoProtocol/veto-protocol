/**
 * Dynamic client registration (RFC 7591).
 *
 * ## Unauthenticated, on purpose
 *
 * A desktop MCP client arrives with no credential and no way to obtain one.
 * Requiring authentication here would mean issuing client ids by hand to every
 * customer's laptop, which is the problem this whole feature exists to remove.
 *
 * What makes that safe is not a check in this file. **A registered client holds
 * no authority.** It is a name and a list of redirect URIs. It cannot read,
 * cannot decide, and cannot be granted anything. All it can do is ask a human
 * to approve it, on a screen where the human sees what they are approving.
 *
 * A client that calls itself "Veto Admin" is a phishing attempt, and nothing
 * here can tell. That problem belongs to the consent screen's wording, and
 * putting a name filter here would move it somewhere it cannot be solved.
 */

import { NextResponse, type NextRequest } from 'next/server';
import { oauthServerCredential } from '@/lib/oauth-config';

export const dynamic = 'force-dynamic';

const CONTROL_PLANE = process.env['VETO_API_URL'] ?? 'http://127.0.0.1:4000';

/** RFC 7591 §3.2.2 error shape. Clients parse this, so it is not our envelope. */
const oauthError = (error: string, description: string, status: number) =>
  NextResponse.json({ error, error_description: description }, { status });

export async function POST(request: NextRequest) {
  let body: { client_name?: unknown; redirect_uris?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return oauthError('invalid_client_metadata', 'Body must be JSON', 400);
  }

  const clientName = typeof body.client_name === 'string' ? body.client_name.trim() : '';
  const redirectUris = Array.isArray(body.redirect_uris)
    ? body.redirect_uris.filter((uri): uri is string => typeof uri === 'string')
    : [];

  if (clientName === '' || redirectUris.length === 0) {
    return oauthError(
      'invalid_client_metadata',
      'client_name and at least one redirect_uris entry are required',
      400,
    );
  }

  const response = await fetch(`${CONTROL_PLANE}/v1/oauth/clients`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${oauthServerCredential()}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ client_name: clientName, redirect_uris: redirectUris }),
    signal: AbortSignal.timeout(10_000),
  }).catch(() => null);

  if (response === null) {
    return oauthError('server_error', 'The control plane could not be reached', 503);
  }

  const payload = (await response.json().catch(() => ({}))) as Record<string, unknown>;

  if (!response.ok) {
    // The control plane's reason, translated into the vocabulary a client
    // parses. Its own envelope would be meaningless here.
    const detail = (payload['error'] as { message?: string } | undefined)?.message;
    return oauthError(
      'invalid_client_metadata',
      detail ?? 'Registration was refused',
      response.status === 503 ? 503 : 400,
    );
  }

  return NextResponse.json(
    {
      client_id: payload['client_id'],
      client_name: payload['client_name'],
      redirect_uris: payload['redirect_uris'],
      // No secret. A desktop application cannot keep one, and issuing it would
      // mean shipping the same value inside every copy.
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    },
    { status: 201 },
  );
}
