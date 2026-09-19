/**
 * GET /login — start the OIDC flow.
 *
 * Generates PKCE, state and nonce, seals them into a short-lived signed cookie,
 * and redirects to the provider. Nothing from the request influences where the
 * user is sent: the redirect URI comes from configuration, so there is no
 * parameter to tamper with and no open redirect to find.
 */

import { NextResponse } from 'next/server';
import * as client from 'openid-client';
import { discover, oidcSettings } from '@/lib/oidc';
import { FLOW_COOKIE, FLOW_TTL_MS, sealFlow } from '@/lib/flow-cookie';
import { cookieOptions } from '@/lib/cookie-options';

export const dynamic = 'force-dynamic';

export async function GET() {
  let settings;
  try {
    settings = oidcSettings();
  } catch (error) {
    // Not configured is not "signed out" — say so plainly rather than looping
    // the user through a flow that cannot complete.
    return NextResponse.json(
      { error: { code: 'SIGN_IN_UNCONFIGURED', message: (error as Error).message } },
      { status: 503 },
    );
  }

  const config = await discover(settings);

  const verifier = client.randomPKCECodeVerifier();
  const challenge = await client.calculatePKCECodeChallenge(verifier);
  const state = client.randomState();
  const nonce = client.randomNonce();

  const authorizationUrl = client.buildAuthorizationUrl(config, {
    redirect_uri: settings.redirectUri,
    scope: settings.scope,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    nonce,
    // Always ask which account. Without this the provider silently reuses
    // whichever session the browser already has, which is wrong in both
    // directions: somebody with a work and a personal account cannot choose,
    // and somebody signing out on a shared machine is handed straight back in.
    //
    // `select_account` and not `login`: it asks who, not for the password
    // again. Re-authentication is a step-up decision and belongs to the
    // approval ceremony, not to opening the dashboard.
    prompt: 'select_account',
  });

  const response = NextResponse.redirect(authorizationUrl.href, { status: 302 });
  response.cookies.set(
    FLOW_COOKIE,
    sealFlow({ verifier, state, nonce, expiresAt: Date.now() + FLOW_TTL_MS }),
    { ...cookieOptions(), maxAge: Math.floor(FLOW_TTL_MS / 1000) },
  );
  return response;
}
