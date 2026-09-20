import 'server-only';
import { redirectUriMatches } from '@veto/oauth/redirect';
import { gatewayResource } from '@/lib/oauth-config';

/** The shape this page needs of a client, fetched from the control plane. */
export interface AuthorizeClient {
  readonly id: string;
  readonly clientName: string;
  readonly redirectUris: readonly string[];
}

/**
 * Checking an authorization request, in the order the order matters.
 *
 * ## Two kinds of refusal, and why they are not the same
 *
 * A bad `client_id` or a `redirect_uri` that was not registered is refused
 * **on this page**. Everything else is refused by redirecting back to the
 * client with an error.
 *
 * That split is the whole security of this step. Redirecting an error to a URI
 * that has not been validated is an open redirect, and an open redirect on an
 * authorization endpoint is a way to deliver somebody else's code. So the
 * redirect target earns the right to be redirected to, before anything is sent
 * to it.
 */

export type FatalReason = 'CLIENT_UNKNOWN' | 'REDIRECT_URI_MISMATCH';

export interface AuthorizeRequest {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly state: string | null;
  readonly codeChallenge: string;
  readonly resource: string;
}

export type Validated =
  /** Refuse here. Nothing may be sent to the redirect URI. */
  | { readonly kind: 'fatal'; readonly reason: FatalReason }
  /** Refuse by redirecting: the target is registered, so it may be told. */
  | { readonly kind: 'redirect'; readonly error: string; readonly description: string }
  | { readonly kind: 'ok'; readonly request: AuthorizeRequest };

export function validateAuthorize(
  params: URLSearchParams,
  client: AuthorizeClient | null,
): Validated {
  // 1. The client, before anything else. An unknown client has no registered
  //    URI, so there is nowhere legitimate to send an error.
  if (client === null) return { kind: 'fatal', reason: 'CLIENT_UNKNOWN' };

  // 2. The redirect URI, compared whole. Not a prefix, not an origin.
  const redirectUri = params.get('redirect_uri') ?? '';
  if (!redirectUriMatches(client.redirectUris, redirectUri)) {
    return { kind: 'fatal', reason: 'REDIRECT_URI_MISMATCH' };
  }

  // From here the target is trusted enough to be told what went wrong.
  const fail = (error: string, description: string): Validated => ({
    kind: 'redirect',
    error,
    description,
  });

  if (params.get('response_type') !== 'code') {
    // Implicit puts a token in a URL. Not supported, and not silently
    // reinterpreted as something that is.
    return fail('unsupported_response_type', 'Only response_type=code is supported');
  }

  const codeChallenge = params.get('code_challenge') ?? '';
  const method = params.get('code_challenge_method') ?? undefined;
  if (method !== 'S256') {
    // An absent method means `plain` per RFC 7636, which is no protection at
    // all — so absent is refused as firmly as explicit.
    return fail('invalid_request', 'code_challenge_method must be S256');
  }
  if (!/^[A-Za-z0-9\-_]{43}$/.test(codeChallenge)) {
    return fail('invalid_request', 'code_challenge must be a base64url SHA-256');
  }

  // RFC 8707. A token from here is for the gateway and nothing else; a client
  // that asks for a different audience is asking for something this server does
  // not issue.
  const resource = (params.get('resource') ?? '').replace(/\/$/, '');
  if (resource === '') {
    return fail('invalid_target', 'A resource indicator is required');
  }
  if (resource !== gatewayResource()) {
    return fail('invalid_target', 'This server only issues tokens for the Veto gateway');
  }

  return {
    kind: 'ok',
    request: {
      clientId: client.id,
      redirectUri,
      state: params.get('state'),
      codeChallenge,
      resource,
    },
  };
}

/** Build the redirect that carries an error back to a validated client. */
export function errorRedirect(
  redirectUri: string,
  state: string | null,
  error: string,
  description: string,
): string {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('error_description', description);
  // Echoed back untouched. A client that sent state uses it to match this
  // response to its own request, and dropping it on the error path is how a
  // client ends up unable to tell which attempt failed.
  if (state !== null) url.searchParams.set('state', state);
  return url.href;
}
