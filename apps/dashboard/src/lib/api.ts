/**
 * Server-side client for the Veto control-plane API (`apps/api`).
 *
 * The dashboard never reaches the database. Everything goes through the same
 * HTTP surface any other client uses, so the rules enforced there — tenant from
 * the principal, owner from the principal, closed request schemas — apply to
 * the dashboard exactly as they apply to a script with curl. A dashboard with a
 * private back door would be a second enforcement point, and invariant 8 allows
 * one.
 *
 * Server-only. Nothing here may be imported into a client component: it carries
 * the session credential, and a bundler that follows an import would ship it.
 */

import 'server-only';

export interface Agent {
  readonly id: string;
  readonly workspace_id: string;
  readonly provider: string;
  readonly client_id: string;
  readonly owner_user_id: string;
  readonly status: 'active' | 'suspended' | 'revoked';
  readonly has_fingerprint: boolean;
  readonly created_at: string;
  readonly revoked_at: string | null;
}

export interface ApiFailure {
  readonly code: string;
  readonly message: string;
  readonly status: number;
}

export class ApiError extends Error {
  readonly failure: ApiFailure;

  // Not a parameter property: see the note in apps/api/src/errors.ts.
  constructor(failure: ApiFailure) {
    super(failure.message);
    this.failure = failure;
    this.name = 'ApiError';
  }
}

function baseUrl(): string {
  const url = (process.env['VETO_API_URL'] ?? '').trim();
  if (!url) {
    throw new Error('VETO_API_URL is not set; the dashboard has no control plane to talk to.');
  }
  return url.replace(/\/+$/, '');
}

async function request<T>(path: string, init: RequestInit & { credential: string }): Promise<T> {
  const { credential, ...rest } = init;

  const response = await fetch(`${baseUrl()}${path}`, {
    ...rest,
    headers: {
      ...(rest.body === undefined ? {} : { 'content-type': 'application/json' }),
      authorization: `Bearer ${credential}`,
      ...rest.headers,
    },
    // Authorization state is never served from a cache.
    cache: 'no-store',
  });

  const text = await response.text();
  const body: unknown = text === '' ? null : JSON.parse(text);

  if (!response.ok) {
    const failure = (body as { error?: { code?: string; message?: string } } | null)?.error;
    throw new ApiError({
      code: failure?.code ?? 'UNKNOWN',
      // The API's message is already written for a caller and carries no
      // internals; it is shown as-is rather than reworded into something vaguer.
      message: failure?.message ?? `Request failed (${response.status})`,
      status: response.status,
    });
  }

  return body as T;
}

/** Sign-in lookup. Uses the identity-resolve scope, which reaches nothing else. */
export const resolveIdentity = async (
  credential: string,
  subject: string,
): Promise<Array<{ user_id: string; workspace_id: string }>> => {
  const { identities } = await request<{ identities: Array<{ user_id: string; workspace_id: string }> }>(
    '/v1/auth/resolve',
    { method: 'POST', credential, body: JSON.stringify({ subject }) },
  );
  return identities;
};

export const listAgents = (credential: string): Promise<{ agents: Agent[] }> =>
  request('/v1/agents', { method: 'GET', credential });

export const registerAgent = (
  credential: string,
  input: { provider: string; client_id: string; fingerprint?: string },
): Promise<Agent> =>
  request('/v1/agents', { method: 'POST', credential, body: JSON.stringify(input) });

export const revokeAgent = (
  credential: string,
  agentId: string,
): Promise<{ agent_id: string; revoked: boolean; already_revoked: boolean; sessions_dropped: number }> =>
  request(`/v1/agents/${encodeURIComponent(agentId)}`, { method: 'DELETE', credential });
