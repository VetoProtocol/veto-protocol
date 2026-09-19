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

export interface GrantView {
  readonly agent_id: string;
  readonly resource_type: string;
  readonly resource_key: string;
}

export const listGrants = (credential: string): Promise<{ grants: GrantView[] }> =>
  request('/v1/grants', { method: 'GET', credential });

export const createGrant = (credential: string, body: GrantView): Promise<GrantView> =>
  request('/v1/grants', { method: 'POST', credential, body: JSON.stringify(body) });

export const revokeGrant = (credential: string, body: GrantView): Promise<{ revoked: boolean }> =>
  request('/v1/grants', { method: 'DELETE', credential, body: JSON.stringify(body) });

export interface PolicyView {
  readonly id: string;
  readonly version: string;
  readonly subject: string;
  readonly action: string;
  readonly effect: 'allow' | 'deny' | 'challenge';
  readonly resource_filter: { type?: string; ids?: string[]; prefix?: string };
  readonly conditions: { presence?: string[]; maxPerDay?: number; requireIntent?: boolean };
}

export const listPolicies = (credential: string): Promise<{ policies: PolicyView[] }> =>
  request('/v1/policies', { method: 'GET', credential });

export const createPolicy = (
  credential: string,
  body: {
    subject: string;
    action: string;
    effect: string;
    resource_filter: { type: string; ids?: string[]; prefix?: string };
    conditions?: { presence?: string[]; maxPerDay?: number; requireIntent?: boolean };
  },
): Promise<PolicyView> =>
  request('/v1/policies', { method: 'POST', credential, body: JSON.stringify(body) });

export const deletePolicy = (
  credential: string,
  policyId: string,
): Promise<{ policy_id: string; removed: boolean }> =>
  request(`/v1/policies/${encodeURIComponent(policyId)}`, { method: 'DELETE', credential });

export interface ConnectionView {
  readonly id: string;
  readonly provider: string;
  readonly scopes: string[];
  readonly status: string;
  readonly expires_at: string | null;
  readonly created_at: string;
}

export const listConnections = (credential: string): Promise<{ connections: ConnectionView[] }> =>
  request('/v1/connections', { method: 'GET', credential });

/**
 * Where to send the browser for consent.
 *
 * The URL is assembled by the API because the API is what exchanges the code
 * afterwards, and Google requires the redirect URI to match byte for byte
 * across both halves. The dashboard supplies only the two values it has to
 * recognise on the way back.
 */
export const googleAuthorizeUrl = (
  credential: string,
  query: { state: string; code_challenge: string; service?: string },
): Promise<{ url: string; scopes: string[] }> =>
  request(
    `/v1/connections/google/authorize-url?${new URLSearchParams(query).toString()}`,
    { method: 'GET', credential },
  );

/** Hands the authorization code across. Nothing comes back but the connection row. */
export const connectGoogle = (
  credential: string,
  body: { code: string; code_verifier: string },
): Promise<ConnectionView> =>
  request('/v1/connections/google', { method: 'POST', credential, body: JSON.stringify(body) });

export const revokeConnection = (
  credential: string,
  connectionId: string,
): Promise<{ connection_id: string; revoked: boolean; already_revoked: boolean; provider_revoked: boolean }> =>
  request(`/v1/connections/${encodeURIComponent(connectionId)}`, { method: 'DELETE', credential });

export interface PresenceView {
  readonly state: 'active' | 'away' | 'locked' | 'automation';
  readonly assurance: 'low' | 'medium' | 'high';
  readonly source: string;
  readonly changed_at: string;
  readonly expires_at: string | null;
}

export interface AuditEventView {
  readonly seq: number;
  readonly id: string;
  readonly actor: string;
  readonly event_type: string;
  readonly resource_ref: string | null;
  readonly outcome: 'allow' | 'deny' | 'challenge' | 'lifecycle';
  readonly correlation_id: string | null;
  readonly prev_hash: string | null;
  readonly hash: string;
  readonly occurred_at: string;
}

export interface LabelView {
  readonly id: string;
  readonly resource_type: string;
  readonly pattern: string;
  readonly exact: boolean;
  readonly sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
  readonly note: string | null;
}

export const listLabels = (credential: string): Promise<{ labels: LabelView[] }> =>
  request('/v1/labels', { method: 'GET', credential });

export const setLabel = (
  credential: string,
  body: { resource_type: string; pattern: string; sensitivity: string; exact?: boolean; note?: string },
): Promise<LabelView> =>
  request('/v1/labels', { method: 'PUT', credential, body: JSON.stringify(body) });

export const removeLabel = (
  credential: string,
  labelId: string,
): Promise<{ label_id: string; removed: boolean }> =>
  request(`/v1/labels/${encodeURIComponent(labelId)}`, { method: 'DELETE', credential });

export const getPresence = (credential: string): Promise<PresenceView> =>
  request('/v1/presence', { method: 'GET', credential });

export const setPresence = (
  credential: string,
  body: { state: string; source: string; assurance: string; ttl_ms?: number },
): Promise<PresenceView> =>
  request('/v1/presence', { method: 'PUT', credential, body: JSON.stringify(body) });

export const getEmergencyLock = (
  credential: string,
): Promise<{ locked: boolean; locked_at: string | null }> =>
  request('/v1/emergency-lock', { method: 'GET', credential });

export interface LockResult {
  readonly locked: boolean;
  /** Approved challenges that were still redeemable and are not any more. */
  readonly grants_revoked: number;
  readonly sessions_dropped: number;
}

export const setEmergencyLock = (credential: string, locked: boolean): Promise<LockResult> =>
  request('/v1/emergency-lock', { method: 'POST', credential, body: JSON.stringify({ locked }) });

export const listAuditEvents = (
  credential: string,
  query: { limit?: number; before?: number; outcome?: string } = {},
): Promise<{ events: AuditEventView[]; next_cursor: number | null }> => {
  const params = new URLSearchParams();
  // Numbers become strings here because the API declares them as strings —
  // coercion is off there on purpose, so it is off in the client too.
  if (query.limit !== undefined) params.set('limit', String(query.limit));
  if (query.before !== undefined) params.set('before', String(query.before));
  if (query.outcome !== undefined) params.set('outcome', query.outcome);
  const qs = params.toString();
  return request(`/v1/audit-events${qs === '' ? '' : `?${qs}`}`, { method: 'GET', credential });
};

export const verifyAuditChain = (
  credential: string,
): Promise<{ verified: boolean; broken_at: number | null; event_id: string | null }> =>
  request('/v1/audit-events/verify', { method: 'GET', credential });

export const listPasskeys = (
  credential: string,
): Promise<{ passkeys: Array<{ id: string; label: string | null; created_at: string; last_used_at: string | null }> }> =>
  request('/v1/passkeys', { method: 'GET', credential });

export const passkeyRegistrationOptions = (credential: string): Promise<Record<string, unknown>> =>
  request('/v1/passkeys/options', { method: 'POST', credential, body: '{}' });

export const enrolPasskey = (
  credential: string,
  body: { response: unknown; label?: string },
): Promise<{ id: string }> =>
  request('/v1/passkeys', { method: 'POST', credential, body: JSON.stringify(body) });

export interface PendingApproval {
  readonly id: string;
  readonly decision_id: string;
  readonly action_digest: string;
  readonly expires_at: string;
  readonly created_at: string;
  readonly tool: string | null;
  readonly action: string | null;
  readonly resource_ref: string | null;
  readonly reason_code: string | null;
}

export const listApprovals = (credential: string): Promise<{ approvals: PendingApproval[] }> =>
  request('/v1/approvals', { method: 'GET', credential });

export const approvalChallenge = (
  credential: string,
  approvalId: string,
): Promise<Record<string, unknown>> =>
  request(`/v1/approvals/${encodeURIComponent(approvalId)}/challenge`, { method: 'GET', credential });

export const resolveApproval = (
  credential: string,
  approvalId: string,
  body: { decision: 'approved' | 'denied'; assertion: unknown },
): Promise<{ approval_id: string; status: string }> =>
  request(`/v1/approvals/${encodeURIComponent(approvalId)}/resolve`, {
    method: 'POST',
    credential,
    body: JSON.stringify(body),
  });

export const revokeAgent = (
  credential: string,
  agentId: string,
): Promise<{ agent_id: string; revoked: boolean; already_revoked: boolean; sessions_dropped: number }> =>
  request(`/v1/agents/${encodeURIComponent(agentId)}`, { method: 'DELETE', credential });
