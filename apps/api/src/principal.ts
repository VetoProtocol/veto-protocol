/**
 * Who is making this request.
 *
 * Spec §3.3 step 1: resolve the human, tenant and agent before anything else.
 * Authentication itself is OIDC and arrives with the dashboard; until then the
 * app takes an `Authenticator` as a required constructor argument.
 *
 * Required, not optional-with-a-default. A default would be a bypass waiting to
 * be shipped, and "missing identity" must deny (invariant 1). An app with no
 * authenticator refuses to be constructed at all, so there is no configuration
 * in which this server runs unauthenticated.
 */

import type { FastifyRequest } from 'fastify';

export interface Principal {
  readonly workspaceId: string;
  readonly userId: string;
  /**
   * Coarse scope from the credential, e.g. 'control-plane'.
   *
   * Routes assert the scope they require. It is not an authorization decision —
   * it stops a credential minted for one purpose being replayed at another
   * (invariant 8 keeps the real decision in the pipeline).
   */
  readonly action: string;
  /** Set when an agent is acting for the human; null for a person at a keyboard. */
  readonly agentId: string | null;
}

export type Authenticator = (request: FastifyRequest) => Promise<Principal | null>;

declare module 'fastify' {
  interface FastifyRequest {
    principal: Principal;
  }
}
