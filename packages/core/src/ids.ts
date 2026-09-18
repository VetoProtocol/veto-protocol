/**
 * Branded identifier types.
 *
 * Every protected decision is scoped by workspace, human, and agent (CLAUDE.md
 * invariant 4, spec §3.3 step 1). Plain `string` lets any of those be passed where
 * another is expected — a tenant-isolation bug that typechecks. Branding makes that
 * a compile error and forces every crossing of the boundary through a validator.
 *
 * Prefixes follow the wire examples in spec §5.1 / §5.2.
 */

declare const brand: unique symbol;
type Brand<B extends string> = string & { readonly [brand]: B };

export type WorkspaceId = Brand<'WorkspaceId'>;
export type HumanId = Brand<'HumanId'>;
export type AgentId = Brand<'AgentId'>;
export type ConnectionId = Brand<'ConnectionId'>;
export type SessionId = Brand<'SessionId'>;
export type RequestId = Brand<'RequestId'>;
export type DecisionId = Brand<'DecisionId'>;
export type ApprovalId = Brand<'ApprovalId'>;
export type PolicyVersion = Brand<'PolicyVersion'>;

export class InvalidIdError extends Error {
  constructor(expectedPrefix: string, received: string) {
    // The received value is an identifier, never a credential — safe to echo.
    super(`Expected an id with prefix "${expectedPrefix}", received: ${JSON.stringify(received)}`);
    this.name = 'InvalidIdError';
  }
}

/** Body after the prefix: url-safe, bounded, non-empty. */
const BODY = /^[A-Za-z0-9_-]{1,64}$/;

function makeIdFactory<T extends string>(prefix: string) {
  const parse = (value: unknown): T => {
    if (typeof value !== 'string' || !value.startsWith(prefix) || !BODY.test(value.slice(prefix.length))) {
      throw new InvalidIdError(prefix, typeof value === 'string' ? value : String(value));
    }
    return value as T;
  };
  const is = (value: unknown): value is T => {
    try {
      parse(value);
      return true;
    } catch {
      return false;
    }
  };
  return { prefix, parse, is };
}

export const WorkspaceId = makeIdFactory<WorkspaceId>('ws_');
export const HumanId = makeIdFactory<HumanId>('usr_');
export const AgentId = makeIdFactory<AgentId>('agt_');
export const ConnectionId = makeIdFactory<ConnectionId>('con_');
export const SessionId = makeIdFactory<SessionId>('ses_');
export const RequestId = makeIdFactory<RequestId>('req_');
export const DecisionId = makeIdFactory<DecisionId>('dec_');
export const ApprovalId = makeIdFactory<ApprovalId>('apr_');
export const PolicyVersion = makeIdFactory<PolicyVersion>('polv_');
