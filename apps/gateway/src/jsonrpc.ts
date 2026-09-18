/**
 * JSON-RPC 2.0, validated strictly (spec §3.4).
 *
 * "Strict" is the whole point. The gateway is the enforcement boundary, and
 * everything arriving here is attacker-controlled: an agent is authenticated
 * but not trusted, and the content that shaped its request may have been
 * written by somebody else entirely. A parser that repairs a malformed request
 * is deciding what the caller meant, which is not a decision this side of the
 * boundary gets to make.
 *
 * Batches are refused outright. They complicate per-request authorization —
 * each element would need its own decision and its own audit event — and
 * nothing needs them. One request, one decision.
 */

export const JSONRPC_VERSION = '2.0';

/** Standard codes, plus the implementation-defined range for our own. */
export const RPC = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  /** A Veto decision refused the call. Carries a reason code in `data`. */
  DENIED: -32001,
  /** The caller is not authenticated, or no longer is. */
  UNAUTHENTICATED: -32002,
} as const;

export type RpcId = string | number | null;

export interface RpcRequest {
  readonly jsonrpc: '2.0';
  readonly id: RpcId;
  readonly method: string;
  readonly params: Record<string, unknown>;
  /** A notification carries no id and never receives a response. */
  readonly isNotification: boolean;
}

export interface RpcErrorBody {
  readonly code: number;
  readonly message: string;
  readonly data?: Record<string, unknown>;
}

export class RpcError extends Error {
  readonly code: number;
  readonly data: Record<string, unknown> | undefined;

  constructor(code: number, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = 'RpcError';
    this.code = code;
    this.data = data;
  }

  toBody(): RpcErrorBody {
    return this.data === undefined
      ? { code: this.code, message: this.message }
      : { code: this.code, message: this.message, data: this.data };
  }
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Validate one JSON-RPC request.
 *
 * Throws rather than returning a result union: every failure here ends the
 * request, and a union invites a caller to carry on with a half-valid object.
 */
export function parseRpcRequest(body: unknown): RpcRequest {
  if (Array.isArray(body)) {
    throw new RpcError(RPC.INVALID_REQUEST, 'Batch requests are not supported');
  }
  if (!isPlainObject(body)) {
    throw new RpcError(RPC.INVALID_REQUEST, 'Request must be a JSON object');
  }
  if (body['jsonrpc'] !== JSONRPC_VERSION) {
    throw new RpcError(RPC.INVALID_REQUEST, 'jsonrpc must be exactly "2.0"');
  }

  const method = body['method'];
  if (typeof method !== 'string' || method === '') {
    throw new RpcError(RPC.INVALID_REQUEST, 'method must be a non-empty string');
  }

  const rawId = body['id'];
  const hasId = Object.prototype.hasOwnProperty.call(body, 'id');
  if (hasId && rawId !== null && typeof rawId !== 'string' && typeof rawId !== 'number') {
    throw new RpcError(RPC.INVALID_REQUEST, 'id must be a string, number, or null');
  }

  const rawParams = body['params'];
  if (rawParams !== undefined && !isPlainObject(rawParams)) {
    // By-position params are legal JSON-RPC and refused anyway: every MCP method
    // takes named params, and accepting both doubles the shapes every
    // downstream validator would have to consider.
    throw new RpcError(RPC.INVALID_PARAMS, 'params must be an object');
  }

  return {
    jsonrpc: JSONRPC_VERSION,
    id: hasId ? (rawId as RpcId) : null,
    method,
    params: rawParams === undefined ? {} : rawParams,
    isNotification: !hasId,
  };
}

export const rpcResult = (id: RpcId, result: unknown) => ({ jsonrpc: JSONRPC_VERSION, id, result });

export const rpcError = (id: RpcId, error: RpcErrorBody) => ({ jsonrpc: JSONRPC_VERSION, id, error });
